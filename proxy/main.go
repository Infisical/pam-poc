package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Simple tunnel storage
var (
	tunnels = make(map[string]*ssh.ServerConn) // agentName -> SSH connection
	mu      sync.RWMutex

	// Certificate Authority for validating agent certificates
	caSigner ssh.Signer

	// TLS CA certificate for client certificates
	tlsCACert []byte

	// TLS CA private key for signing certificates
	tlsCAKey *rsa.PrivateKey

	// TLS configuration for client connections
	tlsConfig *tls.Config
)

// logWriter implements io.Writer to log packet data
type logWriter struct {
	prefix string
}

func (lw *logWriter) Write(p []byte) (n int, err error) {
	log.Printf("[%s] Received %d bytes: %q", lw.prefix, len(p), string(p))
	return len(p), nil
}

// generateTLSCertificates creates TLS certificates for mTLS
func generateTLSCertificates() (*tls.Config, error) {
	// Generate CA key and certificate
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"SSH Tunnel CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Generate server key and certificate
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key: %v", err)
	}

	// Get public IP from environment variable
	publicIP := os.Getenv("PUBLIC_IP")

	// Build DNS names list
	dnsNames := []string{"localhost", "proxy"}
	if publicIP != "" {
		dnsNames = append(dnsNames, publicIP)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"SSH Tunnel Server"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    dnsNames,
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %v", err)
	}

	_, err = x509.ParseCertificate(serverCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server certificate: %v", err)
	}

	// Create TLS config with mTLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{serverCertDER},
				PrivateKey:  serverKey,
			},
		},
		ClientCAs:  x509.NewCertPool(),
		ClientAuth: tls.RequestClientCert,
		MinVersion: tls.VersionTLS12,
		// For now, accept any client certificate (in production, validate against client CA)
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Accept any client certificate for now
			log.Printf("Accepting client certificate: %v", verifiedChains)
			return nil
		},
	}

	// Don't add any CA to ClientCAs - this will make it accept any client certificate
	// In production, you'd add the client CA here

	// Store TLS CA certificate and key for client access
	tlsCACert = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})
	tlsCAKey = caKey

	log.Printf("Generated TLS certificates for mTLS")
	log.Printf("TLS CA Certificate available at: GET http://localhost:8081/tls-ca-cert")

	return tlsConfig, nil
}

func main() {
	// Generate CA key for signing certificates
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caSigner, _ = ssh.NewSignerFromKey(caKey)

	log.Printf("CA Public Key: %s", string(ssh.MarshalAuthorizedKey(caSigner.PublicKey())))

	// Generate server certificate instead of raw host key
	hostSigner := generateSSHServerCertificate(caSigner)
	log.Printf("Server authenticated with CA-signed certificate")

	// Generate TLS certificates for mTLS
	tlsConfig, err := generateTLSCertificates()
	if err != nil {
		log.Fatalf("Failed to generate TLS certificates: %v", err)
	}

	// SSH server config - validate certificates instead of public keys
	config := &ssh.ServerConfig{
		// Remove PublicKeyCallback and add certificate validation
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Check if this is an SSH certificate
			cert, ok := key.(*ssh.Certificate)
			if !ok {
				log.Printf("Agent '%s' tried to authenticate with raw public key (rejected)", conn.User())
				return nil, fmt.Errorf("certificates required, raw public keys not allowed")
			}

			// Validate the certificate
			if err := validateCertificate(cert, conn.User()); err != nil {
				log.Printf("Agent '%s' certificate validation failed: %v", conn.User(), err)
				return nil, err
			}

			log.Printf("Agent '%s' authenticated with valid certificate", conn.User())
			return &ssh.Permissions{
				Extensions: map[string]string{
					"agent-name": conn.User(),
				},
			}, nil
		},
	}
	config.AddHostKey(hostSigner)

	// Start SSH server for agents
	go func() {
		listener, _ := net.Listen("tcp", ":2222")
		log.Println("SSH server listening on :2222 for agents (certificate auth required)")

		for {
			conn, _ := listener.Accept()
			go handleAgent(conn, config)
		}
	}()

	// Start TLS server for client connections (mTLS)
	go func() {
		listener, _ := net.Listen("tcp", ":8080")
		log.Println("TLS server listening on :8080 for clients (mTLS required)")
		log.Println("Clients must present valid certificates")

		for {
			conn, _ := listener.Accept()
			go func(conn net.Conn) {
				// Wrap connection with TLS
				tlsConn := tls.Server(conn, tlsConfig)
				if err := tlsConn.Handshake(); err != nil {
					log.Printf("TLS handshake failed: %v", err)
					tlsConn.Close()
					return
				}

				// Log client certificate info
				if len(tlsConn.ConnectionState().PeerCertificates) > 0 {
					cert := tlsConn.ConnectionState().PeerCertificates[0]
					log.Printf("Client connected with certificate: %s", cert.Subject.CommonName)
				}

				handleClient(tlsConn)
			}(conn)
		}
	}()

	// Start HTTP server for CA management
	http.HandleFunc("/ca-public-key", serveCAPubKey)
	http.HandleFunc("/tls-ca-cert", serveTLSCACert)
	http.HandleFunc("/generate-cert", generateAgentCert)
	http.HandleFunc("/generate-client-cert", generateClientCert)
	http.HandleFunc("/generate-server-cert", generateServerCert)

	log.Println("HTTP management server listening on :8081")
	log.Println("CA management:")
	log.Println("  GET http://localhost:8081/ca-public-key - Get CA public key")
	log.Println("  POST http://localhost:8081/generate-cert?agent=NAME - Generate certificate for agent")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func validateCertificate(cert *ssh.Certificate, username string) error {
	// Check certificate type
	if cert.CertType != ssh.UserCert {
		return fmt.Errorf("invalid certificate type: %d", cert.CertType)
	}

	// Check if certificate is signed by our CA
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), caSigner.PublicKey().Marshal())
		},
	}

	// Validate the certificate
	if err := checker.CheckCert(username, cert); err != nil {
		return fmt.Errorf("certificate check failed: %v", err)
	}

	log.Printf("Certificate valid for user '%s', principals: %v", username, cert.ValidPrincipals)
	return nil
}

func generateSSHServerCertificate(ca ssh.Signer) ssh.Signer {
	// Generate server key pair
	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	serverPub, _ := ssh.NewPublicKey(&serverKey.PublicKey)

	// Get public IP from environment variable
	publicIP := os.Getenv("PUBLIC_IP")

	// Build valid principals list for SSH server certificate
	validPrincipals := []string{"localhost", "127.0.0.1", "proxy"}
	if publicIP != "" {
		validPrincipals = append(validPrincipals, publicIP)
	}

	// Create server certificate template
	template := &ssh.Certificate{
		Key:             serverPub,
		CertType:        ssh.HostCert, // Host certificate (not user cert)
		KeyId:           "ssh-tunnel-server",
		ValidPrincipals: validPrincipals, // Server hostnames
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(365 * 24 * time.Hour).Unix()), // Valid for 1 year
	}

	// Sign the server certificate with our CA
	template.SignCert(rand.Reader, ca)

	// Create a certificate signer that wraps both the private key and certificate
	sshSigner, err := ssh.NewSignerFromKey(serverKey)
	if err != nil {
		log.Fatalf("Failed to create signer from key: %v", err)
	}
	certSigner, err := ssh.NewCertSigner(template, sshSigner)
	if err != nil {
		log.Fatalf("Failed to create cert signer: %v", err)
	}

	log.Printf("Generated server certificate, valid until: %s",
		time.Unix(int64(template.ValidBefore), 0).Format("2006-01-02 15:04:05"))

	return certSigner
}

func serveCAPubKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s\n", string(ssh.MarshalAuthorizedKey(caSigner.PublicKey())))
}

func serveTLSCACert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write(tlsCACert)
}

func generateAgentCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	agentName := r.URL.Query().Get("agent")
	if agentName == "" {
		http.Error(w, "agent parameter required", http.StatusBadRequest)
		return
	}

	// Generate a new key pair for the agent
	agentKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	agentPub, _ := ssh.NewPublicKey(&agentKey.PublicKey)

	// Create certificate template
	template := &ssh.Certificate{
		Key:             agentPub,
		CertType:        ssh.UserCert,
		KeyId:           fmt.Sprintf("agent-%s", agentName),
		ValidPrincipals: []string{agentName},
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(24 * time.Hour).Unix()), // Valid for 24 hours
	}

	// Sign the certificate with our CA
	if err := template.SignCert(rand.Reader, caSigner); err != nil {
		http.Error(w, fmt.Sprintf("Failed to sign certificate: %v", err), http.StatusInternalServerError)
		return
	}

	// Convert private key to PEM format
	agentKeyBytes := x509.MarshalPKCS1PrivateKey(agentKey)
	agentKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: agentKeyBytes,
	})

	// Return both the private key and certificate in a cleaner format
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "PRIVATE_KEY:\n%s\n", string(agentKeyPEM))
	fmt.Fprintf(w, "CERTIFICATE:\n%s\n", string(ssh.MarshalAuthorizedKey(template)))
}

func generateClientCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	agentName := r.URL.Query().Get("agent")
	if agentName == "" {
		http.Error(w, "agent parameter required", http.StatusBadRequest)
		return
	}

	// Generate a new key pair for the client
	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("client-for-%s", agentName),
			Organization: []string{"SSH Tunnel Client"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	// Sign the certificate with our CA
	// First decode the PEM certificate
	caCertBlock, _ := pem.Decode(tlsCACert)
	if caCertBlock == nil {
		http.Error(w, "Failed to decode CA certificate", http.StatusInternalServerError)
		return
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse CA certificate: %v", err), http.StatusInternalServerError)
		return
	}

	// Use the stored CA key
	if tlsCAKey == nil {
		http.Error(w, "CA key not available", http.StatusInternalServerError)
		return
	}
	caKey := tlsCAKey

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create certificate: %v", err), http.StatusInternalServerError)
		return
	}

	// Convert private key to PEM format
	clientKeyBytes := x509.MarshalPKCS1PrivateKey(clientKey)
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: clientKeyBytes,
	})

	// Return both the private key and certificate
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "PRIVATE_KEY:\n%s\n", string(clientKeyPEM))
	fmt.Fprintf(w, "CERTIFICATE:\n%s\n", string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})))
}

func generateServerCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	// Generate a new key pair for the server
	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName:   "gateway-server",
			Organization: []string{"SSH Tunnel Gateway"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		DNSNames:    []string{"localhost", "gateway", "127.0.0.1", "gateway-server"},
	}

	// Sign the certificate with our CA
	// First decode the PEM certificate
	caCertBlock, _ := pem.Decode(tlsCACert)
	if caCertBlock == nil {
		http.Error(w, "Failed to decode CA certificate", http.StatusInternalServerError)
		return
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse CA certificate: %v", err), http.StatusInternalServerError)
		return
	}

	// Use the stored CA key
	if tlsCAKey == nil {
		http.Error(w, "CA key not available", http.StatusInternalServerError)
		return
	}
	caKey := tlsCAKey

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create certificate: %v", err), http.StatusInternalServerError)
		return
	}

	// Convert private key to PEM format
	serverKeyBytes := x509.MarshalPKCS1PrivateKey(serverKey)
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: serverKeyBytes,
	})

	// Return both the private key and certificate
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "PRIVATE_KEY:\n%s\n", string(serverKeyPEM))
	fmt.Fprintf(w, "CERTIFICATE:\n%s\n", string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})))
}

func handleAgent(nConn net.Conn, config *ssh.ServerConfig) {
	defer nConn.Close()

	// SSH handshake
	conn, chans, _, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("SSH handshake failed: %v", err)
		log.Printf("Error type: %T", err)
		if netErr, ok := err.(net.Error); ok {
			log.Printf("Network error - timeout: %v, temporary: %v", netErr.Timeout(), netErr.Temporary())
		}
		return
	}

	log.Printf("SSH handshake successful for user: %s", conn.User())

	agentName := conn.User()
	log.Printf("Agent %s established tunnel", agentName)

	// Store the connection
	mu.Lock()
	tunnels[agentName] = conn
	mu.Unlock()

	// Clean up when agent disconnects
	defer func() {
		mu.Lock()
		delete(tunnels, agentName)
		mu.Unlock()
		log.Printf("Agent %s disconnected", agentName)
	}()

	// Block shell access, allow port forwarding
	for newChannel := range chans {
		if newChannel.ChannelType() == "session" {
			newChannel.Reject(ssh.Prohibited, "no shell")
		}
	}
}

func handleClient(clientConn net.Conn) {
	defer clientConn.Close()

	log.Printf("Client connected from %s", clientConn.RemoteAddr())

	// Read the first few bytes to determine which agent to connect to
	// Format: "agent1\n" or just "agent1" followed by data
	buffer := make([]byte, 1024)
	n, err := clientConn.Read(buffer)
	if err != nil {
		log.Printf("Failed to read from client: %v", err)
		return
	}

	// Find the first newline to separate agent name from data
	data := buffer[:n]
	log.Printf("Received %d bytes from client: %q", n, string(data))
	newlineIndex := bytes.IndexByte(data, '\n')

	var agentName string
	var remainingData []byte

	if newlineIndex != -1 {
		// Agent name is everything before the newline
		agentName = string(data[:newlineIndex])
		remainingData = data[newlineIndex+1:]
		log.Printf("Extracted agent name: %s", agentName)
	} else {
		// No newline found, assume first 10 bytes are agent name
		if len(data) < 10 {
			log.Printf("Invalid client data format")
			return
		}
		agentName = string(data[:10])
		remainingData = data[10:]
		log.Printf("Extracted agent name: %s", agentName)
	}

	// Get the SSH connection for this agent
	mu.RLock()
	conn, exists := tunnels[agentName]
	mu.RUnlock()

	if !exists {
		log.Printf("Agent '%s' not connected", agentName)
		clientConn.Write([]byte("ERROR: Agent not connected\n"))
		return
	}

	log.Printf("Routing TCP connection to agent: %s", agentName)

	// Open SSH channel to connect to agent's local service through the tunnel
	payload := struct {
		Host string
		Port uint32
		_    string
		_    uint32
	}{"localhost", 8000, "", 0} // Connect to agent's local port 8000

	channel, _, err := conn.OpenChannel("direct-tcpip", ssh.Marshal(&payload))
	if err != nil {
		log.Printf("Failed to connect to agent: %v", err)
		clientConn.Write([]byte("ERROR: Failed to connect to agent\n"))
		return
	}
	defer channel.Close()

	// If we have remaining data from the initial read, write it to the channel
	if len(remainingData) > 0 {
		channel.Write(remainingData)
	}

	// Bidirectional forwarding with logging
	// Forward from client to agent in a goroutine
	go func() {
		// Create a tee reader to log outgoing data
		teeReader := io.TeeReader(clientConn, &logWriter{prefix: "CLIENT->AGENT"})
		io.Copy(channel, teeReader)
		channel.CloseWrite() // Signal EOF to agent
	}()

	// Forward from agent to client in main thread with logging
	// Create a tee reader to log incoming data
	teeReader := io.TeeReader(channel, &logWriter{prefix: "AGENT->CLIENT"})
	io.Copy(clientConn, teeReader)

	log.Printf("Client %s disconnected", clientConn.RemoteAddr())
}
