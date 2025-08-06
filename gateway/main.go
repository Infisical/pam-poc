package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// logWriter implements io.Writer to log data while forwarding
type logWriter struct{}

func (lw *logWriter) Write(p []byte) (n int, err error) {
	if len(p) > 0 {
		log.Printf("Received %d bytes: %s", len(p), string(p))
	}
	return len(p), nil
}

var (
	serverURL string
	agentName string
	sshPort   int
	localPort int
)

func init() {
	// Get configuration from environment variables with defaults
	if serverURL = os.Getenv("SERVER_URL"); serverURL == "" {
		serverURL = "http://localhost:8081"
	}
	if agentName = os.Getenv("AGENT_NAME"); agentName == "" {
		agentName = "web-agent"
	}
	if sshPortStr := os.Getenv("SSH_PORT"); sshPortStr != "" {
		if port, err := strconv.Atoi(sshPortStr); err == nil {
			sshPort = port
		} else {
			sshPort = 2222
		}
	} else {
		sshPort = 2222
	}
	if localPortStr := os.Getenv("LOCAL_PORT"); localPortStr != "" {
		if port, err := strconv.Atoi(localPortStr); err == nil {
			localPort = port
		} else {
			localPort = 8000
		}
	} else {
		localPort = 8000
	}
}

func main() {
	log.Println("Starting Go-based SSH tunnel agent...")

	// Start the local HTTP server
	go startLocalServer()

	// Start security testing in background
	// go runSecurityTests()

	// Fetch certificate and establish tunnel
	if err := establishTunnel(); err != nil {
		log.Fatalf("Failed to establish tunnel: %v", err)
	}
}

func startLocalServer() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Local server received request: %s %s", r.Method, r.URL.Path)
		fmt.Fprintf(w, "Hello from agent: %s! Path: %s\n", agentName, r.URL.Path)
	})

	log.Printf("Local HTTP server starting on :%d", localPort)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", localPort), nil); err != nil {
		log.Fatalf("Failed to start local server: %v", err)
	}
}

func establishTunnel() error {
	for {
		if err := connectAndServe(); err != nil {
			log.Printf("Connection failed: %v, retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}
		// If we get here, the connection was closed gracefully
		log.Printf("Connection closed, reconnecting in 2 seconds...")
		time.Sleep(2 * time.Second)
	}
}

func connectAndServe() error {
	// Fetch SSH certificate from server
	privateKey, certificate, err := fetchSSHCertificate()
	if err != nil {
		return fmt.Errorf("failed to fetch SSH certificate: %v", err)
	}

	// Create SSH client config
	config, err := createSSHConfig(privateKey, certificate)
	if err != nil {
		return fmt.Errorf("failed to create SSH config: %v", err)
	}

	// Connect to SSH server
	sshHost := os.Getenv("SSH_HOST")
	if sshHost == "" {
		sshHost = "localhost" // Default to localhost if not specified
	}
	log.Printf("Connecting to SSH server on %s:%d...", sshHost, sshPort)
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", sshHost, sshPort), config)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server: %v", err)
	}
	defer client.Close()

	log.Printf("SSH connection established for agent: %s", agentName)
	log.Printf("Agent ready to handle incoming channels...")

	// Handle incoming channels from the server
	channels := client.HandleChannelOpen("direct-tcpip")
	if channels == nil {
		return fmt.Errorf("failed to handle channel open")
	}

	// Process incoming channels
	for newChannel := range channels {
		go handleIncomingChannel(newChannel)
	}

	return nil // Connection closed
}

func handleIncomingChannel(newChannel ssh.NewChannel) {
	// Parse the target information from the server
	var req struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}

	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		log.Printf("Failed to parse channel request: %v", err)
		newChannel.Reject(ssh.Prohibited, "invalid request")
		return
	}

	log.Printf("Incoming connection request to %s:%d from %s:%d",
		req.Host, req.Port, req.OriginHost, req.OriginPort)

	// Accept the channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Failed to accept channel: %v", err)
		return
	}
	defer channel.Close()

	// Handle any requests on this channel (usually none for direct-tcpip)
	go ssh.DiscardRequests(requests)

	// Determine the target address
	target := fmt.Sprintf("%s:%d", req.Host, req.Port)
	log.Printf("Creating TCP tunnel to: %s", target)

	// Create mTLS server configuration
	tlsConfig, err := createMTLSConfig()
	if err != nil {
		log.Printf("Failed to create mTLS config: %v", err)
		return
	}

	// Create a virtual connection that pipes data between SSH channel and TLS
	virtualConn := &virtualConnection{
		channel: channel,
	}

	// Wrap the virtual connection with TLS
	tlsConn := tls.Server(virtualConn, tlsConfig)

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return
	}

	log.Printf("mTLS connection established with client: %s", tlsConn.ConnectionState().ServerName)

	// Connect to local service
	localConn, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("Failed to connect to local service %s: %v", target, err)
		return
	}
	defer localConn.Close()

	log.Printf("TCP tunnel established to %s", target)

	// Create bidirectional tunnel with TLS
	// Forward data from TLS connection to local service
	go func() {
		io.Copy(localConn, tlsConn)
		localConn.Close()
		log.Printf("TLS -> local service tunnel closed")
	}()

	// Forward data from local service to TLS connection
	io.Copy(tlsConn, localConn)
	log.Printf("Local service -> TLS tunnel closed")
}

// Keep all the existing certificate and SSH config functions unchanged
func fetchSSHCertificate() ([]byte, []byte, error) {
	log.Printf("Fetching SSH certificate from %s/generate-cert?agent=%s", serverURL, agentName)

	resp, err := http.Post(fmt.Sprintf("%s/generate-cert?agent=%s", serverURL, agentName), "application/json", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch SSH certificate: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("server returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse the response to extract private key and certificate
	privateKey, certificate, err := parseCertificateResponse(string(body))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SSH certificate response: %v", err)
	}

	log.Printf("Successfully fetched SSH certificate for agent: %s", agentName)
	return privateKey, certificate, nil
}

func parseCertificateResponse(response string) ([]byte, []byte, error) {
	lines := strings.Split(response, "\n")
	var privateKeyLines, certLines []string
	var inPrivateKey, inCert bool

	for _, line := range lines {
		// Check for section markers
		if strings.TrimSpace(line) == "PRIVATE_KEY:" {
			inPrivateKey = true
			inCert = false
			continue
		}
		if strings.TrimSpace(line) == "CERTIFICATE:" {
			inPrivateKey = false
			inCert = true
			continue
		}

		// End markers
		if strings.Contains(line, "-----END RSA PRIVATE KEY-----") {
			if inPrivateKey {
				privateKeyLines = append(privateKeyLines, line)
			}
			inPrivateKey = false
			continue
		}

		// Collect private key lines (including the BEGIN marker)
		if inPrivateKey && strings.TrimSpace(line) != "" {
			privateKeyLines = append(privateKeyLines, line)
		}

		// Collect certificate line
		if inCert && strings.Contains(line, "ssh-rsa-cert") {
			certLines = append(certLines, strings.TrimSpace(line))
			inCert = false
			continue
		}
	}

	if len(privateKeyLines) == 0 {
		return nil, nil, fmt.Errorf("no private key found in response")
	}
	if len(certLines) == 0 {
		return nil, nil, fmt.Errorf("no certificate found in response")
	}

	// Reconstruct the private key PEM block
	privateKeyPEM := strings.Join(privateKeyLines, "\n")
	if !strings.HasSuffix(privateKeyPEM, "\n") {
		privateKeyPEM += "\n"
	}

	return []byte(privateKeyPEM), []byte(certLines[0]), nil
}

// parseTLSCertificateResponse parses TLS certificate response from proxy
func parseTLSCertificateResponse(response string) ([]byte, []byte, error) {
	lines := strings.Split(response, "\n")
	var privateKeyLines, certLines []string
	var inPrivateKey, inCert bool

	for _, line := range lines {
		// Check for section markers
		if strings.TrimSpace(line) == "PRIVATE_KEY:" {
			inPrivateKey = true
			inCert = false
			continue
		}
		if strings.TrimSpace(line) == "CERTIFICATE:" {
			inPrivateKey = false
			inCert = true
			continue
		}

		// Collect private key lines (including the BEGIN/END markers)
		if inPrivateKey && strings.TrimSpace(line) != "" {
			privateKeyLines = append(privateKeyLines, line)
		}

		// Collect certificate lines (including the BEGIN/END markers)
		if inCert && strings.TrimSpace(line) != "" {
			certLines = append(certLines, line)
		}
	}

	if len(privateKeyLines) == 0 {
		return nil, nil, fmt.Errorf("no private key found in response")
	}
	if len(certLines) == 0 {
		return nil, nil, fmt.Errorf("no certificate found in response")
	}

	// Reconstruct the private key PEM block
	privateKeyPEM := strings.Join(privateKeyLines, "\n")
	if !strings.HasSuffix(privateKeyPEM, "\n") {
		privateKeyPEM += "\n"
	}

	// Reconstruct the certificate PEM block
	certPEM := strings.Join(certLines, "\n")
	if !strings.HasSuffix(certPEM, "\n") {
		certPEM += "\n"
	}

	return []byte(privateKeyPEM), []byte(certPEM), nil
}

func createSSHConfig(privateKeyPEM, certificatePEM []byte) (*ssh.ClientConfig, error) {
	// Parse private key
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// Create SSH signer from private key
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer from private key: %v", err)
	}

	// Parse certificate
	cert, _, _, _, err := ssh.ParseAuthorizedKey(certificatePEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Create certificate signer
	certSigner, err := ssh.NewCertSigner(cert.(*ssh.Certificate), signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate signer: %v", err)
	}

	// Create SSH client config with explicit algorithm preferences
	config := &ssh.ClientConfig{
		User: agentName,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(certSigner),
		},
		HostKeyCallback: createHostKeyCallback(),
		Timeout:         30 * time.Second,
		// Explicitly set algorithm preferences to match server
		Config: ssh.Config{
			KeyExchanges: []string{
				"diffie-hellman-group14-sha256",
				"diffie-hellman-group16-sha512",
				"diffie-hellman-group18-sha512",
			},
			Ciphers: []string{
				"aes128-ctr",
				"aes192-ctr",
				"aes256-ctr",
			},
			MACs: []string{
				"hmac-sha2-256",
				"hmac-sha2-512",
			},
		},
	}

	return config, nil
}

func createHostKeyCallback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// Fetch CA public key from server to validate host key
		caPubKey, err := fetchCAPublicKey()
		if err != nil {
			return fmt.Errorf("failed to fetch CA public key: %v", err)
		}

		// Parse CA public key
		caKey, _, _, _, err := ssh.ParseAuthorizedKey(caPubKey)
		if err != nil {
			return fmt.Errorf("failed to parse CA public key: %v", err)
		}

		// Check if the host key is signed by our CA
		checker := &ssh.CertChecker{
			IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
				return bytes.Equal(auth.Marshal(), caKey.Marshal())
			},
		}

		// Validate the host key
		if err := checker.CheckHostKey(hostname, remote, key); err != nil {
			return fmt.Errorf("host key validation failed: %v", err)
		}

		log.Printf("Host key validated successfully for %s", hostname)
		return nil
	}
}

func fetchCAPublicKey() ([]byte, error) {
	resp, err := http.Get(fmt.Sprintf("%s/ca-public-key", serverURL))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CA public key: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA public key response: %v", err)
	}

	// The response now contains just the raw SSH public key
	return bytes.TrimSpace(body), nil
}

// Keep all security test functions unchanged for now
func runSecurityTests() {
	// Wait a bit for the tunnel to be established
	time.Sleep(2 * time.Second)

	log.Println("🔒 Starting SSH server security tests...")

	// Test 1: Try to get a shell
	testShellAccess()

	// Test 2: Try to execute commands
	testCommandExecution()

	// Test 3: Try SFTP
	testSFTPAccess()

	log.Println("Security tests completed")
}

func testShellAccess() {
	log.Println("  Testing shell access...")

	// Create SSH client config for testing
	config := &ssh.ClientConfig{
		User: agentName,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(getTestSigner()),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For testing only
		Timeout:         5 * time.Second,
	}

	// Try to connect and request a shell
	client, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", sshPort), config)
	if err != nil {
		log.Printf("    ❌ Shell test: Connection failed (expected): %v", err)
		return
	}
	defer client.Close()

	// Try to open a session
	session, err := client.NewSession()
	if err != nil {
		log.Printf("    ❌ Shell test: Session creation failed (expected): %v", err)
		return
	}
	defer session.Close()

	// Try to request a shell
	err = session.RequestPty("xterm", 40, 80, ssh.TerminalModes{})
	if err != nil {
		log.Printf("    ✅ Shell test: PTY request properly rejected: %v", err)
		return
	}

	// Try to start a shell
	err = session.Shell()
	if err != nil {
		log.Printf("    ✅ Shell test: Shell access properly denied: %v", err)
	} else {
		log.Printf("    ⚠️  Shell test: WARNING - Shell access was granted!")
	}
}

func testCommandExecution() {
	log.Println("  Testing command execution...")

	config := &ssh.ClientConfig{
		User: agentName,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(getTestSigner()),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For testing only
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", sshPort), config)
	if err != nil {
		log.Printf("    ❌ Command test: Connection failed (expected): %v", err)
		return
	}
	defer client.Close()

	// Try to execute a command
	session, err := client.NewSession()
	if err != nil {
		log.Printf("    ❌ Command test: Session creation failed (expected): %v", err)
		return
	}
	defer session.Close()

	// Try to run a command
	err = session.Run("whoami")
	if err != nil {
		log.Printf("    ✅ Command test: Command execution properly denied: %v", err)
	} else {
		log.Printf("    ⚠️  Command test: WARNING - Command execution was allowed!")
	}
}

func testSFTPAccess() {
	log.Println("  Testing SFTP access...")

	config := &ssh.ClientConfig{
		User: agentName,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(getTestSigner()),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For testing only
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", sshPort), config)
	if err != nil {
		log.Printf("    ❌ SFTP test: Connection failed (expected): %v", err)
		return
	}
	defer client.Close()

	// Try to open SFTP subsystem
	sftpClient, err := client.NewSession()
	if err != nil {
		log.Printf("    ❌ SFTP test: Session creation failed (expected): %v", err)
		return
	}
	defer sftpClient.Close()

	// Try to request SFTP subsystem
	err = sftpClient.RequestSubsystem("sftp")
	if err != nil {
		log.Printf("    ✅ SFTP test: SFTP subsystem properly denied: %v", err)
	} else {
		log.Printf("    ⚠️  SFTP test: WARNING - SFTP access was granted!")
	}
}

func getTestSigner() ssh.Signer {
	// Fetch SSH certificate for testing
	privateKey, certificate, err := fetchSSHCertificate()
	if err != nil {
		log.Printf("    ❌ Security test setup failed: %v", err)
		return nil
	}

	// Validate that we can create SSH config (but we don't need it for the signer)
	_, err = createSSHConfig(privateKey, certificate)
	if err != nil {
		log.Printf("    ❌ Security test signer creation failed: %v", err)
		return nil
	}

	// Create a signer directly from the private key and certificate
	block, _ := pem.Decode(privateKey)
	if block == nil {
		log.Printf("    ❌ Security test: failed to decode private key")
		return nil
	}

	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Printf("    ❌ Security test: failed to parse private key: %v", err)
		return nil
	}

	signer, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		log.Printf("    ❌ Security test: failed to create signer: %v", err)
		return nil
	}

	// Parse certificate
	cert, _, _, _, err := ssh.ParseAuthorizedKey(certificate)
	if err != nil {
		log.Printf("    ❌ Security test: failed to parse certificate: %v", err)
		return nil
	}

	// Create certificate signer
	certSigner, err := ssh.NewCertSigner(cert.(*ssh.Certificate), signer)
	if err != nil {
		log.Printf("    ❌ Security test: failed to create cert signer: %v", err)
		return nil
	}

	return certSigner
}

// virtualConnection implements net.Conn to bridge SSH channel and TLS
type virtualConnection struct {
	channel ssh.Channel
}

func (vc *virtualConnection) Read(b []byte) (n int, err error) {
	return vc.channel.Read(b)
}

func (vc *virtualConnection) Write(b []byte) (n int, err error) {
	return vc.channel.Write(b)
}

func (vc *virtualConnection) Close() error {
	return vc.channel.Close()
}

func (vc *virtualConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (vc *virtualConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (vc *virtualConnection) SetDeadline(t time.Time) error {
	return nil
}

func (vc *virtualConnection) SetReadDeadline(t time.Time) error {
	return nil
}

func (vc *virtualConnection) SetWriteDeadline(t time.Time) error {
	return nil
}

// createMTLSConfig creates TLS configuration for mTLS server
func createMTLSConfig() (*tls.Config, error) {
	// Fetch server certificate from proxy
	serverCert, serverKey, err := fetchServerCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch server certificate: %v", err)
	}

	// Fetch CA certificate for client validation
	caCert, err := fetchCACertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CA certificate: %v", err)
	}

	// Parse server certificate
	cert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server certificate: %v", err)
	}

	// Parse CA certificate
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// fetchServerCertificate fetches server certificate from proxy
func fetchServerCertificate() ([]byte, []byte, error) {
	resp, err := http.Post(fmt.Sprintf("%s/generate-server-cert", serverURL), "application/json", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch server certificate: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse the response to extract private key and certificate
	privateKey, certificate, err := parseTLSCertificateResponse(string(body))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse TLS certificate response: %v", err)
	}

	return certificate, privateKey, nil
}

// fetchCACertificate fetches CA certificate from proxy
func fetchCACertificate() ([]byte, error) {
	resp, err := http.Get(fmt.Sprintf("%s/tls-ca-cert", serverURL))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CA certificate: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	return body, nil
}
