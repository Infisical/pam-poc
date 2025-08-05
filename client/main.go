package main

import (
	"bufio"
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
	"strings"
	"time"
)

// logWriter implements io.Writer to log packet data
type logWriter struct {
	prefix string
}

func (lw *logWriter) Write(p []byte) (n int, err error) {
	log.Printf("[%s] Received %d bytes: %q", lw.prefix, len(p), string(p))
	return len(p), nil
}

// fetchCertificates gets server CA and generates client certificates
func fetchCertificates(serverAddr string) (*tls.Config, error) {
	// Fetch server CA certificate for server authentication
	resp, err := http.Get(fmt.Sprintf("http://%s/tls-ca-cert", serverAddr))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch server CA: %v", err)
	}
	defer resp.Body.Close()

	serverCAPEM, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read server CA: %v", err)
	}

	// Parse server CA certificate
	serverCABlock, _ := pem.Decode(serverCAPEM)
	if serverCABlock == nil {
		return nil, fmt.Errorf("failed to decode server CA certificate")
	}

	serverCACert, err := x509.ParseCertificate(serverCABlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server CA certificate: %v", err)
	}

	// Generate client key
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client key: %v", err)
	}

	// Create a self-signed client certificate (in production, this would be signed by a client CA)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   "client1",
			Organization: []string{"SSH Tunnel Client"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	// Self-sign the client certificate (for now)
	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, clientTemplate, &clientKey.PublicKey, clientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %v", err)
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{clientCertDER},
				PrivateKey:  clientKey,
			},
		},
		RootCAs:    x509.NewCertPool(),
		ServerName: "localhost",
	}

	// Add server CA for server authentication
	tlsConfig.RootCAs.AddCert(serverCACert)

	log.Printf("Generated client certificates for mTLS")
	log.Printf("Client certificate created with %d certificates", len(tlsConfig.Certificates))
	log.Printf("Server CA added to RootCAs")
	return tlsConfig, nil
}

func main() {
	// Default values
	agentName := "web-agent"
	tunnelServer := "localhost:8080"
	managementServer := "localhost:8081"

	// Override with command line args if provided
	if len(os.Args) >= 2 {
		agentName = os.Args[1]
	}
	if len(os.Args) >= 3 {
		tunnelServer = os.Args[2]
	}
	if len(os.Args) >= 4 {
		managementServer = os.Args[3]
	}

	// Fetch TLS certificates from server
	tlsConfig, err := fetchCertificates(managementServer)
	if err != nil {
		log.Fatalf("Failed to fetch certificates: %v", err)
	}

	// Start HTTP proxy server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleHTTPRequest(w, r, agentName, tunnelServer, tlsConfig)
	})

	log.Printf("HTTP proxy listening on :8082")
	log.Printf("Forwarding requests to agent: %s via TLS tunnel: %s", agentName, tunnelServer)
	log.Printf("Use: curl http://localhost:8082/your/path")
	log.Printf("Optional: go run . <agent-name> <tunnel-server:port> <management-server:port>")
	log.Fatal(http.ListenAndServe(":8082", nil))
}

func handleHTTPRequest(w http.ResponseWriter, r *http.Request, agentName, tunnelServer string, tlsConfig *tls.Config) {
	log.Printf("Proxying request: %s %s", r.Method, r.URL.Path)
	log.Printf("TLS config has %d certificates", len(tlsConfig.Certificates))

	// Connect to tunnel server with TLS
	conn, err := tls.Dial("tcp", tunnelServer, tlsConfig)
	if err != nil {
		log.Printf("Failed to connect to tunnel server: %v", err)
		http.Error(w, "Failed to connect to tunnel", http.StatusServiceUnavailable)
		return
	}
	defer conn.Close()

	log.Printf("TLS connection established successfully")
	log.Printf("TLS version: %d", conn.ConnectionState().Version)
	log.Printf("TLS cipher suite: %d", conn.ConnectionState().CipherSuite)

	// Send agent name followed by newline
	conn.Write([]byte(agentName + "\n"))

	// Reconstruct the HTTP request
	httpRequest := reconstructHTTPRequest(r)

	// Send the HTTP request through the tunnel with logging
	log.Printf("[CLIENT->TUNNEL] Sending %d bytes: %q", len(httpRequest), string(httpRequest))
	_, err = conn.Write(httpRequest)
	if err != nil {
		log.Printf("Failed to write to tunnel: %v", err)
		http.Error(w, "Failed to send request through tunnel", http.StatusInternalServerError)
		return
	}

	// Read complete HTTP response from tunnel
	response, err := readCompleteHTTPResponse(conn)
	if err != nil {
		log.Printf("Failed to read response from tunnel: %v", err)
		http.Error(w, "Failed to read response from tunnel", http.StatusInternalServerError)
		return
	}
	log.Printf("[TUNNEL->CLIENT] Received %d bytes: %q", len(response), string(response))

	// Parse and forward the HTTP response
	forwardHTTPResponse(w, response)
}

func reconstructHTTPRequest(r *http.Request) []byte {
	var buf bytes.Buffer

	// Write request line
	buf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", r.Method, r.URL.RequestURI()))

	// Write headers
	for name, values := range r.Header {
		for _, value := range values {
			buf.WriteString(fmt.Sprintf("%s: %s\r\n", name, value))
		}
	}

	// Add Host header if not present
	if r.Header.Get("Host") == "" {
		buf.WriteString(fmt.Sprintf("Host: %s\r\n", r.Host))
	}

	// End headers
	buf.WriteString("\r\n")

	// Write body
	if r.Body != nil {
		body, _ := io.ReadAll(r.Body)
		buf.Write(body)
	}

	return buf.Bytes()
}

func readCompleteHTTPResponse(conn net.Conn) ([]byte, error) {
	reader := bufio.NewReader(conn)
	var response bytes.Buffer

	// Read status line
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read status line: %v", err)
	}
	response.WriteString(statusLine)

	// Read headers
	contentLength := -1
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read headers: %v", err)
		}
		response.WriteString(line)

		// Check for end of headers (empty line)
		if line == "\r\n" || line == "\n" {
			break
		}

		// Parse Content-Length header
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &contentLength)
			}
		}
	}

	// Read body based on Content-Length
	if contentLength > 0 {
		body := make([]byte, contentLength)
		_, err := io.ReadFull(reader, body)
		if err != nil {
			return nil, fmt.Errorf("failed to read body: %v", err)
		}
		response.Write(body)
	} else {
		// No Content-Length, read until connection closes or timeout
		// Set a reasonable timeout
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		body, err := io.ReadAll(reader)
		if err != nil {
			// If timeout, that's okay - we got what we could
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				response.Write(body)
				return response.Bytes(), nil
			}
			return nil, fmt.Errorf("failed to read body: %v", err)
		}
		response.Write(body)
	}

	return response.Bytes(), nil
}

func forwardHTTPResponse(w http.ResponseWriter, responseData []byte) {
	// Find the end of headers (double CRLF)
	headerEnd := bytes.Index(responseData, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		// Try single CRLF
		headerEnd = bytes.Index(responseData, []byte("\n\n"))
	}

	if headerEnd == -1 {
		// No headers found, write raw response
		w.Write(responseData)
		return
	}

	// Parse headers
	headers := responseData[:headerEnd]
	body := responseData[headerEnd+4:] // Skip the double CRLF

	// Parse status line and headers
	lines := strings.Split(string(headers), "\r\n")
	if len(lines) == 0 {
		w.Write(responseData)
		return
	}

	// Parse status line (first line)
	statusLine := lines[0]
	parts := strings.Split(statusLine, " ")
	if len(parts) >= 3 {
		// Set status code
		statusCode := 200
		fmt.Sscanf(parts[1], "%d", &statusCode)
		w.WriteHeader(statusCode)
	}

	// Set headers
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		if colonIndex := strings.Index(line, ":"); colonIndex != -1 {
			headerName := strings.TrimSpace(line[:colonIndex])
			headerValue := strings.TrimSpace(line[colonIndex+1:])
			w.Header().Set(headerName, headerValue)
		}
	}

	// Write body
	w.Write(body)
}
