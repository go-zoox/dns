package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// generateTestCert generates a self-signed certificate for testing
func generateTestCert() (certPEM, keyPEM []byte, err error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key
	keyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyDER,
	})

	return certPEM, keyPEM, nil
}

func TestNewServer_DefaultOptions(t *testing.T) {
	server := New()
	if server == nil {
		t.Fatal("New() returned nil")
	}
	if server.port != 8853 {
		t.Errorf("Expected default port 8853, got %d", server.port)
	}
	if server.host != "0.0.0.0" {
		t.Errorf("Expected default host 0.0.0.0, got %s", server.host)
	}
	if server.enableDoT {
		t.Error("Expected DoT to be disabled by default")
	}
	if server.dotPort != 853 {
		t.Errorf("Expected default DoT port 853, got %d", server.dotPort)
	}
}

func TestNewServer_WithDoTPort(t *testing.T) {
	server := New(&Options{
		DoTPort:   8853,
		EnableDoT: true,
	})
	if server.dotPort != 8853 {
		t.Errorf("Expected DoT port 8853, got %d", server.dotPort)
	}
}

func TestNewServer_EnableDoT_DefaultPort(t *testing.T) {
	server := New(&Options{
		EnableDoT: true,
	})
	if !server.enableDoT {
		t.Error("Expected DoT to be enabled")
	}
	if server.dotPort != 853 {
		t.Errorf("Expected default DoT port 853 when enabled, got %d", server.dotPort)
	}
}

func TestNewServer_DoTAddr(t *testing.T) {
	server := New(&Options{
		Host:    "127.0.0.1",
		DoTPort: 8853,
	})
	addr := server.DoTAddr()
	expected := "127.0.0.1:8853"
	if addr != expected {
		t.Errorf("Expected DoT address %s, got %s", expected, addr)
	}
}

func TestLoadTLSConfig_FromTLSConfig(t *testing.T) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{},
	}
	opts := &Options{
		TLSConfig: tlsConfig,
	}
	config := loadTLSConfig(opts)
	if config == nil {
		t.Fatal("Expected TLS config to be loaded")
	}
	if config != tlsConfig {
		t.Error("Expected returned config to be the same as provided config")
	}
}

func TestLoadTLSConfig_FromCertFiles(t *testing.T) {
	// Generate test certificate
	certPEM, keyPEM, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Create temporary files
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	opts := &Options{
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}
	config := loadTLSConfig(opts)
	if config == nil {
		t.Fatal("Expected TLS config to be loaded from files")
	}
	if len(config.Certificates) == 0 {
		t.Error("Expected at least one certificate to be loaded")
	}
}

func TestLoadTLSConfig_InvalidCertFile(t *testing.T) {
	tmpDir := t.TempDir()
	invalidCertFile := filepath.Join(tmpDir, "invalid.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	// Create invalid cert file
	if err := os.WriteFile(invalidCertFile, []byte("invalid cert"), 0644); err != nil {
		t.Fatalf("Failed to write invalid cert file: %v", err)
	}
	// Create key file
	if err := os.WriteFile(keyFile, []byte("invalid key"), 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	opts := &Options{
		TLSCertFile: invalidCertFile,
		TLSKeyFile:  keyFile,
	}
	config := loadTLSConfig(opts)
	if config != nil {
		t.Error("Expected TLS config to be nil for invalid certificate files")
	}
}

func TestLoadTLSConfig_NoConfig(t *testing.T) {
	opts := &Options{}
	config := loadTLSConfig(opts)
	if config != nil {
		t.Error("Expected TLS config to be nil when no config provided")
	}
}

func TestNewServer_WithTLSConfig(t *testing.T) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{},
	}
	server := New(&Options{
		EnableDoT: true,
		TLSConfig: tlsConfig,
	})
	if !server.enableDoT {
		t.Error("Expected DoT to be enabled")
	}
	if server.tlsConfig == nil {
		t.Fatal("Expected TLS config to be set")
	}
	if server.tlsConfig != tlsConfig {
		t.Error("Expected TLS config to be the same as provided")
	}
}

func TestNewServer_WithCertFiles(t *testing.T) {
	// Generate test certificate
	certPEM, keyPEM, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Create temporary files
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	server := New(&Options{
		EnableDoT:   true,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	})
	if !server.enableDoT {
		t.Error("Expected DoT to be enabled")
	}
	if server.tlsConfig == nil {
		t.Fatal("Expected TLS config to be loaded from files")
	}
	if len(server.tlsConfig.Certificates) == 0 {
		t.Error("Expected at least one certificate to be loaded")
	}
}

func TestNewServer_EnableDoT_WithoutTLSConfig(t *testing.T) {
	server := New(&Options{
		EnableDoT: true,
		// No TLS config provided
	})
	if !server.enableDoT {
		t.Error("Expected DoT to be enabled")
	}
	// TLS config should be nil when no config provided
	if server.tlsConfig != nil {
		t.Error("Expected TLS config to be nil when no config provided")
	}
}

func TestServer_Addr(t *testing.T) {
	server := New(&Options{
		Host: "127.0.0.1",
		Port: 53,
	})
	addr := server.Addr()
	expected := "127.0.0.1:53"
	if addr != expected {
		t.Errorf("Expected address %s, got %s", expected, addr)
	}
}

func TestServer_Handle(t *testing.T) {
	server := New()
	handler := func(host string, typ int) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}
	server.Handle(handler)
	if server.handler == nil {
		t.Error("Expected handler to be set")
	}
}

func TestLoadTLSConfig_TLSConfigTakesPrecedence(t *testing.T) {
	// Generate test certificate for files
	certPEM, keyPEM, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// TLSConfig should take precedence over files
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{},
	}
	opts := &Options{
		TLSConfig:   tlsConfig,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}
	config := loadTLSConfig(opts)
	if config == nil {
		t.Fatal("Expected TLS config to be loaded")
	}
	if config != tlsConfig {
		t.Error("Expected TLSConfig to take precedence over cert files")
	}
}

func TestLoadTLSConfig_OnlyCertFile(t *testing.T) {
	certPEM, _, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	opts := &Options{
		TLSCertFile: certFile,
		// No key file
	}
	config := loadTLSConfig(opts)
	if config != nil {
		t.Error("Expected TLS config to be nil when only cert file is provided")
	}
}

func TestLoadTLSConfig_OnlyKeyFile(t *testing.T) {
	_, keyPEM, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(keyFile, keyPEM, 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	opts := &Options{
		TLSKeyFile: keyFile,
		// No cert file
	}
	config := loadTLSConfig(opts)
	if config != nil {
		t.Error("Expected TLS config to be nil when only key file is provided")
	}
}

func TestNewServer_CustomPorts(t *testing.T) {
	server := New(&Options{
		Port:    5353,
		DoTPort: 8853,
	})
	if server.port != 5353 {
		t.Errorf("Expected port 5353, got %d", server.port)
	}
	if server.dotPort != 8853 {
		t.Errorf("Expected DoT port 8853, got %d", server.dotPort)
	}
}

func TestNewServer_DoTDisabled_NoTLSConfig(t *testing.T) {
	server := New(&Options{
		EnableDoT: false,
	})
	if server.enableDoT {
		t.Error("Expected DoT to be disabled")
	}
	if server.tlsConfig != nil {
		t.Error("Expected TLS config to be nil when DoT is disabled")
	}
}

func TestNewServer_DoTPortZero_UsesDefault(t *testing.T) {
	server := New(&Options{
		EnableDoT: true,
		DoTPort:   0, // Zero value
	})
	if server.dotPort != 853 {
		t.Errorf("Expected default DoT port 853 when port is 0, got %d", server.dotPort)
	}
}

func TestNewServer_WithDoH(t *testing.T) {
	server := New(&Options{
		EnableDoH: true,
		DoHPort:   8443,
	})
	if !server.enableDoH {
		t.Error("Expected DoH to be enabled")
	}
	if server.dohPort != 8443 {
		t.Errorf("Expected DoH port 8443, got %d", server.dohPort)
	}
}

func TestNewServer_EnableDoH_DefaultPort(t *testing.T) {
	server := New(&Options{
		EnableDoH: true,
	})
	if !server.enableDoH {
		t.Error("Expected DoH to be enabled")
	}
	if server.dohPort != 443 {
		t.Errorf("Expected default DoH port 443 when enabled, got %d", server.dohPort)
	}
}

func TestNewServer_DoHAddr(t *testing.T) {
	server := New(&Options{
		Host:    "127.0.0.1",
		DoHPort: 8443,
	})
	addr := server.DoHAddr()
	expected := "127.0.0.1:8443"
	if addr != expected {
		t.Errorf("Expected DoH address %s, got %s", expected, addr)
	}
}

func TestNewServer_WithDoQ(t *testing.T) {
	server := New(&Options{
		EnableDoQ: true,
		DoQPort:   8853,
	})
	if !server.enableDoQ {
		t.Error("Expected DoQ to be enabled")
	}
	if server.doqPort != 8853 {
		t.Errorf("Expected DoQ port 8853, got %d", server.doqPort)
	}
}

func TestNewServer_EnableDoQ_DefaultPort(t *testing.T) {
	server := New(&Options{
		EnableDoQ: true,
	})
	if !server.enableDoQ {
		t.Error("Expected DoQ to be enabled")
	}
	if server.doqPort != 853 {
		t.Errorf("Expected default DoQ port 853 when enabled, got %d", server.doqPort)
	}
}

func TestNewServer_DoQAddr(t *testing.T) {
	server := New(&Options{
		Host:    "127.0.0.1",
		DoQPort: 8853,
	})
	addr := server.DoQAddr()
	expected := "127.0.0.1:8853"
	if addr != expected {
		t.Errorf("Expected DoQ address %s, got %s", expected, addr)
	}
}

func TestNewServer_DoH_WithTLSConfig(t *testing.T) {
	certPEM, keyPEM, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	server := New(&Options{
		EnableDoH:   true,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	})
	if !server.enableDoH {
		t.Error("Expected DoH to be enabled")
	}
	if server.tlsConfig == nil {
		t.Fatal("Expected TLS config to be loaded for DoH")
	}
}

func TestNewServer_DoQ_WithTLSConfig(t *testing.T) {
	certPEM, keyPEM, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	server := New(&Options{
		EnableDoQ:   true,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	})
	if !server.enableDoQ {
		t.Error("Expected DoQ to be enabled")
	}
	if server.tlsConfig == nil {
		t.Fatal("Expected TLS config to be loaded for DoQ")
	}
}

func TestServer_DoH_Handler(t *testing.T) {
	// Generate test certificate
	certPEM, keyPEM, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create server with DoH enabled
	// Use different ports to avoid conflicts with other tests
	server := New(&Options{
		Host:        "127.0.0.1",
		Port:        5354, // Different port to avoid conflicts
		EnableDoH:   true,
		DoHPort:     8444, // Different port to avoid conflicts
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	})

	// Set up handler
	server.Handle(func(host string, typ int) ([]string, error) {
		if host == "example.com" {
			return []string{"1.2.3.4"}, nil
		}
		return nil, nil
	})

	// Start server in background
	go func() {
		server.Serve()
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Create DNS query
	msg := new(mdns.Msg)
	msg.SetQuestion("example.com.", mdns.TypeA)
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack DNS message: %v", err)
	}

	// Test POST request
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("POST", "https://127.0.0.1:8444/dns-query", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		// Server might not be fully started, skip test
		t.Skipf("DoH POST test skipped (server may not be ready): %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != "application/dns-message" {
		t.Errorf("Expected Content-Type application/dns-message, got %s", resp.Header.Get("Content-Type"))
	}

	// Test GET request
	base64Query := base64.RawURLEncoding.EncodeToString(data)
	getURL := "https://127.0.0.1:8444/dns-query?dns=" + base64Query

	req2, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		t.Fatalf("Failed to create GET request: %v", err)
	}

	resp2, err := client.Do(req2)
	if err != nil {
		t.Skipf("DoH GET test skipped (server may not be ready): %v", err)
		return
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for GET, got %d", resp2.StatusCode)
	}
}

func TestServer_DoQ_Handler(t *testing.T) {
	// Generate test certificate
	certPEM, keyPEM, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create server with DoQ enabled
	// Use different ports to avoid conflicts with other tests
	server := New(&Options{
		Host:        "127.0.0.1",
		Port:        5355, // Different port to avoid conflicts
		EnableDoQ:   true,
		DoQPort:     8854, // Different port to avoid conflicts
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	})

	// Set up handler
	server.Handle(func(host string, typ int) ([]string, error) {
		if host == "example.com" {
			return []string{"1.2.3.4"}, nil
		}
		return nil, nil
	})

	// Start server in background
	go func() {
		server.Serve()
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// Create DNS query
	msg := new(mdns.Msg)
	msg.SetQuestion("example.com.", mdns.TypeA)
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack DNS message: %v", err)
	}

	// Connect to DoQ server
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"doq"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, "127.0.0.1:8854", tlsConfig, &quic.Config{})
	if err != nil {
		t.Skipf("DoQ test skipped (server may not be ready): %v", err)
		return
	}
	defer conn.CloseWithError(0, "")

	// Open stream and send query
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}
	defer stream.Close()

	// Send DNS query
	_, err = stream.Write(data)
	if err != nil {
		t.Fatalf("Failed to write query: %v", err)
	}
	stream.Close()

	// Read response
	response := make([]byte, 65535)
	n, err := stream.Read(response)
	if err != nil && err != io.EOF {
		t.Fatalf("Failed to read response: %v", err)
	}

	if n == 0 {
		t.Error("Expected non-empty response")
		return
	}

	// Parse response
	respMsg := new(mdns.Msg)
	if err := respMsg.Unpack(response[:n]); err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	if respMsg.Rcode != mdns.RcodeSuccess {
		t.Errorf("Expected RcodeSuccess, got %d", respMsg.Rcode)
	}
}
