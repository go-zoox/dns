package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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
