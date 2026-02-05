package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test.yaml")

	configContent := `
server:
  host: "127.0.0.1"
  port: 5353
  ttl: 300

dot:
  enabled: true
  port: 8853
  tls:
    cert: "/path/to/cert.pem"
    key: "/path/to/key.pem"

hosts:
  "example.com": "1.2.3.4"
  "test.local": "192.168.1.100"

upstream:
  servers:
    - "8.8.8.8:53"
  timeout: "10s"
`

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test server config
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Expected host 127.0.0.1, got %s", cfg.Server.Host)
	}
	if cfg.Server.Port != 5353 {
		t.Errorf("Expected port 5353, got %d", cfg.Server.Port)
	}
	if cfg.Server.TTL != 300 {
		t.Errorf("Expected TTL 300, got %d", cfg.Server.TTL)
	}

	// Test DoT config
	if !cfg.DoT.Enabled {
		t.Error("Expected DoT to be enabled")
	}
	if cfg.DoT.Port != 8853 {
		t.Errorf("Expected DoT port 8853, got %d", cfg.DoT.Port)
	}
	if cfg.DoT.TLS.Cert != "/path/to/cert.pem" {
		t.Errorf("Expected cert /path/to/cert.pem, got %s", cfg.DoT.TLS.Cert)
	}

	// Test upstream config
	if len(cfg.Upstream.Servers) != 1 {
		t.Errorf("Expected 1 upstream server, got %d", len(cfg.Upstream.Servers))
	}
	if cfg.Upstream.Servers[0] != "8.8.8.8:53" {
		t.Errorf("Expected upstream 8.8.8.8:53, got %s", cfg.Upstream.Servers[0])
	}
	if cfg.Upstream.Timeout != "10s" {
		t.Errorf("Expected timeout 10s, got %s", cfg.Upstream.Timeout)
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "minimal.yaml")

	// Minimal config with only hosts
	configContent := `
hosts:
  "example.com": "1.2.3.4"
`

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test defaults
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Expected default host 0.0.0.0, got %s", cfg.Server.Host)
	}
	if cfg.Server.Port != 53 {
		t.Errorf("Expected default port 53, got %d", cfg.Server.Port)
	}
	if cfg.Server.TTL != 500 {
		t.Errorf("Expected default TTL 500, got %d", cfg.Server.TTL)
	}
	if cfg.DoT.Port != 853 {
		t.Errorf("Expected default DoT port 853, got %d", cfg.DoT.Port)
	}
	if cfg.Upstream.Timeout != "5s" {
		t.Errorf("Expected default timeout 5s, got %s", cfg.Upstream.Timeout)
	}
	if len(cfg.Upstream.Servers) != 1 || cfg.Upstream.Servers[0] != "114.114.114.114:53" {
		t.Errorf("Expected default upstream, got %v", cfg.Upstream.Servers)
	}
}

func TestLoadConfig_InvalidFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/file.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "invalid.yaml")

	invalidContent := `
server:
  port: invalid
  host: [invalid, array]
`

	if err := os.WriteFile(configFile, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	_, err := LoadConfig(configFile)
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}
}

func TestParseHosts_SimpleFormat(t *testing.T) {
	cfg := &Config{
		Hosts: HostsConfig{
			"example.com": "1.2.3.4",
			"test.local":  "192.168.1.100",
		},
	}

	hosts, err := cfg.ParseHosts()
	if err != nil {
		t.Fatalf("Failed to parse hosts: %v", err)
	}

	if len(hosts) != 2 {
		t.Errorf("Expected 2 hosts, got %d", len(hosts))
	}

	// Check example.com
	if mapping, ok := hosts["example.com"]; ok {
		if len(mapping.IPv4) != 1 || mapping.IPv4[0] != "1.2.3.4" {
			t.Errorf("Expected example.com -> 1.2.3.4, got %v", mapping.IPv4)
		}
	} else {
		t.Error("example.com not found in hosts")
	}

	// Check test.local
	if mapping, ok := hosts["test.local"]; ok {
		if len(mapping.IPv4) != 1 || mapping.IPv4[0] != "192.168.1.100" {
			t.Errorf("Expected test.local -> 192.168.1.100, got %v", mapping.IPv4)
		}
	} else {
		t.Error("test.local not found in hosts")
	}
}

func TestParseHosts_MultipleIPs(t *testing.T) {
	cfg := &Config{
		Hosts: HostsConfig{
			"www.example.com": []interface{}{"1.2.3.4", "1.2.3.5", "1.2.3.6"},
		},
	}

	hosts, err := cfg.ParseHosts()
	if err != nil {
		t.Fatalf("Failed to parse hosts: %v", err)
	}

	if mapping, ok := hosts["www.example.com"]; ok {
		if len(mapping.IPv4) != 3 {
			t.Errorf("Expected 3 IPv4 addresses, got %d", len(mapping.IPv4))
		}
		expected := []string{"1.2.3.4", "1.2.3.5", "1.2.3.6"}
		for i, ip := range expected {
			if mapping.IPv4[i] != ip {
				t.Errorf("Expected IP %s at index %d, got %s", ip, i, mapping.IPv4[i])
			}
		}
	} else {
		t.Error("www.example.com not found in hosts")
	}
}

func TestParseHosts_IPv6(t *testing.T) {
	cfg := &Config{
		Hosts: HostsConfig{
			"ipv6.example.com": "2001:db8::1",
		},
	}

	hosts, err := cfg.ParseHosts()
	if err != nil {
		t.Fatalf("Failed to parse hosts: %v", err)
	}

	if mapping, ok := hosts["ipv6.example.com"]; ok {
		if len(mapping.IPv6) != 1 || mapping.IPv6[0] != "2001:db8::1" {
			t.Errorf("Expected IPv6 2001:db8::1, got %v", mapping.IPv6)
		}
		if len(mapping.IPv4) != 0 {
			t.Errorf("Expected no IPv4, got %v", mapping.IPv4)
		}
	} else {
		t.Error("ipv6.example.com not found in hosts")
	}
}

func TestParseHosts_StructuredFormat(t *testing.T) {
	cfg := &Config{
		Hosts: HostsConfig{
			"dual.example.com": map[string]interface{}{
				"a":    []interface{}{"1.2.3.4", "1.2.3.5"},
				"aaaa": []interface{}{"2001:db8::1", "2001:db8::2"},
			},
		},
	}

	hosts, err := cfg.ParseHosts()
	if err != nil {
		t.Fatalf("Failed to parse hosts: %v", err)
	}

	if mapping, ok := hosts["dual.example.com"]; ok {
		if len(mapping.IPv4) != 2 {
			t.Errorf("Expected 2 IPv4 addresses, got %d", len(mapping.IPv4))
		}
		if len(mapping.IPv6) != 2 {
			t.Errorf("Expected 2 IPv6 addresses, got %d", len(mapping.IPv6))
		}
		if mapping.IPv4[0] != "1.2.3.4" || mapping.IPv4[1] != "1.2.3.5" {
			t.Errorf("Unexpected IPv4 addresses: %v", mapping.IPv4)
		}
		if mapping.IPv6[0] != "2001:db8::1" || mapping.IPv6[1] != "2001:db8::2" {
			t.Errorf("Unexpected IPv6 addresses: %v", mapping.IPv6)
		}
	} else {
		t.Error("dual.example.com not found in hosts")
	}
}

func TestParseHosts_StructuredFormat_StringValues(t *testing.T) {
	cfg := &Config{
		Hosts: HostsConfig{
			"simple.example.com": map[string]interface{}{
				"a":    "1.2.3.4",
				"aaaa": "2001:db8::1",
			},
		},
	}

	hosts, err := cfg.ParseHosts()
	if err != nil {
		t.Fatalf("Failed to parse hosts: %v", err)
	}

	if mapping, ok := hosts["simple.example.com"]; ok {
		if len(mapping.IPv4) != 1 || mapping.IPv4[0] != "1.2.3.4" {
			t.Errorf("Expected IPv4 1.2.3.4, got %v", mapping.IPv4)
		}
		if len(mapping.IPv6) != 1 || mapping.IPv6[0] != "2001:db8::1" {
			t.Errorf("Expected IPv6 2001:db8::1, got %v", mapping.IPv6)
		}
	} else {
		t.Error("simple.example.com not found in hosts")
	}
}

func TestLookupHost_ExactMatch(t *testing.T) {
	cfg := &Config{
		Hosts: HostsConfig{
			"example.com": "1.2.3.4",
		},
	}

	// Test A record lookup
	ips, err := cfg.LookupHost("example.com", 4)
	if err != nil {
		t.Fatalf("Failed to lookup host: %v", err)
	}
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("Expected [1.2.3.4], got %v", ips)
	}

	// Test with trailing dot
	ips, err = cfg.LookupHost("example.com.", 4)
	if err != nil {
		t.Fatalf("Failed to lookup host with dot: %v", err)
	}
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("Expected [1.2.3.4], got %v", ips)
	}
}

func TestLookupHost_CaseInsensitive(t *testing.T) {
	cfg := &Config{
		Hosts: HostsConfig{
			"Example.COM": "1.2.3.4",
		},
	}

	ips, err := cfg.LookupHost("example.com", 4)
	if err != nil {
		t.Fatalf("Failed to lookup host: %v", err)
	}
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("Expected [1.2.3.4], got %v", ips)
	}

	ips, err = cfg.LookupHost("EXAMPLE.COM", 4)
	if err != nil {
		t.Fatalf("Failed to lookup host: %v", err)
	}
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("Expected [1.2.3.4], got %v", ips)
	}
}

func TestLookupHost_IPv6(t *testing.T) {
	cfg := &Config{
		Hosts: HostsConfig{
			"ipv6.example.com": "2001:db8::1",
		},
	}

	// Test AAAA record lookup
	ips, err := cfg.LookupHost("ipv6.example.com", 6)
	if err != nil {
		t.Fatalf("Failed to lookup host: %v", err)
	}
	if len(ips) != 1 || ips[0] != "2001:db8::1" {
		t.Errorf("Expected [2001:db8::1], got %v", ips)
	}

	// Test A record lookup (should not find IPv6)
	_, err = cfg.LookupHost("ipv6.example.com", 4)
	if err == nil {
		t.Error("Expected error for A record lookup on IPv6-only host")
	}
}

func TestLookupHost_NotFound(t *testing.T) {
	cfg := &Config{
		Hosts: HostsConfig{
			"example.com": "1.2.3.4",
		},
	}

	_, err := cfg.LookupHost("nonexistent.com", 4)
	if err == nil {
		t.Error("Expected error for nonexistent host")
	}
}

func TestLookupHost_MultipleIPs(t *testing.T) {
	cfg := &Config{
		Hosts: HostsConfig{
			"www.example.com": []interface{}{"1.2.3.4", "1.2.3.5"},
		},
	}

	ips, err := cfg.LookupHost("www.example.com", 4)
	if err != nil {
		t.Fatalf("Failed to lookup host: %v", err)
	}
	if len(ips) != 2 {
		t.Errorf("Expected 2 IPs, got %d", len(ips))
	}
	if ips[0] != "1.2.3.4" || ips[1] != "1.2.3.5" {
		t.Errorf("Expected [1.2.3.4, 1.2.3.5], got %v", ips)
	}
}

func TestLookupHost_DualStack(t *testing.T) {
	cfg := &Config{
		Hosts: HostsConfig{
			"dual.example.com": map[string]interface{}{
				"a":    []interface{}{"1.2.3.4"},
				"aaaa": []interface{}{"2001:db8::1"},
			},
		},
	}

	// Test A record
	ips, err := cfg.LookupHost("dual.example.com", 4)
	if err != nil {
		t.Fatalf("Failed to lookup A record: %v", err)
	}
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("Expected A record [1.2.3.4], got %v", ips)
	}

	// Test AAAA record
	ips, err = cfg.LookupHost("dual.example.com", 6)
	if err != nil {
		t.Fatalf("Failed to lookup AAAA record: %v", err)
	}
	if len(ips) != 1 || ips[0] != "2001:db8::1" {
		t.Errorf("Expected AAAA record [2001:db8::1], got %v", ips)
	}
}

func TestIsIPv6(t *testing.T) {
	tests := []struct {
		ip     string
		isIPv6 bool
	}{
		{"1.2.3.4", false},
		{"192.168.1.1", false},
		{"2001:db8::1", true},
		{"::1", true},
		{"fe80::1", true},
		{"127.0.0.1", false},
	}

	for _, tt := range tests {
		result := isIPv6(tt.ip)
		if result != tt.isIPv6 {
			t.Errorf("isIPv6(%s) = %v, expected %v", tt.ip, result, tt.isIPv6)
		}
	}
}

func TestParseHosts_EmptyHosts(t *testing.T) {
	cfg := &Config{
		Hosts: HostsConfig{},
	}

	hosts, err := cfg.ParseHosts()
	if err != nil {
		t.Fatalf("Failed to parse empty hosts: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("Expected empty hosts map, got %d entries", len(hosts))
	}
}

func TestParseHosts_WhitespaceHandling(t *testing.T) {
	cfg := &Config{
		Hosts: HostsConfig{
			"  example.com  ": "  1.2.3.4  ",
		},
	}

	hosts, err := cfg.ParseHosts()
	if err != nil {
		t.Fatalf("Failed to parse hosts: %v", err)
	}

	// Should trim whitespace
	if mapping, ok := hosts["example.com"]; ok {
		if len(mapping.IPv4) != 1 || mapping.IPv4[0] != "1.2.3.4" {
			t.Errorf("Expected trimmed values, got %v", mapping.IPv4)
		}
	} else {
		t.Error("example.com not found after trimming")
	}
}
