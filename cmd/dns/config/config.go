package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the DNS server configuration
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	DoT      DoTConfig      `yaml:"dot"`
	Hosts    HostsConfig    `yaml:"hosts"`
	Upstream UpstreamConfig `yaml:"upstream"`
}

// ServerConfig represents basic server settings
type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	TTL  uint32 `yaml:"ttl"`
}

// DoTConfig represents DNS-over-TLS configuration
type DoTConfig struct {
	Enabled bool     `yaml:"enabled"`
	Port    int      `yaml:"port"`
	TLS     TLSConfig `yaml:"tls"`
}

// TLSConfig represents TLS certificate configuration
type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// HostsConfig represents custom domain to IP mappings
// Supports multiple formats:
//   - Simple: "example.com": "1.2.3.4"
//   - Multiple IPs: "example.com": ["1.2.3.4", "1.2.3.5"]
//   - With type: "example.com": {"a": ["1.2.3.4"], "aaaa": ["2001:db8::1"]}
type HostsConfig map[string]interface{}

// HostMapping represents a parsed host mapping
type HostMapping struct {
	Domain string
	IPv4   []string
	IPv6   []string
}

// UpstreamConfig represents upstream DNS servers configuration
type UpstreamConfig struct {
	Servers []string `yaml:"servers"`
	Timeout string   `yaml:"timeout"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	if config.Server.Host == "" {
		config.Server.Host = "0.0.0.0"
	}
	if config.Server.Port == 0 {
		config.Server.Port = 53
	}
	if config.Server.TTL == 0 {
		config.Server.TTL = 500
	}
	if config.DoT.Port == 0 {
		config.DoT.Port = 853
	}
	if config.Upstream.Timeout == "" {
		config.Upstream.Timeout = "5s"
	}
	if len(config.Upstream.Servers) == 0 {
		config.Upstream.Servers = []string{"114.114.114.114:53"}
	}

	return &config, nil
}

// ParseHosts parses the hosts configuration into a map of domain to IP mappings
func (c *Config) ParseHosts() (map[string]*HostMapping, error) {
	hosts := make(map[string]*HostMapping)

	for domain, value := range c.Hosts {
		domain = strings.ToLower(strings.TrimSpace(domain))
		mapping := &HostMapping{
			Domain: domain,
			IPv4:   []string{},
			IPv6:   []string{},
		}

		switch v := value.(type) {
		case string:
			// Simple format: "example.com": "1.2.3.4"
			ip := strings.TrimSpace(v)
			if isIPv6(ip) {
				mapping.IPv6 = append(mapping.IPv6, ip)
			} else {
				mapping.IPv4 = append(mapping.IPv4, ip)
			}

		case []interface{}:
			// Multiple IPs: "example.com": ["1.2.3.4", "1.2.3.5"]
			for _, item := range v {
				ip := strings.TrimSpace(fmt.Sprintf("%v", item))
				if isIPv6(ip) {
					mapping.IPv6 = append(mapping.IPv6, ip)
				} else {
					mapping.IPv4 = append(mapping.IPv4, ip)
				}
			}

		case map[string]interface{}:
			// Structured format: "example.com": {"a": [...], "aaaa": [...]}
			if aList, ok := v["a"].([]interface{}); ok {
				for _, item := range aList {
					ip := strings.TrimSpace(fmt.Sprintf("%v", item))
					mapping.IPv4 = append(mapping.IPv4, ip)
				}
			}
			if aaaaList, ok := v["aaaa"].([]interface{}); ok {
				for _, item := range aaaaList {
					ip := strings.TrimSpace(fmt.Sprintf("%v", item))
					mapping.IPv6 = append(mapping.IPv6, ip)
				}
			}
			// Also support single string values
			if aStr, ok := v["a"].(string); ok {
				mapping.IPv4 = append(mapping.IPv4, strings.TrimSpace(aStr))
			}
			if aaaaStr, ok := v["aaaa"].(string); ok {
				mapping.IPv6 = append(mapping.IPv6, strings.TrimSpace(aaaaStr))
			}
		}

		if len(mapping.IPv4) > 0 || len(mapping.IPv6) > 0 {
			hosts[domain] = mapping
		}
	}

	return hosts, nil
}

// LookupHost looks up a domain in the hosts configuration
func (c *Config) LookupHost(domain string, queryType int) ([]string, error) {
	hosts, err := c.ParseHosts()
	if err != nil {
		return nil, err
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	
	// Try exact match first
	if mapping, ok := hosts[domain]; ok {
		if queryType == 4 { // A record
			if len(mapping.IPv4) > 0 {
				return mapping.IPv4, nil
			}
		} else if queryType == 6 { // AAAA record
			if len(mapping.IPv6) > 0 {
				return mapping.IPv6, nil
			}
		}
	}

	// Try with trailing dot removed
	domainNoDot := strings.TrimSuffix(domain, ".")
	if mapping, ok := hosts[domainNoDot]; ok {
		if queryType == 4 { // A record
			if len(mapping.IPv4) > 0 {
				return mapping.IPv4, nil
			}
		} else if queryType == 6 { // AAAA record
			if len(mapping.IPv6) > 0 {
				return mapping.IPv6, nil
			}
		}
	}

	return nil, fmt.Errorf("not found in hosts")
}

// isIPv6 checks if an IP address is IPv6
func isIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}
