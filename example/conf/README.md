# DNS Server Configuration

This directory contains example configuration files for the DNS server.

## Configuration File Format

The DNS server uses YAML format for configuration files. You can specify a configuration file using the `--config` or `-c` flag:

```bash
dns server --config /path/to/config.yaml
```

## Configuration Structure

### Basic Server Settings

```yaml
server:
  host: "0.0.0.0"    # Listen address (default: 0.0.0.0)
  port: 53           # DNS server port (default: 53)
  ttl: 500           # TTL for DNS responses in seconds (default: 500)
```

### DNS-over-TLS (DoT) Configuration

```yaml
dot:
  enabled: false     # Enable DoT server (default: false)
  port: 853         # DoT server port (default: 853)
  tls:
    cert: "/path/to/cert.pem"    # TLS certificate file (required if DoT enabled)
    key: "/path/to/key.pem"      # TLS private key file (required if DoT enabled)
```

### Custom Domain Mappings (Hosts)

Custom domain mappings have the **highest priority** and are checked before upstream DNS servers.

#### Simple Format

```yaml
hosts:
  "example.com": "1.2.3.4"
  "test.local": "192.168.1.100"
```

#### Multiple IPs

```yaml
hosts:
  "www.example.com":
    - "1.2.3.4"
    - "1.2.3.5"
```

#### IPv6 Support

```yaml
hosts:
  "ipv6.example.com": "2001:db8::1"
```

#### Both IPv4 and IPv6

```yaml
hosts:
  "dual.example.com":
    a:     # IPv4 addresses (A records)
      - "1.2.3.4"
      - "1.2.3.5"
    aaaa: # IPv6 addresses (AAAA records)
      - "2001:db8::1"
      - "2001:db8::2"
```

### Upstream DNS Servers

Upstream DNS servers are used when custom hosts don't match the query.

```yaml
upstream:
  servers:
    - "114.114.114.114:53"    # Plain DNS
    - "8.8.8.8:53"            # Google DNS
    - "tls://1.1.1.1"         # Cloudflare DoT
    - "https://dns.adguard.com/dns-query"  # DoH
  timeout: "5s"              # Query timeout (default: 5s)
```

## Priority Order

1. **Custom Hosts** (from `hosts` section) - Highest priority
2. **Upstream DNS Servers** (from `upstream.servers`) - Fallback

## Command Line Override

Command line flags **override** configuration file values. For example:

```bash
# Use config file but override port
dns server --config config.yaml --port 5353
```

## Example Files

- `server.yaml` - Complete example with all options
- `test-server.yaml` - Minimal test configuration

## Usage Examples

### Basic Server with Custom Hosts

```yaml
server:
  port: 53

hosts:
  "local.dev": "127.0.0.1"
  "api.local.dev": "127.0.0.1"

upstream:
  servers:
    - "8.8.8.8:53"
```

### Server with DoT Support

```yaml
server:
  port: 53

dot:
  enabled: true
  port: 853
  tls:
    cert: "/etc/ssl/certs/dns.crt"
    key: "/etc/ssl/private/dns.key"

upstream:
  servers:
    - "tls://1.1.1.1"
```
