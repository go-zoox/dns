# DNS - Simple DNS Client and Server

[![PkgGoDev](https://pkg.go.dev/badge/github.com/go-zoox/dns)](https://pkg.go.dev/github.com/go-zoox/dns)
[![Build Status](https://github.com/go-zoox/dns/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/go-zoox/dns/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/go-zoox/dns)](https://goreportcard.com/report/github.com/go-zoox/dns)
[![Coverage Status](https://coveralls.io/repos/github/go-zoox/dns/badge.svg?branch=master)](https://coveralls.io/github/go-zoox/dns?branch=master)
[![GitHub issues](https://img.shields.io/github/issues/go-zoox/dns.svg)](https://github.com/go-zoox/dns/issues)
[![Release](https://img.shields.io/github/tag/go-zoox/dns.svg?label=Release)](https://github.com/go-zoox/dns/tags)

## Installation
To install the package, run:
```bash
go get github.com/go-zoox/dns
```

## Getting Started

```go
func main() {
	server := dns.NewServer(&dns.ServerOptions{
		Port: 53,
	})
	client := dns.NewClient()

	server.Handle(func(host string, typ int) ([]string, error) {
		key := fmt.Sprintf("%s_%d", host, typ)

		if host == "gozoox.com" {
			return []string{"6.6.6.6"}, nil
		}

		if ips, err := client.LookUp(host, &dns.LookUpOptions{Typ: typ}); err != nil {
			return nil, err
		} else {
			logger.Info("found host(%s %d) %v", host, typ, ips)
			return ips, nil
		}
	})

	server.Serve()
}
```

## Inspired By
* [AdGuardHome](https://github.com/AdguardTeam/AdGuardHome) - Network-wide ads & trackers blocking DNS server.
* [kenshinx/godns](https://github.com/kenshinx/godns) - A fast dns cache server written by go.
* [miekg/dns](https://github.com/miekg/dns) - DNS library in Go.

## License
GoZoox is released under the [MIT License](./LICENSE).