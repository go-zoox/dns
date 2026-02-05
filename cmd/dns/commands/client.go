package commands

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-zoox/cli"
	"github.com/go-zoox/dns"
	"github.com/go-zoox/dns/client"
	"github.com/go-zoox/dns/constants"
)

// NewClientCommand creates a new client command
func NewClientCommand() *cli.Command {
	return &cli.Command{
		Name:  "client",
		Usage: "DNS client for querying DNS servers",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:    "server",
				Aliases: []string{"s"},
				Usage:   "DNS server address (supports plain DNS, DoT, DoH, etc.)",
				EnvVars: []string{"DNS_SERVER"},
			},
			&cli.StringFlag{
				Name:    "domain",
				Aliases: []string{"d"},
				Usage:   "Domain name to query",
			},
			&cli.StringFlag{
				Name:    "type",
				Aliases: []string{"t"},
				Usage:   "Query type (A, AAAA)",
				Value:   "A",
			},
			&cli.StringFlag{
				Name:    "timeout",
				Usage:   "Timeout for DNS query (e.g., 5s, 10s)",
				Value:   "5s",
				EnvVars: []string{"DNS_TIMEOUT"},
			},
			&cli.BoolFlag{
				Name:    "plain",
				Usage:   "Output only IP addresses, one per line",
				EnvVars: []string{"DNS_PLAIN"},
			},
		},
		Action: func(ctx *cli.Context) error {
			servers := ctx.StringSlice("server")
			domain := ctx.String("domain")
			queryType := strings.ToUpper(ctx.String("type"))
			timeoutStr := ctx.String("timeout")
			plain := ctx.Bool("plain")

			// Parse timeout
			timeout, err := time.ParseDuration(timeoutStr)
			if err != nil {
				return fmt.Errorf("invalid timeout format: %v", err)
			}

			if domain == "" {
				return fmt.Errorf("domain is required")
			}

			// Default server if not provided
			if len(servers) == 0 {
				servers = []string{"114.114.114.114:53"}
			}

			// Create DNS client
			dnsClient := dns.NewClient(&dns.ClientOptions{
				Servers: servers,
				Timeout: timeout,
			})

			// Determine query type
			var typ int
			switch queryType {
			case "A":
				typ = constants.QueryTypeIPv4
			case "AAAA":
				typ = constants.QueryTypeIPv6
			default:
				return fmt.Errorf("unsupported query type: %s (supported: A, AAAA)", queryType)
			}

			// Perform lookup
			ips, err := dnsClient.LookUp(domain, &client.LookUpOptions{
				Typ: typ,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			// Print results
			if len(ips) == 0 {
				if !plain {
					fmt.Printf("No %s records found for %s\n", queryType, domain)
				}
				return nil
			}

			if plain {
				// Plain mode: only output IP addresses, one per line
				for _, ip := range ips {
					fmt.Println(ip)
				}
			} else {
				// Normal mode: output with headers
				fmt.Printf("%s records for %s:\n", queryType, domain)
				for _, ip := range ips {
					fmt.Printf("  %s\n", ip)
				}
			}

			return nil
		},
	}
}
