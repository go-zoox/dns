package commands

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-zoox/cli"
	"github.com/go-zoox/dns"
	"github.com/go-zoox/dns/client"
	"github.com/go-zoox/dns/cmd/dns/config"
	"github.com/go-zoox/logger"
)

// NewServerCommand creates a new server command
func NewServerCommand() *cli.Command {
	return &cli.Command{
		Name:  "server",
		Usage: "Start a DNS server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Path to configuration file (YAML)",
				EnvVars: []string{"DNS_CONFIG"},
			},
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Usage:   "DNS server port (UDP/TCP)",
				Value:   53,
				EnvVars: []string{"DNS_PORT"},
			},
			&cli.StringFlag{
				Name:    "host",
				Usage:   "DNS server host",
				Value:   "0.0.0.0",
				EnvVars: []string{"DNS_HOST"},
			},
			&cli.UintFlag{
				Name:    "ttl",
				Usage:   "TTL for DNS responses (in seconds)",
				Value:   500,
				EnvVars: []string{"DNS_TTL"},
			},
			&cli.BoolFlag{
				Name:    "dot",
				Usage:   "Enable DNS-over-TLS (DoT)",
				EnvVars: []string{"DNS_DOT"},
			},
			&cli.IntFlag{
				Name:    "dot-port",
				Usage:   "DoT server port",
				Value:   853,
				EnvVars: []string{"DNS_DOT_PORT"},
			},
			&cli.StringFlag{
				Name:    "tls-cert",
				Usage:   "TLS certificate file path (required for DoT)",
				EnvVars: []string{"DNS_TLS_CERT"},
			},
			&cli.StringFlag{
				Name:    "tls-key",
				Usage:   "TLS private key file path (required for DoT)",
				EnvVars: []string{"DNS_TLS_KEY"},
			},
			&cli.StringSliceFlag{
				Name:    "upstream",
				Aliases: []string{"u"},
				Usage:   "Upstream DNS servers",
				EnvVars: []string{"DNS_UPSTREAM"},
			},
		},
		Action: func(ctx *cli.Context) error {
			var cfg *config.Config
			var err error

			// Load configuration file if provided
			configPath := ctx.String("config")
			if configPath != "" {
				cfg, err = config.LoadConfig(configPath)
				if err != nil {
					return fmt.Errorf("failed to load config: %w", err)
				}
				logger.Info("Loaded configuration from %s", configPath)
			}

			// Get values from config file or command line flags (CLI flags override config)
			port := ctx.Int("port")
			host := ctx.String("host")
			ttl := ctx.Uint("ttl")
			enableDoT := ctx.Bool("dot")
			dotPort := ctx.Int("dot-port")
			tlsCert := ctx.String("tls-cert")
			tlsKey := ctx.String("tls-key")
			upstreams := ctx.StringSlice("upstream")

			// Merge config file values if config was loaded
			if cfg != nil {
				if port == 53 && cfg.Server.Port != 0 {
					port = cfg.Server.Port
				}
				if host == "0.0.0.0" && cfg.Server.Host != "" {
					host = cfg.Server.Host
				}
				if ttl == 500 && cfg.Server.TTL != 0 {
					ttl = uint(cfg.Server.TTL)
				}
				if !enableDoT && cfg.DoT.Enabled {
					enableDoT = cfg.DoT.Enabled
				}
				if dotPort == 853 && cfg.DoT.Port != 0 {
					dotPort = cfg.DoT.Port
				}
				if tlsCert == "" && cfg.DoT.TLS.Cert != "" {
					tlsCert = cfg.DoT.TLS.Cert
				}
				if tlsKey == "" && cfg.DoT.TLS.Key != "" {
					tlsKey = cfg.DoT.TLS.Key
				}
				if len(upstreams) == 0 && len(cfg.Upstream.Servers) > 0 {
					upstreams = cfg.Upstream.Servers
				}
			}

			// Default upstream if still empty
			if len(upstreams) == 0 {
				upstreams = []string{"114.114.114.114:53"}
			}

			// Parse upstream timeout
			upstreamTimeout := 5 * time.Second
			if cfg != nil && cfg.Upstream.Timeout != "" {
				if parsed, err := time.ParseDuration(cfg.Upstream.Timeout); err == nil {
					upstreamTimeout = parsed
				}
			}

			// Validate DoT configuration
			if enableDoT {
				if tlsCert == "" || tlsKey == "" {
					return fmt.Errorf("TLS certificate and key are required when DoT is enabled (use --tls-cert and --tls-key or config file)")
				}
			}

			// Create upstream client
			upstreamClient := dns.NewClient(&dns.ClientOptions{
				Servers: upstreams,
				Timeout: upstreamTimeout,
			})

			// Create server
			serverOptions := &dns.ServerOptions{
				Port:      port,
				Host:      host,
				TTL:       uint32(ttl),
				EnableDoT: enableDoT,
			}

			if enableDoT {
				serverOptions.DoTPort = dotPort
				serverOptions.TLSCertFile = tlsCert
				serverOptions.TLSKeyFile = tlsKey
			}

			server := dns.NewServer(serverOptions)

			// Set up handler
			server.Handle(func(hostname string, typ int) ([]string, error) {
				// First, check custom hosts mapping (highest priority)
				if cfg != nil {
					ips, err := cfg.LookupHost(hostname, typ)
					if err == nil && len(ips) > 0 {
						logger.Info("Resolved %s (%d) from hosts -> %v", hostname, typ, ips)
						return ips, nil
					}
				}

				// Fallback to upstream DNS servers
				ips, err := upstreamClient.LookUp(hostname, &client.LookUpOptions{
					Typ: typ,
				})
				if err != nil {
					logger.Error("Failed to resolve %s: %v", hostname, err)
					return nil, err
				}

				logger.Info("Resolved %s (%d) from upstream -> %v", hostname, typ, ips)
				return ips, nil
			})

			// Handle graceful shutdown
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

			go func() {
				<-sigChan
				logger.Info("Shutting down DNS server...")
				os.Exit(0)
			}()

			// Start server
			if enableDoT {
				logger.Info("Starting DNS server on %s:%d (UDP/TCP) and DoT on %s:%d", host, port, host, dotPort)
			} else {
				logger.Info("Starting DNS server on %s:%d (UDP/TCP)", host, port)
			}

			server.Serve()

			return nil
		},
	}
}
