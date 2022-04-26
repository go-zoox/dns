package dns

import (
	"github.com/go-zoox/dns/client"
	"github.com/go-zoox/dns/server"
)

// ClientOptions is an alias for client.Options
type ClientOptions = client.Options

// NewClient creates a new DNS client
func NewClient(options ...*ClientOptions) *client.Client {
	return client.New(options...)
}

// ServerOptions is an alias for server.Options
type ServerOptions = server.Options

// NewServer creates a new DNS server
func NewServer(options ...*ServerOptions) *server.Server {
	return server.New(options...)
}
