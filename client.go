package dns

import (
	"net"
	"strconv"
	"time"

	"github.com/go-zoox/errors"

	mdns "github.com/miekg/dns"
)

type Client struct {
	core    *mdns.Client
	servers []*ClientDNSServer
}

type ClientOptions struct {
	servers []*ClientDNSServer
}

func NewClient(options ...*ClientOptions) *Client {
	servers := []*ClientDNSServer{}

	if len(options) > 0 {
		servers = append(servers, options[0].servers...)
	}

	servers = append(servers, NewClientDNSServer(DefaultDNSServer, 53))

	core := &mdns.Client{
		Timeout: 5 * time.Second,
	}

	return &Client{
		core:    core,
		servers: servers,
	}
}

type LookUpOptions struct {
	Typ int
}

func (client *Client) LookUp(domain string, options ...*LookUpOptions) ([]string, error) {
	typ := QueryTypeIPv4
	if len(options) > 0 {
		typ = options[0].Typ
	}

	switch typ {
	case QueryTypeIPv4:
		return client.LookUpIPv4(domain)
	case QueryTypeIPv6:
		return client.LookUpIPv6(domain)
	default:
		return nil, errors.Errorf("invalid type: %d", typ)
	}
}

func (client *Client) LookUpIPv4(domain string) ([]string, error) {
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(domain), mdns.TypeA)
	r, err := client.Query(m)
	if err != nil {
		return nil, err
	}

	dst := []string{}
	for _, answer := range r.Answer {
		if record, ok := answer.(*mdns.A); ok {
			dst = append(dst, record.A.String())
		}
	}

	return dst, nil
}

func (client *Client) LookUpIPv6(domain string) ([]string, error) {
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(domain), mdns.TypeAAAA)
	r, err := client.Query(m)
	if err != nil {
		return nil, err
	}

	dst := []string{}
	for _, answer := range r.Answer {
		if record, ok := answer.(*mdns.AAAA); ok {
			dst = append(dst, record.AAAA.String())
		}
	}

	return dst, nil
}

func (client *Client) Query(m *mdns.Msg) (*mdns.Msg, error) {
	var r *mdns.Msg
	var err error
	for _, s := range client.servers {
		r, _, err = client.core.Exchange(m, net.JoinHostPort(s.Server, strconv.Itoa(s.Port)))
		if err != nil {
			return nil, err
		}
		// if r.Rcode != mdns.RcodeSuccess {
		// 	return nil, errors.New("failed to query: " + domain)
		// }
		if r.Rcode != mdns.RcodeSuccess {
			return nil, errors.New("failed to query")
		}
	}

	return r, nil
}

type ClientDNSServer struct {
	Server string
	Port   int
}

func NewClientDNSServer(server string, port int) *ClientDNSServer {
	return &ClientDNSServer{server, port}
}
