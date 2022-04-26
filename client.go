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
	Servers []*ClientDNSServer
}

func NewClient(options ...*ClientOptions) *Client {
	servers := []*ClientDNSServer{}

	if len(options) > 0 && options[0].Servers != nil && len(options[0].Servers) > 0 {
		servers = append(servers, options[0].Servers...)
	} else {
		servers = append(servers, NewClientDNSServer(DefaultDNSServer, 53))
	}

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
	r, err := client.Query(domain, mdns.TypeA)
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
	r, err := client.Query(domain, mdns.TypeAAAA)
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

func (client *Client) CreateMsg(domain string, typ uint16) *mdns.Msg {
	m := new(mdns.Msg)
	m.Id = mdns.Id()
	m.RecursionDesired = true
	m.SetQuestion(mdns.Fqdn(domain), typ)

	return m
}

func (client *Client) Query(domain string, typ uint16) (*mdns.Msg, error) {
	var reply *mdns.Msg
	var err error

	msg := client.CreateMsg(domain, typ)

	for _, s := range client.servers {
		reply, _, err = client.core.Exchange(msg, net.JoinHostPort(s.Server, strconv.Itoa(s.Port)))
		if err == nil && reply != nil && reply.Rcode == mdns.RcodeSuccess {
			return reply, nil
		}

		if reply != nil && reply.Rcode != mdns.RcodeSuccess {
			err = errors.New("failed to query with code: " + strconv.Itoa(reply.Rcode))
		}
	}

	return reply, err
}

type ClientDNSServer struct {
	Server string
	Port   int
}

func NewClientDNSServer(server string, port int) *ClientDNSServer {
	return &ClientDNSServer{server, port}
}
