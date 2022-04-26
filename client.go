package dns

import (
	"strconv"
	"time"

	"github.com/go-zoox/errors"

	"github.com/AdguardTeam/dnsproxy/upstream"
	mdns "github.com/miekg/dns"
)

// Client is a DNS client
type Client struct {
	Servers []string
	Timeout time.Duration
}

// ClientOptions is a set of options for Client
type ClientOptions struct {
	// Servers is a list of DNS servers to use.
	// Support
	//   1. PLAIN DNS						- 8.8.8.8:53 or udp://dns.adguard.com for plain DNS;
	//	 2. PLAIN DNS-over-TCP 	- tcp://8.8.8.8:53 for plain DNS-over-TCP;
	// 	 3. DNS-over-TLS 				- tls://1.1.1.1 for DNS-over-TLS;
	//   4. DNS-over-HTTPS			- https://dns.adguard.com/dns-query for DNS-over-HTTPS;
	//   5. DNSCRYPT 						- sdns://... for DNS stamp, see https://dnscrypt.info/stamps-specifications.
	Servers []string

	// Timeout is the maximum duration to wait for a response from a server.
	// default: 5 seconds
	Timeout time.Duration
}

// NewClient creates a new DNS client
func NewClient(options ...*ClientOptions) *Client {
	servers := []string{}
	timeout := 5 * time.Second

	if len(options) > 0 {
		if options[0].Servers != nil && len(options[0].Servers) > 0 {
			servers = append(servers, options[0].Servers...)
		}

		if options[0].Timeout != 0 {
			timeout = options[0].Timeout
		}
	} else {
		servers = append(servers, DefaultDNSServer)
	}

	return &Client{
		Servers: servers,
		Timeout: timeout,
	}
}

// LookUpOptions is a set of options for LookUp
type LookUpOptions struct {
	Typ int
}

// LookUp looks up a domain name and returns a list of IP addresses
func (c *Client) LookUp(domain string, options ...*LookUpOptions) ([]string, error) {
	typ := QueryTypeIPv4
	if len(options) > 0 {
		typ = options[0].Typ
	}

	switch typ {
	case QueryTypeIPv4:
		return c.lookUpIPv4(domain)
	case QueryTypeIPv6:
		return c.lookUpIPv6(domain)
	default:
		return nil, errors.Errorf("invalid type: %d", typ)
	}
}

func (c *Client) lookUpIPv4(domain string) ([]string, error) {
	r, err := c.query(domain, mdns.TypeA)
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

func (c *Client) lookUpIPv6(domain string) ([]string, error) {
	r, err := c.query(domain, mdns.TypeAAAA)
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

func (c *Client) createRequest(domain string, typ uint16) *mdns.Msg {
	req := new(mdns.Msg)
	req.Id = mdns.Id()
	req.RecursionDesired = true
	req.Question = []mdns.Question{
		{Name: domain + ".", Qtype: typ, Qclass: mdns.ClassINET},
	}

	return req
}

func (c *Client) query(domain string, typ uint16) (*mdns.Msg, error) {
	var reply *mdns.Msg
	var err error
	var u upstream.Upstream

	req := c.createRequest(domain, typ)

	for _, s := range c.Servers {
		u, err = upstream.AddressToUpstream(s, &upstream.Options{
			Timeout: c.Timeout,
		})
		if err != nil {
			// return nil, fmt.Errorf("Cannot create an upstream: %s", err)
			// try next server
			continue
		}

		reply, err = u.Exchange(req)
		if err == nil && reply != nil && reply.Rcode == mdns.RcodeSuccess {
			return reply, nil
		}

		if reply != nil && reply.Rcode != mdns.RcodeSuccess {
			err = errors.New("failed to query with code: " + strconv.Itoa(reply.Rcode))
		}
	}

	return reply, err
}
