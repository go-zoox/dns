package dns

import (
	"net"
	"os"
	"os/signal"
	"strconv"

	"github.com/go-zoox/logger"
	"github.com/miekg/dns"
	mdns "github.com/miekg/dns"
)

type Server struct {
	port    int
	host    string
	ttl     uint32
	handler func(host string, typ int) ([]string, error)
}

type ServerOptions struct {
	Port int
	Host string
	TTL  uint32
}

// NewServer creates a new dns server
func NewServer(options ...*ServerOptions) *Server {
	port := 8853 // 53
	host := "0.0.0.0"
	ttl := uint32(500) // 500 ms
	if len(options) > 0 {
		if options[0].Port != 0 {
			port = options[0].Port
		}
		if options[0].Host != "" {
			host = options[0].Host
		}
		if options[0].TTL != 0 {
			ttl = options[0].TTL
		}
	}

	return &Server{
		port: port,
		host: host,
		ttl:  ttl,
	}
}

func (s *Server) Addr() string {
	return net.JoinHostPort(s.host, strconv.Itoa(s.port))
}

// Handle handles the lookup
func (s *Server) Handle(cb func(host string, typ int) ([]string, error)) {
	s.handler = cb
}

func (s *Server) doUDP(w mdns.ResponseWriter, req *mdns.Msg) {
	s.do("udp", w, req)
}

func (s *Server) doTCP(w mdns.ResponseWriter, req *mdns.Msg) {
	s.do("tcp", w, req)
}

func (s *Server) do(typ string, w mdns.ResponseWriter, req *mdns.Msg) {
	q := req.Question[0]
	Q := Question{UnFqdn(q.Name), mdns.TypeToString[q.Qtype], mdns.ClassToString[q.Qclass]}

	var remote net.IP
	if typ == "tcp" {
		remote = w.RemoteAddr().(*net.TCPAddr).IP
	} else {
		remote = w.RemoteAddr().(*net.UDPAddr).IP
	}
	logger.Info("[%s] lookup %s", remote, Q.String())

	IPQuery := isIPQuery(q)

	m := new(mdns.Msg)
	m.SetReply(req)

	switch IPQuery {
	case QueryTypeIPv4:
		rr_header := mdns.RR_Header{
			Name:   q.Name,
			Rrtype: mdns.TypeA,
			Class:  mdns.ClassINET,
			Ttl:    s.ttl,
		}

		ips, err := s.handler(Q.qname, QueryTypeIPv4)
		if err != nil {
			logger.Error("lookup %s error %s", Q.qname, err)
		}

		for _, ip := range ips {
			a := &mdns.A{
				Hdr: rr_header,
				A:   net.ParseIP(ip).To4(),
			}
			m.Answer = append(m.Answer, a)
		}
	case QueryTypeIPv6:
		rr_header := mdns.RR_Header{
			Name:   q.Name,
			Rrtype: mdns.TypeAAAA,
			Class:  mdns.ClassINET,
			Ttl:    s.ttl,
		}

		ips, err := s.handler(Q.qname, QueryTypeIPv6)
		if err != nil {
			logger.Error("lookup %s error %s", Q.qname, err)
		}

		for _, ip := range ips {
			aaaa := &mdns.AAAA{
				Hdr:  rr_header,
				AAAA: net.ParseIP(ip).To16(),
			}
			m.Answer = append(m.Answer, aaaa)
		}
	}

	w.WriteMsg(m)
}

func (s *Server) start(typ string, server *dns.Server) {
	logger.Info("Start %s listener on %s/%s", server.Net, s.Addr(), typ)
	err := server.ListenAndServe()
	if err != nil {
		logger.Error("Start %s listener on %s/%s failed:%s", server.Net, s.Addr(), typ, err.Error())
	}
}

// Serve starts the dns server
func (s *Server) Serve() {

	udpHandler := mdns.NewServeMux()
	udpHandler.HandleFunc(".", s.doUDP)

	tcpHandler := mdns.NewServeMux()
	tcpHandler.HandleFunc(".", s.doTCP)

	udpServer := &mdns.Server{
		Addr:    s.Addr(),
		Net:     "udp",
		Handler: udpHandler,
		UDPSize: 65535,
	}

	tcpServer := &dns.Server{Addr: s.Addr(),
		Net:     "tcp",
		Handler: tcpHandler,
	}

	go s.start("udp", udpServer)
	go s.start("tcp", tcpServer)

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt)

forever:
	for {
		select {
		case <-sig:
			logger.Info("signal received, stopping")
			break forever
		}
	}

}

//
func UnFqdn(s string) string {
	if mdns.IsFqdn(s) {
		return s[:len(s)-1]
	}
	return s
}

type Question struct {
	qname  string
	qtype  string
	qclass string
}

func (q *Question) String() string {
	return q.qname + " " + q.qclass + " " + q.qtype
}

func isIPQuery(q mdns.Question) int {
	if q.Qclass != mdns.ClassINET {
		return QueryTypeUnknown
	}

	switch q.Qtype {
	case mdns.TypeA:
		return QueryTypeIPv4
	case mdns.TypeAAAA:
		return QueryTypeIPv6
	default:
		return QueryTypeUnknown
	}
}
