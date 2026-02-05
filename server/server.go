package server

import (
	"crypto/tls"
	"net"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/go-zoox/dns/constants"
	"github.com/go-zoox/logger"
	mdns "github.com/miekg/dns"
)

// Server is a dns server
type Server struct {
	port      int
	host      string
	ttl       uint32
	handler   func(host string, typ int) ([]string, error)
	dotPort   int
	enableDoT bool
	tlsConfig *tls.Config
}

// Options is the options for the server
type Options struct {
	Port        int
	Host        string
	TTL         uint32
	DoTPort     int
	EnableDoT   bool
	TLSCertFile string
	TLSKeyFile  string
	TLSConfig   *tls.Config
}

// New creates a new dns server
func New(options ...*Options) *Server {
	port := 8853 // 53
	host := "0.0.0.0"
	ttl := uint32(500) // 500 ms
	dotPort := 853
	enableDoT := false
	var tlsConfig *tls.Config

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
		if options[0].DoTPort != 0 {
			dotPort = options[0].DoTPort
		} else if options[0].EnableDoT {
			// Default to 853 if DoT is enabled but port not specified
			dotPort = 853
		}
		enableDoT = options[0].EnableDoT

		// Load TLS config if DoT is enabled
		if enableDoT {
			tlsConfig = loadTLSConfig(options[0])
		}
	}

	return &Server{
		port:      port,
		host:      host,
		ttl:       ttl,
		dotPort:   dotPort,
		enableDoT: enableDoT,
		tlsConfig: tlsConfig,
	}
}

// loadTLSConfig loads TLS configuration from options
func loadTLSConfig(opts *Options) *tls.Config {
	// If TLSConfig is provided directly, use it
	if opts.TLSConfig != nil {
		return opts.TLSConfig
	}

	// If certificate files are provided, load them
	if opts.TLSCertFile != "" && opts.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.TLSCertFile, opts.TLSKeyFile)
		if err != nil {
			logger.Error("Failed to load TLS certificate: %s", err.Error())
			return nil
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}

	// No TLS configuration provided
	logger.Warn("DoT is enabled but no TLS configuration provided")
	return nil
}

// Addr returns the address of the server
func (s *Server) Addr() string {
	return net.JoinHostPort(s.host, strconv.Itoa(s.port))
}

// DoTAddr returns the address of the DoT server
func (s *Server) DoTAddr() string {
	return net.JoinHostPort(s.host, strconv.Itoa(s.dotPort))
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

func (s *Server) doTLS(w mdns.ResponseWriter, req *mdns.Msg) {
	s.do("tcp-tls", w, req)
}

func (s *Server) do(typ string, w mdns.ResponseWriter, req *mdns.Msg) {
	q := req.Question[0]
	Q := Question{UnFqdn(q.Name), mdns.TypeToString[q.Qtype], mdns.ClassToString[q.Qclass]}

	var remote net.IP
	if typ == "tcp" || typ == "tcp-tls" {
		remote = w.RemoteAddr().(*net.TCPAddr).IP
	} else {
		remote = w.RemoteAddr().(*net.UDPAddr).IP
	}

	IPQuery := isIPQuery(q)

	m := new(mdns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true

	lookupTime := createTimeUse()

	switch IPQuery {
	case constants.QueryTypeIPv4:
		rrHeader := mdns.RR_Header{
			Name:   q.Name,
			Rrtype: mdns.TypeA,
			Class:  mdns.ClassINET,
			Ttl:    s.ttl,
		}

		if ips, err := s.handler(Q.qname, constants.QueryTypeIPv4); err != nil {
			logger.Error("[%s] lookup %s error(%s) +%dms", remote, Q.qname, err, lookupTime())
		} else {
			logger.Info("[%s] lookup %s +%dms", remote, Q.String(), lookupTime())
			for _, ip := range ips {
				a := &mdns.A{
					Hdr: rrHeader,
					A:   net.ParseIP(ip).To4(),
				}
				m.Answer = append(m.Answer, a)
			}
		}
	case constants.QueryTypeIPv6:
		rrHeader := mdns.RR_Header{
			Name:   q.Name,
			Rrtype: mdns.TypeAAAA,
			Class:  mdns.ClassINET,
			Ttl:    s.ttl,
		}

		if ips, err := s.handler(Q.qname, constants.QueryTypeIPv6); err != nil {
			logger.Error("[%s] lookup %s error(%s) +%dms", remote, Q.qname, err, lookupTime())
		} else {
			logger.Info("[%s] lookup %s +%dms", remote, Q.String(), lookupTime())
			for _, ip := range ips {
				aaaa := &mdns.AAAA{
					Hdr:  rrHeader,
					AAAA: net.ParseIP(ip).To16(),
				}
				m.Answer = append(m.Answer, aaaa)
			}
		}
	}

	w.WriteMsg(m)
}

func (s *Server) start(typ string, server *mdns.Server) error {
	var addr string
	if typ == "dot" {
		addr = s.DoTAddr()
	} else {
		addr = s.Addr()
	}
	logger.Info("Start %s listener on %s/%s", server.Net, addr, typ)
	err := server.ListenAndServe()
	if err != nil {
		// logger.Error("Start %s listener on %s/%s failed:%s", server.Net, addr, typ, err.Error())
		return err
	}

	return nil
}

func (s *Server) startDoT() error {
	if !s.enableDoT {
		return nil
	}

	if s.tlsConfig == nil {
		logger.Error("DoT is enabled but TLS configuration is missing")
		return nil
	}

	tlsHandler := mdns.NewServeMux()
	tlsHandler.HandleFunc(".", s.doTLS)

	dotServer := &mdns.Server{
		Addr:      s.DoTAddr(),
		Net:       "tcp-tls",
		Handler:   tlsHandler,
		TLSConfig: s.tlsConfig,
	}

	return s.start("dot", dotServer)
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

	tcpServer := &mdns.Server{Addr: s.Addr(),
		Net:     "tcp",
		Handler: tcpHandler,
	}

	// @TODO
	cancel := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func(cancel chan struct{}, s *Server) {
		if err := s.start("udp", udpServer); err != nil {
			logger.Error("Start udp listener on %s failed:%s", s.Addr(), err.Error())
			cancel <- struct{}{}
		}
	}(cancel, s)
	go func(cancel chan struct{}, s *Server) {
		if err := s.start("tcp", tcpServer); err != nil {
			logger.Error("Start tcp listener on %s failed:%s", s.Addr(), err.Error())
			cancel <- struct{}{}
		}
	}(cancel, s)

	// Start DoT server if enabled
	if s.enableDoT && s.tlsConfig != nil {
		go func(cancel chan struct{}, s *Server) {
			if err := s.startDoT(); err != nil {
				logger.Error("Start DoT listener on %s failed:%s", s.DoTAddr(), err.Error())
				cancel <- struct{}{}
			}
		}(cancel, s)
	}

	for {
		select {
		case <-sig:
			logger.Info("signal received, stopping")
			return
		case <-cancel:
			return
		}
	}
}

// UnFqdn converts a fqdn to a non-fqdn
func UnFqdn(s string) string {
	if mdns.IsFqdn(s) {
		return s[:len(s)-1]
	}
	return s
}

// Question represents a question
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
		return constants.QueryTypeUnknown
	}

	switch q.Qtype {
	case mdns.TypeA:
		return constants.QueryTypeIPv4
	case mdns.TypeAAAA:
		return constants.QueryTypeIPv6
	default:
		return constants.QueryTypeUnknown
	}
}

func createTimeUse() func() int64 {
	startAt := time.Now()
	return func() int64 {
		return int64(time.Since(startAt) / time.Millisecond)
	}
}
