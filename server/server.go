package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/go-zoox/dns/constants"
	"github.com/go-zoox/logger"
	mdns "github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// Server is a dns server
type Server struct {
	port         int
	host         string
	ttl          uint32
	handler      func(host string, typ int) ([]string, error)
	dotPort      int
	enableDoT    bool
	tlsConfig    *tls.Config
	dohPort      int
	enableDoH    bool
	doqPort      int
	enableDoQ    bool
	httpServer   *http.Server
	quicListener *quic.Listener
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
	DoHPort     int
	EnableDoH   bool
	DoQPort     int
	EnableDoQ   bool
}

// New creates a new dns server
func New(options ...*Options) *Server {
	port := 8853 // 53
	host := "0.0.0.0"
	ttl := uint32(500) // 500 ms
	dotPort := 853
	enableDoT := false
	dohPort := 443
	enableDoH := false
	doqPort := 853
	enableDoQ := false
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

		if options[0].DoHPort != 0 {
			dohPort = options[0].DoHPort
		} else if options[0].EnableDoH {
			// Default to 443 if DoH is enabled but port not specified
			dohPort = 443
		}
		enableDoH = options[0].EnableDoH

		if options[0].DoQPort != 0 {
			doqPort = options[0].DoQPort
		} else if options[0].EnableDoQ {
			// Default to 853 if DoQ is enabled but port not specified
			doqPort = 853
		}
		enableDoQ = options[0].EnableDoQ

		// Load TLS config if DoT, DoH, or DoQ is enabled
		if enableDoT || enableDoH || enableDoQ {
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
		dohPort:   dohPort,
		enableDoH: enableDoH,
		doqPort:   doqPort,
		enableDoQ: enableDoQ,
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

// DoHAddr returns the address of the DoH server
func (s *Server) DoHAddr() string {
	return net.JoinHostPort(s.host, strconv.Itoa(s.dohPort))
}

// DoQAddr returns the address of the DoQ server
func (s *Server) DoQAddr() string {
	return net.JoinHostPort(s.host, strconv.Itoa(s.doqPort))
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

// doH handles DNS over HTTPS requests
func (s *Server) doH(w http.ResponseWriter, r *http.Request) {
	var msg *mdns.Msg
	var err error

	// Support both GET and POST methods
	switch r.Method {
	case http.MethodGet:
		// GET: dns query in base64url format
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}

		// Decode base64url
		data, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "invalid dns parameter", http.StatusBadRequest)
			return
		}

		msg = new(mdns.Msg)
		if err = msg.Unpack(data); err != nil {
			http.Error(w, "invalid dns message", http.StatusBadRequest)
			return
		}

	case http.MethodPost:
		// POST: binary DNS message in body
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "invalid content type", http.StatusBadRequest)
			return
		}

		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}

		msg = new(mdns.Msg)
		if err = msg.Unpack(data); err != nil {
			http.Error(w, "invalid dns message", http.StatusBadRequest)
			return
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Process DNS query
	if len(msg.Question) == 0 {
		http.Error(w, "no question in dns message", http.StatusBadRequest)
		return
	}

	q := msg.Question[0]
	Q := Question{UnFqdn(q.Name), mdns.TypeToString[q.Qtype], mdns.ClassToString[q.Qclass]}

	var remote net.IP
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		remote = net.ParseIP(host)
	} else {
		remote = net.ParseIP(r.RemoteAddr)
	}
	if remote == nil {
		remote = net.IPv4(0, 0, 0, 0)
	}

	IPQuery := isIPQuery(q)

	m := new(mdns.Msg)
	m.SetReply(msg)
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

	// Pack response
	data, err := m.Pack()
	if err != nil {
		http.Error(w, "failed to pack response", http.StatusInternalServerError)
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// startDoH starts the DNS over HTTPS server
func (s *Server) startDoH() error {
	if !s.enableDoH {
		return nil
	}

	if s.tlsConfig == nil {
		logger.Error("DoH is enabled but TLS configuration is missing")
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.doH)
	mux.HandleFunc("/query", s.doH) // Alternative path

	s.httpServer = &http.Server{
		Addr:      s.DoHAddr(),
		Handler:   mux,
		TLSConfig: s.tlsConfig,
	}

	logger.Info("Start DoH listener on %s", s.DoHAddr())
	err := s.httpServer.ListenAndServeTLS("", "")
	if err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}

// doQ handles DNS over QUIC requests
func (s *Server) doQ(stream *quic.Stream, conn *quic.Conn) error {
	defer stream.Close()

	// Read DNS message
	data := make([]byte, 65535)
	n, err := stream.Read(data)
	if err != nil && err != io.EOF {
		return err
	}

	msg := new(mdns.Msg)
	if err = msg.Unpack(data[:n]); err != nil {
		return err
	}

	// Process DNS query
	if len(msg.Question) == 0 {
		return nil
	}

	q := msg.Question[0]
	Q := Question{UnFqdn(q.Name), mdns.TypeToString[q.Qtype], mdns.ClassToString[q.Qclass]}

	remote := conn.RemoteAddr()
	var remoteIP net.IP
	if addr, ok := remote.(*net.UDPAddr); ok {
		remoteIP = addr.IP
	} else {
		remoteIP = net.IPv4(0, 0, 0, 0)
	}

	IPQuery := isIPQuery(q)

	m := new(mdns.Msg)
	m.SetReply(msg)
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
			logger.Error("[%s] lookup %s error(%s) +%dms", remoteIP, Q.qname, err, lookupTime())
		} else {
			logger.Info("[%s] lookup %s +%dms", remoteIP, Q.String(), lookupTime())
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
			logger.Error("[%s] lookup %s error(%s) +%dms", remoteIP, Q.qname, err, lookupTime())
		} else {
			logger.Info("[%s] lookup %s +%dms", remoteIP, Q.String(), lookupTime())
			for _, ip := range ips {
				aaaa := &mdns.AAAA{
					Hdr:  rrHeader,
					AAAA: net.ParseIP(ip).To16(),
				}
				m.Answer = append(m.Answer, aaaa)
			}
		}
	}

	// Pack and send response
	respData, err := m.Pack()
	if err != nil {
		return err
	}

	_, err = stream.Write(respData)
	return err
}

// startDoQ starts the DNS over QUIC server
func (s *Server) startDoQ() error {
	if !s.enableDoQ {
		return nil
	}

	if s.tlsConfig == nil {
		logger.Error("DoQ is enabled but TLS configuration is missing")
		return nil
	}

	addr, err := net.ResolveUDPAddr("udp", s.DoQAddr())
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	// Create a copy of TLS config with DoQ ALPN
	doqTLSConfig := s.tlsConfig.Clone()
	if len(doqTLSConfig.NextProtos) == 0 {
		doqTLSConfig.NextProtos = []string{"doq"}
	} else {
		// Add "doq" if not already present
		hasDoq := false
		for _, proto := range doqTLSConfig.NextProtos {
			if proto == "doq" {
				hasDoq = true
				break
			}
		}
		if !hasDoq {
			doqTLSConfig.NextProtos = append(doqTLSConfig.NextProtos, "doq")
		}
	}

	// Create QUIC listener
	listener, err := quic.Listen(conn, doqTLSConfig, &quic.Config{
		Allow0RTT: true,
	})
	if err != nil {
		return err
	}

	s.quicListener = listener

	logger.Info("Start DoQ listener on %s", s.DoQAddr())

	// Accept connections
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			if err.Error() == "server closed" {
				return nil
			}
			logger.Error("DoQ accept error: %s", err.Error())
			continue
		}

		// Handle each connection in a goroutine
		go func(c *quic.Conn) {
			for {
				stream, err := c.AcceptStream(context.Background())
				if err != nil {
					return
				}

				go func(st *quic.Stream, conn *quic.Conn) {
					if err := s.doQ(st, conn); err != nil {
						logger.Error("DoQ stream error: %s", err.Error())
					}
				}(stream, c)
			}
		}(conn)
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

	// Start DoH server if enabled
	if s.enableDoH && s.tlsConfig != nil {
		go func(cancel chan struct{}, s *Server) {
			if err := s.startDoH(); err != nil {
				logger.Error("Start DoH listener on %s failed:%s", s.DoHAddr(), err.Error())
				cancel <- struct{}{}
			}
		}(cancel, s)
	}

	// Start DoQ server if enabled
	if s.enableDoQ && s.tlsConfig != nil {
		go func(cancel chan struct{}, s *Server) {
			if err := s.startDoQ(); err != nil {
				logger.Error("Start DoQ listener on %s failed:%s", s.DoQAddr(), err.Error())
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
