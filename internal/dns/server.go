package dns

import (
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/vpndns/cdn/internal/config"
	"github.com/vpndns/cdn/internal/models"
	"github.com/vpndns/cdn/internal/querylog"
	"github.com/vpndns/cdn/internal/ratelimit"
	"github.com/vpndns/cdn/internal/resolver"
	"github.com/vpndns/cdn/internal/stats"
)

// Server serves UDP/TCP DNS.
type Server struct {
	cfg       *config.Store
	res       *resolver.Resolver
	rl        *ratelimit.PerIP
	logSink   func(resolver.LogRecord)
	st        *stats.Collector
	mu        sync.RWMutex
	blacklist []string
}

func New(cfg *config.Store, res *resolver.Resolver, rl *ratelimit.PerIP, logSink func(resolver.LogRecord), st *stats.Collector) *Server {
	return &Server{cfg: cfg, res: res, rl: rl, logSink: logSink, st: st}
}

func (s *Server) ReloadSecurity(blacklist []string) {
	s.mu.Lock()
	s.blacklist = append([]string(nil), blacklist...)
	s.mu.Unlock()
}

func (s *Server) ServeUDP(ctx context.Context, addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	tuneUDPConnBuffers(conn)
	u := &dns.Server{
		PacketConn:  conn,
		Handler:     dns.HandlerFunc(s.handle),
		UDPSize:     dns.MaxMsgSize,
		ReadTimeout: 6 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = u.Shutdown()
	}()
	return u.ActivateAndServe()
}

func (s *Server) ServeTCP(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	max := int64(0)
	if c := s.cfg.Get(); c != nil {
		max = int64(c.Listen.MaxTCPDNSConnections)
	}
	ln = newSemListener(ln, max)
	t := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(s.handle)}
	go func() {
		<-ctx.Done()
		_ = t.Shutdown()
	}()
	return t.ActivateAndServe()
}

func (s *Server) resolveCtx() (context.Context, context.CancelFunc) {
	cfg := s.cfg.Get()
	ms := 3000
	if cfg != nil && cfg.Resolver.QueryTimeoutMS > 0 {
		ms = cfg.Resolver.QueryTimeoutMS
	}
	d := time.Duration(ms)*time.Millisecond + 300*time.Millisecond
	if d < time.Second {
		d = time.Second
	}
	return context.WithTimeout(context.Background(), d)
}

func (s *Server) handle(w dns.ResponseWriter, r *dns.Msg) {
	clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	if s.rl != nil && !s.rl.Allow(clientIP) {
		if s.st != nil {
			s.st.RecordRateLimited()
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	if len(r.Question) == 0 {
		if s.st != nil {
			s.st.RecordMalformed()
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(m)
		return
	}
	name := strings.ToLower(r.Question[0].Name)
	if models.IsReverseLookupQName(name) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		m.Authoritative = false
		m.RecursionAvailable = true
		_ = w.WriteMsg(m)
		return
	}
	qt := r.Question[0].Qtype
	cfg := s.cfg.Get()
	if cfg != nil && cfg.Resolver.DisableIPv6 && qt == dns.TypeAAAA {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeSuccess
		m.Authoritative = false
		m.Answer = nil
		_ = w.WriteMsg(m)
		return
	}
	if s.st != nil {
		s.st.RecordDNSQuery()
	}
	nw := w.RemoteAddr().Network()
	transport := "udp"
	if strings.HasPrefix(nw, "tcp") {
		transport = "tcp"
	}
	req := &models.DNSRequest{
		Msg:       r,
		ClientVIP: clientIP,
		Transport: transport,
	}
	if s.blocked(name) {
		action := "nxdomain"
		if cfg != nil {
			action = cfg.Resolver.NonWhitelistAction
		}
		realIP := net.ParseIP(clientIP)
		resp := resolver.PolicyBlockResponse(r, action, realIP, "")
		_ = w.WriteMsg(resp.Msg)
		s.emitLog(querylog.FromFailure(name, clientIP, qt, 0, int(resp.Msg.Rcode), querylog.AnswerSummary(resp.Msg), "黑名单", resolver.TransportTracePreflight(req)))
		return
	}

	start := time.Now()
	rctx, cancel := s.resolveCtx()
	defer cancel()
	resp, err := s.res.Resolve(rctx, req)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		if errors.Is(err, resolver.ErrOverload) {
			if s.st != nil {
				s.st.RecordOverload()
			}
			m := new(dns.Msg)
			m.SetReply(r)
			rc := dns.RcodeServerFailure
			cfg := s.cfg.Get()
			if cfg != nil && strings.ToLower(strings.TrimSpace(cfg.Resolver.OverloadDNSResponse)) == "refused" {
				m.Rcode = dns.RcodeRefused
				rc = dns.RcodeRefused
			} else {
				m.Rcode = dns.RcodeServerFailure
			}
			_ = w.WriteMsg(m)
			s.emitLog(querylog.FromFailure(name, clientIP, qt, lat, rc, "OVERLOAD", "过载", resolver.FailureTraceForLog(req, err)))
			return
		}
		log.Printf("resolve: q=%s err=%v", name, err)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
		s.emitLog(querylog.FromFailure(name, clientIP, qt, lat, dns.RcodeServerFailure, "SERVFAIL", "错误", resolver.FailureTraceForLog(req, err)))
		return
	}
	if resp == nil || resp.Msg == nil {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
		s.emitLog(querylog.FromFailure(name, clientIP, qt, lat, dns.RcodeServerFailure, "SERVFAIL", "错误", resolver.FailureTraceForLog(req, nil)))
		return
	}
	resp.Msg.SetReply(r)
	_ = w.WriteMsg(resp.Msg)
	if !resp.SkipQueryLog {
		rec := querylog.FromResolve(name, clientIP, qt, resp, lat)
		s.emitLog(rec)
	}
}

func (s *Server) blocked(name string) bool {
	s.mu.RLock()
	list := s.blacklist
	s.mu.RUnlock()
	return MatchedInDomainList(name, list)
}

func (s *Server) emitLog(r resolver.LogRecord) {
	if s.logSink != nil {
		s.logSink(r)
	}
}
