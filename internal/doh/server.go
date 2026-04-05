package doh

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/vpndns/cdn/internal/config"
	vpndnsdns "github.com/vpndns/cdn/internal/dns"
	"github.com/vpndns/cdn/internal/models"
	"github.com/vpndns/cdn/internal/querylog"
	"github.com/vpndns/cdn/internal/ratelimit"
	"github.com/vpndns/cdn/internal/resolver"
	"github.com/vpndns/cdn/internal/stats"
)

// Server implements RFC 8484 DNS-over-HTTPS (POST /dns-query) and Google-style JSON (GET /resolve).
type Server struct {
	cfg     *config.Store
	res     *resolver.Resolver
	rl      *ratelimit.PerIP
	logSink func(resolver.LogRecord)
	st      *stats.Collector
}

func New(cfg *config.Store, res *resolver.Resolver, rl *ratelimit.PerIP, logSink func(resolver.LogRecord), st *stats.Collector) *Server {
	return &Server{cfg: cfg, res: res, rl: rl, logSink: logSink, st: st}
}

func clientVIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.cfg.Get()
		if cfg.Security.DoHAuth.Enabled {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if tok != cfg.Security.DoHAuth.Token {
				if s.st != nil {
					s.st.RecordDoHUnauthorized()
				}
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		vip := clientVIPFromRequest(r)
		if s.rl != nil && !s.rl.Allow(vip) {
			if s.st != nil {
				s.st.RecordRateLimited()
			}
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}

		var wire []byte
		var err error
		switch r.Method {
		case http.MethodPost:
			wire, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		case http.MethodGet:
			// optional: dns parameter base64url
			http.Error(w, "use POST application/dns-message", http.StatusNotImplemented)
			return
		}
		if err != nil || len(wire) == 0 {
			if s.st != nil {
				s.st.RecordMalformed()
			}
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(wire); err != nil {
			if s.st != nil {
				s.st.RecordMalformed()
			}
			http.Error(w, "bad dns", http.StatusBadRequest)
			return
		}
		if len(msg.Question) == 0 {
			if s.st != nil {
				s.st.RecordMalformed()
			}
			http.Error(w, "no question", http.StatusBadRequest)
			return
		}
		if s.st != nil {
			s.st.RecordDNSQuery()
		}

		wireName := msg.Question[0].Name
		qt := msg.Question[0].Qtype
		if vpndnsdns.MatchedInDomainList(wireName, cfg.Security.Blacklist) {
			realIP := net.ParseIP(vip)
			resp := resolver.PolicyBlockResponse(msg, cfg.Resolver.NonWhitelistAction, realIP, "")
			packBl, perr := resp.Msg.Pack()
			if perr != nil {
				http.Error(w, "pack error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/dns-message")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(packBl)
			s.emit(querylog.FromFailure(wireName, vip, qt, 0, int(resp.Msg.Rcode), querylog.AnswerSummary(resp.Msg), "黑名单"))
			return
		}

		start := time.Now()
		req := &models.DNSRequest{Msg: msg, ClientVIP: vip}
		qms := cfg.Resolver.QueryTimeoutMS
		if qms <= 0 {
			qms = 3000
		}
		resolveCtx, cancelResolve := context.WithTimeout(r.Context(), time.Duration(qms)*time.Millisecond)
		defer cancelResolve()
		resp, err := s.res.Resolve(resolveCtx, req)
		lat := time.Since(start).Milliseconds()
		if err != nil {
			if errors.Is(err, resolver.ErrOverload) {
				if s.st != nil {
					s.st.RecordOverload()
				}
				http.Error(w, "overload", http.StatusServiceUnavailable)
				rc := dns.RcodeServerFailure
				s.emit(querylog.FromFailure(wireName, vip, qt, lat, rc, "OVERLOAD", "过载"))
				return
			}
			log.Printf("doh resolve: %v", err)
			http.Error(w, "resolve error", http.StatusBadGateway)
			s.emit(querylog.FromFailure(wireName, vip, qt, lat, dns.RcodeServerFailure, "SERVFAIL", "错误"))
			return
		}
		if resp == nil || resp.Msg == nil {
			http.Error(w, "empty", http.StatusBadGateway)
			s.emit(querylog.FromFailure(wireName, vip, qt, lat, dns.RcodeServerFailure, "SERVFAIL", "错误"))
			return
		}
		pack, err := resp.Msg.Pack()
		if err != nil {
			http.Error(w, "pack error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pack)
		s.emit(querylog.FromResolve(wireName, vip, qt, resp, lat))
	})
}

func (s *Server) emit(r resolver.LogRecord) {
	if s.logSink != nil {
		s.logSink(r)
	}
}
