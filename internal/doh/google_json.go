package doh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	vpndnsdns "github.com/vpndns/cdn/internal/dns"
	"github.com/vpndns/cdn/internal/models"
	"github.com/vpndns/cdn/internal/querylog"
	"github.com/vpndns/cdn/internal/resolver"
)

// Google JSON DoH: GET /resolve?name=&type= — compatible with
// https://developers.google.com/speed/public-dns/docs/doh/json

type googleDNSJSON struct {
	Status   int             `json:"Status"`
	TC       bool            `json:"TC"`
	RD       bool            `json:"RD"`
	RA       bool            `json:"RA"`
	AD       bool            `json:"AD"`
	CD       bool            `json:"CD"`
	Question []gjsonQuestion `json:"Question,omitempty"`
	Answer   []gjsonAnswer   `json:"Answer,omitempty"`
}

type gjsonQuestion struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

type gjsonAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

func dnsMsgToGoogleJSON(msg *dns.Msg) googleDNSJSON {
	if msg == nil {
		return googleDNSJSON{Status: int(dns.RcodeServerFailure)}
	}
	out := googleDNSJSON{
		Status: int(msg.Rcode),
		TC:     msg.Truncated,
		RD:     msg.RecursionDesired,
		RA:     msg.RecursionAvailable,
		AD:     msg.AuthenticatedData,
		CD:     msg.CheckingDisabled,
	}
	for _, q := range msg.Question {
		out.Question = append(out.Question, gjsonQuestion{
			Name: q.Name,
			Type: int(q.Qtype),
		})
	}
	for _, rr := range msg.Answer {
		h := rr.Header()
		out.Answer = append(out.Answer, gjsonAnswer{
			Name: h.Name,
			Type: int(h.Rrtype),
			TTL:  h.Ttl,
			Data: rrToGoogleData(rr),
		})
	}
	return out
}

func rrToGoogleData(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return dns.Fqdn(v.Target)
	case *dns.PTR:
		return v.Ptr
	case *dns.TXT:
		return strings.Join(v.Txt, " ")
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, v.Mx)
	case *dns.NS:
		return dns.Fqdn(v.Ns)
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d", v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	default:
		s := rr.String()
		if i := strings.Index(s, "\t"); i >= 0 {
			parts := strings.Split(s, "\t")
			if len(parts) >= 5 {
				return strings.Join(parts[4:], "\t")
			}
		}
		return s
	}
}

// ResolveJSONHandler serves Google-style GET /resolve (application/dns-json).
func (s *Server) ResolveJSONHandler() http.Handler {
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
		if r.Method != http.MethodGet {
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

		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			if s.st != nil {
				s.st.RecordMalformed()
			}
			http.Error(w, "missing name", http.StatusBadRequest)
			return
		}
		qtype := uint16(dns.TypeA)
		if ts := strings.TrimSpace(r.URL.Query().Get("type")); ts != "" {
			if n, err := strconv.Atoi(ts); err == nil && n > 0 && n <= 0xffff {
				qtype = uint16(n)
			}
		}

		qname := dns.Fqdn(name)
		msg := new(dns.Msg)
		msg.SetQuestion(qname, qtype)
		msg.RecursionDesired = true

		if len(msg.Question) == 0 {
			if s.st != nil {
				s.st.RecordMalformed()
			}
			http.Error(w, "no question", http.StatusBadRequest)
			return
		}
		wireName := msg.Question[0].Name
		if models.IsReverseLookupQName(wireName) {
			skip := new(dns.Msg)
			skip.SetQuestion(wireName, qtype)
			skip.Rcode = dns.RcodeRefused
			skip.RecursionDesired = true
			skip.RecursionAvailable = true
			w.Header().Set("Content-Type", "application/dns-json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(dnsMsgToGoogleJSON(skip))
			return
		}
		if cfg != nil && cfg.Resolver.DisableIPv6 && qtype == dns.TypeAAAA {
			skip := new(dns.Msg)
			skip.SetQuestion(wireName, qtype)
			skip.Rcode = dns.RcodeSuccess
			skip.RecursionDesired = true
			skip.RecursionAvailable = true
			w.Header().Set("Content-Type", "application/dns-json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(dnsMsgToGoogleJSON(skip))
			return
		}
		if s.st != nil {
			s.st.RecordDNSQuery()
		}

		qt := msg.Question[0].Qtype
		dnsReq := &models.DNSRequest{
			Msg:        msg,
			ClientVIP:  vip,
			Transport:  "doh-json",
			DoHFullURL: HTTPRequestFullURL(r),
		}
		if vpndnsdns.MatchedInDomainList(wireName, cfg.Security.Blacklist) {
			realIP := net.ParseIP(vip)
			resp := resolver.PolicyBlockResponse(msg, cfg.Resolver.NonWhitelistAction, realIP, "")
			w.Header().Set("Content-Type", "application/dns-json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(dnsMsgToGoogleJSON(resp.Msg))
			s.emit(querylog.FromFailure(wireName, vip, qt, 0, int(resp.Msg.Rcode), querylog.AnswerSummary(resp.Msg), "黑名单", resolver.TransportTracePreflight(dnsReq)))
			return
		}

		start := time.Now()
		req := dnsReq
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
				s.emit(querylog.FromFailure(wireName, vip, qt, lat, dns.RcodeServerFailure, "OVERLOAD", "过载", resolver.FailureTraceForLog(req, err)))
				return
			}
			log.Printf("doh json resolve: %v", err)
			http.Error(w, "resolve error", http.StatusBadGateway)
			s.emit(querylog.FromFailure(wireName, vip, qt, lat, dns.RcodeServerFailure, "SERVFAIL", "错误", resolver.FailureTraceForLog(req, err)))
			return
		}
		if resp == nil || resp.Msg == nil {
			http.Error(w, "empty", http.StatusBadGateway)
			s.emit(querylog.FromFailure(wireName, vip, qt, lat, dns.RcodeServerFailure, "SERVFAIL", "错误", resolver.FailureTraceForLog(req, nil)))
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(dnsMsgToGoogleJSON(resp.Msg))
		if !resp.SkipQueryLog {
			s.emit(querylog.FromResolve(wireName, vip, qt, resp, lat))
		}
	})
}
