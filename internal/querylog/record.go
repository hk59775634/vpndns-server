package querylog

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/vpndns/cdn/internal/models"
	"github.com/vpndns/cdn/internal/resolver"
)

func qTypeString(qt uint16) string {
	if s, ok := dns.TypeToString[qt]; ok && s != "" {
		return s
	}
	return fmt.Sprintf("TYPE%d", qt)
}

// AnswerSummary returns a short human-readable summary of the DNS answer section (for UI / cache listing).
func AnswerSummary(m *dns.Msg) string {
	return answerSummary(m)
}

func answerSummary(m *dns.Msg) string {
	if m == nil {
		return "—"
	}
	rc := m.Rcode
	rcStr, ok := dns.RcodeToString[rc]
	if !ok {
		rcStr = fmt.Sprintf("RCODE%d", rc)
	}
	if rc != dns.RcodeSuccess {
		return rcStr
	}
	var parts []string
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			parts = append(parts, v.A.String())
		case *dns.AAAA:
			parts = append(parts, v.AAAA.String())
		case *dns.CNAME:
			parts = append(parts, "→ "+strings.TrimSuffix(v.Target, "."))
		default:
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			parts = append(parts, strings.Fields(rr.String())[0])
		}
	}
	if len(parts) == 0 {
		return rcStr + "（无记录）"
	}
	s := strings.Join(parts, ", ")
	if len(s) > 220 {
		s = s[:217] + "…"
	}
	return s
}

func routeLabel(l models.ResolveLog) string {
	if l.BlockedWL {
		return "非白名单"
	}
	if l.Cached {
		return "缓存"
	}
	if l.WentOUT {
		return "海外"
	}
	if l.CNOnly {
		return "国内"
	}
	return "—"
}

func normDomain(fqdn string) string {
	return strings.TrimSuffix(strings.ToLower(fqdn), ".")
}

// FromResolve builds a log row after a successful resolution.
func FromResolve(wireName, vip string, qt uint16, resp *models.DNSResponse, lat int64) resolver.LogRecord {
	rec := resolver.LogRecord{
		Time:      time.Now(),
		Domain:    normDomain(wireName),
		QType:     qTypeString(qt),
		VIP:       vip,
		LatencyMS: lat,
	}
	if resp != nil && resp.Msg != nil {
		rec.Rcode = int(resp.Msg.Rcode)
		rec.AnswerSummary = answerSummary(resp.Msg)
		l := resp.Log
		rec.RealIP = l.RealIP
		rec.ClientSubnet = l.ClientSubnet
		rec.CNOnly = l.CNOnly
		rec.WentOUT = l.WentOUT
		rec.Cached = l.Cached
		rec.BlockedWL = l.BlockedWL
		rec.Route = routeLabel(l)
	}
	return rec
}

// FromFailure builds a log row when resolution fails before a normal response.
func FromFailure(wireName, vip string, qt uint16, lat int64, rcode int, answerSummary, route string) resolver.LogRecord {
	return resolver.LogRecord{
		Time:          time.Now(),
		Domain:        normDomain(wireName),
		QType:         qTypeString(qt),
		VIP:           vip,
		LatencyMS:     lat,
		Rcode:         rcode,
		AnswerSummary: answerSummary,
		Route:         route,
	}
}
