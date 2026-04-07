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
	return models.AnswerSummary(m)
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
		rec.AnswerSummary = models.AnswerSummary(resp.Msg)
		l := resp.Log
		rec.RealIP = l.RealIP
		rec.ClientSubnet = l.ClientSubnet
		rec.CNOnly = l.CNOnly
		rec.WentOUT = l.WentOUT
		rec.Cached = l.Cached
		rec.BlockedWL = l.BlockedWL
		rec.Route = routeLabel(l)
		rec.Trace = l.Trace
	}
	return rec
}

// FromFailure builds a log row when resolution fails before a normal response.
// trace is optional (e.g. DoH URL / POST from TransportTracePreflight).
func FromFailure(wireName, vip string, qt uint16, lat int64, rcode int, answerSummary, route string, trace *models.ResolveTrace) resolver.LogRecord {
	rec := resolver.LogRecord{
		Time:          time.Now(),
		Domain:        normDomain(wireName),
		QType:         qTypeString(qt),
		VIP:           vip,
		LatencyMS:     lat,
		Rcode:         rcode,
		AnswerSummary: answerSummary,
		Route:         route,
		Trace:         trace,
	}
	return rec
}
