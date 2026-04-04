package api

import (
	"strconv"
	"strings"

	"github.com/vpndns/cdn/internal/resolver"
)

func logFilterActive(domainQ, vipQ, realQ, freeQ string) bool {
	return strings.TrimSpace(domainQ) != "" || strings.TrimSpace(vipQ) != "" ||
		strings.TrimSpace(realQ) != "" || strings.TrimSpace(freeQ) != ""
}

// logMatchesQuery returns true if rec passes all non-empty filters (AND).
// domain / vip / real_ip: case-insensitive substring match on the corresponding field.
// q: case-insensitive substring in any of domain, vip, real_ip, client_subnet, qtype, answer_summary, route, latency, rcode.
func logMatchesQuery(rec *resolver.LogRecord, domainQ, vipQ, realQ, freeQ string) bool {
	if s := strings.TrimSpace(domainQ); s != "" {
		if !strings.Contains(strings.ToLower(rec.Domain), strings.ToLower(s)) {
			return false
		}
	}
	if s := strings.TrimSpace(vipQ); s != "" {
		if !strings.Contains(strings.ToLower(rec.VIP), strings.ToLower(s)) {
			return false
		}
	}
	if s := strings.TrimSpace(realQ); s != "" {
		if !strings.Contains(strings.ToLower(rec.RealIP), strings.ToLower(s)) {
			return false
		}
	}
	if s := strings.TrimSpace(freeQ); s != "" {
		f := strings.ToLower(s)
		hay := strings.ToLower(strings.Join([]string{
			rec.Domain,
			rec.VIP,
			rec.RealIP,
			rec.ClientSubnet,
			rec.QType,
			rec.AnswerSummary,
			rec.Route,
			strconv.FormatInt(rec.LatencyMS, 10),
			strconv.Itoa(rec.Rcode),
		}, "\n"))
		if !strings.Contains(hay, f) {
			return false
		}
	}
	return true
}
