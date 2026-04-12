package models

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// DNSRequest carries a DNS message plus client context for smart resolution.
type DNSRequest struct {
	Msg *dns.Msg
	// ClientVIP is the VPN virtual IP (e.g. UDP source or header-derived).
	ClientVIP string
	// ClientECS is optional EDNS0 client subnet string "ip/mask" (IPv4 or IPv6).
	ClientECS string
	// Transport is optional for query logs: "udp" | "tcp" | "doh" | "doh-json".
	Transport string
	// DoHFullURL is the full client request URL when Transport is doh or doh-json.
	DoHFullURL string
	// DoHPostWire is a copy of RFC 8484 POST body (application/dns-message) when Transport == "doh".
	DoHPostWire []byte
}

// ResolveLog records routing context for admin query logs (not stored in Redis cache payload).
type ResolveLog struct {
	RealIP       string
	ClientSubnet string
	CNOnly       bool
	WentOUT      bool
	BlockedWL    bool
	Cached       bool
	Trace        *ResolveTrace
}

// DNSResponse wraps a DNS reply with metadata for caching.
type DNSResponse struct {
	Msg *dns.Msg
	// MinTTL is the minimum TTL among answer RRs (for cache expiry cap).
	MinTTL uint32
	Log    ResolveLog
	// UpstreamEndpoint is set only on fresh pool responses (not from Redis/L1 cache):
	// e.g. "DoH https://dns.google/dns-query" or "UDP 223.5.5.5:53".
	UpstreamEndpoint string
	// UpstreamRequestURL is the exact HTTPS URL used for Google JSON GET (/resolve?name=&type=&edns_client_subnet=), when applicable.
	UpstreamRequestURL string `json:"upstream_request_url,omitempty"`
	// GoogleEchoedECS is the edns_client_subnet field from Google JSON /resolve when present and applicable.
	GoogleEchoedECS string `json:"-"`
	// SkipQueryLog when true: transport must not emit admin/query logs or stats rows for this answer.
	SkipQueryLog bool `json:"-"`
}

// QuestionName returns the first question FQDN in lowercase.
func (r *DNSRequest) QuestionName() string {
	if r == nil || r.Msg == nil || len(r.Msg.Question) == 0 {
		return ""
	}
	return dns.Fqdn(r.Msg.Question[0].Name)
}

// QuestionType returns the first question QTYPE.
func (r *DNSRequest) QuestionType() uint16 {
	if r == nil || r.Msg == nil || len(r.Msg.Question) == 0 {
		return 0
	}
	return r.Msg.Question[0].Qtype
}

// ExtractIPs collects A/AAAA addresses from answer and extra sections.
func ExtractIPs(msg *dns.Msg) []net.IP {
	if msg == nil {
		return nil
	}
	var out []net.IP
	add := func(rrs []dns.RR) {
		for _, rr := range rrs {
			switch v := rr.(type) {
			case *dns.A:
				out = append(out, v.A)
			case *dns.AAAA:
				out = append(out, v.AAAA)
			}
		}
	}
	add(msg.Answer)
	add(msg.Extra)
	return out
}

// MinAnswerTTL returns minimum TTL in the answer section, or defaultTTL if none.
func MinAnswerTTL(msg *dns.Msg, defaultTTL uint32) uint32 {
	if msg == nil || len(msg.Answer) == 0 {
		return defaultTTL
	}
	var min uint32 = ^uint32(0)
	for _, rr := range msg.Answer {
		h := rr.Header()
		if h.Rrtype == dns.TypeOPT {
			continue
		}
		if h.Ttl < min {
			min = h.Ttl
		}
	}
	if min == ^uint32(0) {
		return defaultTTL
	}
	return min
}

// AnswerSummary returns a short human-readable summary of the DNS answer section (for UI / logs).
func AnswerSummary(m *dns.Msg) string {
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

// IsReverseLookupQName reports whether fqdn is under IPv4 or IPv6 reverse DNS trees.
func IsReverseLookupQName(fqdn string) bool {
	s := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	return strings.HasSuffix(s, ".in-addr.arpa") || strings.HasSuffix(s, ".ip6.arpa")
}

// NewIPv6DisabledAAAAResponse returns NOERROR empty (NODATA) for AAAA when disable_ipv6 is enabled.
// SkipQueryLog avoids admin query logs and stats rows; transport layers may short-circuit before Resolve.
func NewIPv6DisabledAAAAResponse(req *DNSRequest) *DNSResponse {
	m := new(dns.Msg)
	m.SetReply(req.Msg)
	m.Rcode = dns.RcodeSuccess
	m.Authoritative = false
	m.Answer = nil
	return &DNSResponse{
		Msg:          m,
		MinTTL:       60,
		SkipQueryLog: true,
		Log:          ResolveLog{},
	}
}

// NewReverseLookupSkippedResponse returns REFUSED without caching or logging (see Resolver / DNS frontends).
func NewReverseLookupSkippedResponse(req *DNSRequest) *DNSResponse {
	m := new(dns.Msg)
	m.SetReply(req.Msg)
	m.Rcode = dns.RcodeRefused
	m.Authoritative = false
	m.RecursionAvailable = true
	return &DNSResponse{
		Msg:          m,
		MinTTL:       0,
		SkipQueryLog: true,
		Log:          ResolveLog{},
	}
}
