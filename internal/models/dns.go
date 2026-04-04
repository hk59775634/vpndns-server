package models

import (
	"net"

	"github.com/miekg/dns"
)

// DNSRequest carries a DNS message plus client context for smart resolution.
type DNSRequest struct {
	Msg *dns.Msg
	// ClientVIP is the VPN virtual IP (e.g. UDP source or header-derived).
	ClientVIP string
	// ClientECS is optional EDNS0 client subnet string "ip/mask" (IPv4 or IPv6).
	ClientECS string
}

// ResolveLog records routing context for admin query logs (not stored in Redis cache payload).
type ResolveLog struct {
	RealIP       string
	ClientSubnet string
	CNOnly       bool
	WentOUT      bool
	BlockedWL    bool
	Cached       bool
}

// DNSResponse wraps a DNS reply with metadata for caching.
type DNSResponse struct {
	Msg *dns.Msg
	// MinTTL is the minimum TTL among answer RRs (for cache expiry cap).
	MinTTL uint32
	Log    ResolveLog
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
