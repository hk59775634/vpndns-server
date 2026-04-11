package cache

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func qtypeStr(q uint16) string {
	if s, ok := dns.TypeToString[q]; ok && s != "" {
		return s
	}
	return fmt.Sprintf("TYPE%d", q)
}

// QTypeString returns the canonical short name for qtype (same as used in Redis keys and coalescing).
func QTypeString(q uint16) string {
	return qtypeStr(q)
}

// ECSKey builds dns:{domain}:{type}:ecs:{subnet}
func ECSKey(domain string, qtype uint16, ecsSubnet string) string {
	d := strings.TrimSuffix(strings.ToLower(domain), ".")
	return fmt.Sprintf("dns:%s:%s:ecs:%s", d, qtypeStr(qtype), ecsSubnet)
}

// GlobalKey builds dns:{domain}:{type}:global
func GlobalKey(domain string, qtype uint16) string {
	d := strings.TrimSuffix(strings.ToLower(domain), ".")
	return fmt.Sprintf("dns:%s:%s:global", d, qtypeStr(qtype))
}
