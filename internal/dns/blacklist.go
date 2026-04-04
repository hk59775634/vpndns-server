package dns

import "strings"

// MatchedInDomainList reports whether fqdn matches any pattern (exact, suffix, or *.suffix).
func MatchedInDomainList(fqdn string, patterns []string) bool {
	n := strings.TrimSuffix(strings.ToLower(fqdn), ".")
	for _, b := range patterns {
		b = strings.TrimSpace(strings.ToLower(b))
		if b == "" {
			continue
		}
		if strings.HasPrefix(b, "*.") {
			suf := strings.TrimPrefix(b, "*.")
			if n == suf || strings.HasSuffix(n, "."+suf) {
				return true
			}
			continue
		}
		if n == b || strings.HasSuffix(n, "."+b) {
			return true
		}
	}
	return false
}
