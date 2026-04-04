package subscribe

import (
	"strings"
)

// parseSubscribeLine extracts a whitelist pattern from one subscription line.
// Supports AdGuard/ABP-style ||domain^ rules and plain one-domain-per-line lists.
func parseSubscribeLine(line string) (pattern string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return "", false
	}
	// Cosmetic / element hiding rules
	if strings.Contains(line, "##") {
		return "", false
	}
	if strings.HasPrefix(line, "||") {
		s := strings.TrimPrefix(line, "||")
		s = strings.TrimSpace(s)
		if strings.HasSuffix(s, "^") {
			s = strings.TrimSuffix(s, "^")
		}
		return normalizePattern(strings.TrimSpace(s))
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", false
	}
	return normalizePattern(fields[0])
}

func normalizePattern(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	// Source data sometimes has "||*. myid.gov.au^" → "*. myid.gov.au"
	if strings.HasPrefix(s, "*. ") {
		rest := strings.TrimSpace(strings.TrimPrefix(s, "*. "))
		s = "*." + rest
	}
	// "||*.*google.com^" → map to our single *.suffix matcher
	if strings.HasPrefix(s, "*.*") {
		s = "*." + strings.TrimPrefix(s, "*.*")
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", false
	}
	return s, true
}
