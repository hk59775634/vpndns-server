package doh

import (
	"net/http"
	"strings"
)

// HTTPRequestFullURL returns the client-visible URL (scheme, host, path, query).
// Honors X-Forwarded-Proto and X-Forwarded-Host when present.
func HTTPRequestFullURL(r *http.Request) string {
	if r == nil {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); p != "" {
		scheme = strings.ToLower(p)
	}
	host := r.Host
	if h := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); h != "" {
		host = strings.TrimSpace(strings.Split(h, ",")[0])
	}
	if host == "" {
		host = r.URL.Host
	}
	return scheme + "://" + host + r.URL.RequestURI()
}
