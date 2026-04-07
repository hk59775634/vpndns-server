package upstream

import (
	"fmt"
	"strings"

	"github.com/vpndns/cdn/internal/config"
)

// pickDoHExchangeJSON returns whether to use Google JSON GET (/resolve) vs RFC 8484 binary POST.
func pickDoHExchangeJSON(u *config.UpstreamSpec) (bool, error) {
	if u == nil {
		return false, nil
	}
	mode := strings.ToLower(strings.TrimSpace(u.DoHMode))
	name := strings.TrimSpace(u.Name)
	switch mode {
	case "json", "json_get", "google_json":
		if !isGoogleJSONResolveURL(u.URL) {
			return false, fmt.Errorf("upstream %q: doh_mode json_get requires URL path ending with /resolve (e.g. https://dns.google/resolve)", name)
		}
		return true, nil
	case "rfc8484", "binary", "wire":
		return false, nil
	case "auto", "":
		return isGoogleJSONResolveURL(u.URL), nil
	default:
		return false, fmt.Errorf("upstream %q: invalid doh_mode %q (use auto, rfc8484, json_get)", name, u.DoHMode)
	}
}

// upstreamDoHIsJSON is for admin log labels only (mirrors pickDoHExchangeJSON without error cases).
func upstreamDoHIsJSON(u *config.UpstreamSpec) bool {
	if u == nil || strings.TrimSpace(u.URL) == "" {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(u.DoHMode))
	switch mode {
	case "json", "json_get", "google_json":
		return true
	case "rfc8484", "binary", "wire":
		return false
	default:
		return isGoogleJSONResolveURL(u.URL)
	}
}
