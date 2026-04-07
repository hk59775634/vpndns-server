package upstream

import (
	"testing"

	"github.com/vpndns/cdn/internal/config"
)

func TestPickDoHExchangeJSON(t *testing.T) {
	cases := []struct {
		u       config.UpstreamSpec
		want    bool
		wantErr bool
	}{
		{config.UpstreamSpec{Name: "a", URL: "https://dns.google/dns-query", DoHMode: "auto"}, false, false},
		{config.UpstreamSpec{Name: "b", URL: "https://dns.google/resolve", DoHMode: "auto"}, true, false},
		{config.UpstreamSpec{Name: "c", URL: "https://dns.google/dns-query", DoHMode: "rfc8484"}, false, false},
		{config.UpstreamSpec{Name: "d", URL: "https://dns.google/resolve", DoHMode: "rfc8484"}, false, false},
		{config.UpstreamSpec{Name: "e", URL: "https://dns.google/resolve", DoHMode: "json_get"}, true, false},
		{config.UpstreamSpec{Name: "f", URL: "https://dns.google/dns-query", DoHMode: "json_get"}, false, true},
	}
	for _, tc := range cases {
		got, err := pickDoHExchangeJSON(&tc.u)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%s: want error", tc.u.Name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.u.Name, err)
		}
		if got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.u.Name, got, tc.want)
		}
	}
}
