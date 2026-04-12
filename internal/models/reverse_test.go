package models

import (
	"testing"

	"github.com/miekg/dns"
)

func TestIsReverseLookupQName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"1.0.0.127.in-addr.arpa.", true},
		{"1.0.0.127.in-addr.arpa", true},
		{"b.a.9.8.7.6.5.4.3.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", true},
		{"example.com.", false},
		{"in-addr.arpa.", false},
		{"arpa.", false},
	}
	for _, tc := range tests {
		if got := IsReverseLookupQName(tc.name); got != tc.want {
			t.Fatalf("%q: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestNewIPv6DisabledAAAAResponse(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeAAAA)
	req := &DNSRequest{Msg: m}
	resp := NewIPv6DisabledAAAAResponse(req)
	if resp == nil || resp.Msg == nil || !resp.SkipQueryLog {
		t.Fatal("bad response")
	}
	if resp.Msg.Rcode != dns.RcodeSuccess || len(resp.Msg.Answer) != 0 {
		t.Fatalf("want NOERROR NODATA, got rcode=%d answers=%d", resp.Msg.Rcode, len(resp.Msg.Answer))
	}
}

func TestNewReverseLookupSkippedResponse(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("4.3.2.1.in-addr.arpa.", dns.TypePTR)
	req := &DNSRequest{Msg: m}
	resp := NewReverseLookupSkippedResponse(req)
	if resp == nil || resp.Msg == nil || !resp.SkipQueryLog {
		t.Fatal("bad response")
	}
	if resp.Msg.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode %d", resp.Msg.Rcode)
	}
}
