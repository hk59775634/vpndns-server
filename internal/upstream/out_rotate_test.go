package upstream

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestOutEmptyNoDataAQuad(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Rcode = dns.RcodeSuccess
	if !outEmptyNoDataAQuad(m, dns.TypeA) {
		t.Fatal("expected empty NOERROR A as retryable")
	}
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("1.1.1.1").To4()}}
	if outEmptyNoDataAQuad(m, dns.TypeA) {
		t.Fatal("expected non-empty")
	}
	m2 := new(dns.Msg)
	m2.Rcode = dns.RcodeNameError
	if outEmptyNoDataAQuad(m2, dns.TypeA) {
		t.Fatal("NXDOMAIN is not empty-no-data in this sense")
	}
}
