package resolver

import (
	"net"
	"testing"
)

func TestCnUpstreamECS_usesDefaultWhenConfigured(t *testing.T) {
	def := net.ParseIP("58.56.59.66")
	pub := net.ParseIP("103.6.4.0")
	clientECS := "192.0.2.0/24"
	ip, bits := cnUpstreamECS(pub, clientECS, def)
	if bits != 24 || !ip.Equal(def) {
		t.Fatalf("expected default_cn_ecs 58.56.59.66/24, got %v/%d", ip, bits)
	}
}

func TestCnUpstreamECS_noDefaultUsesClientThenMapped(t *testing.T) {
	pub := net.ParseIP("203.0.113.50")
	clientECS := "192.0.2.0/24"
	ip, bits := cnUpstreamECS(pub, clientECS, nil)
	if bits != 24 {
		t.Fatalf("bits: %d", bits)
	}
	if !ip.Equal(net.ParseIP("192.0.2.0")) {
		t.Fatalf("expected client ECS address, got %v", ip)
	}
}

func TestOutUpstreamECS_prefersOutDefault(t *testing.T) {
	out := net.ParseIP("8.8.8.8")
	cn := net.ParseIP("58.56.59.66")
	pub := net.ParseIP("103.6.4.0")
	ip, bits := outUpstreamECS(pub, "", out, cn)
	if bits != 24 || !ip.Equal(out) {
		t.Fatalf("expected default_out_ecs, got %v/%d", ip, bits)
	}
}

func TestOutUpstreamECS_fallsBackToCnDefaultWithoutMappedIP(t *testing.T) {
	cn := net.ParseIP("58.56.59.66")
	pub := net.ParseIP("103.6.4.0")
	ip, bits := outUpstreamECS(pub, "", nil, cn)
	if bits != 24 || !ip.Equal(cn) {
		t.Fatalf("expected default_cn_ecs for OUT when default_out empty, got %v/%d", ip, bits)
	}
}

func TestOutUpstreamECS_clientEDNSOverCnDefault(t *testing.T) {
	cn := net.ParseIP("58.56.59.66")
	pub := net.ParseIP("103.6.4.0")
	ip, bits := outUpstreamECS(pub, "192.0.2.0/24", nil, cn)
	if bits != 24 || !ip.Equal(net.ParseIP("192.0.2.0")) {
		t.Fatalf("expected client ECS first, got %v/%d", ip, bits)
	}
}
