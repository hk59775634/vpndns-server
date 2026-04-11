package resolver

import (
	"net"
	"testing"
)

func TestCnUpstreamECSSelect_usesDefaultWhenNoPublicClientOrMapped(t *testing.T) {
	def := net.ParseIP("58.56.59.66")
	// Private client subnet → skip client; no mapped pub in ecsSourceIP if we pass nil
	ip, bits, src := cnUpstreamECSSelect(nil, "10.1.1.1/24", def)
	if bits != 24 || !ip.Equal(def) || src != "default_cn" {
		t.Fatalf("expected default_cn_ecs 58.56.59.66/24 default_cn, got %v/%d %s", ip, bits, src)
	}
}

func TestCnUpstreamECSSelect_prefersPublicClientOverDefault(t *testing.T) {
	def := net.ParseIP("58.56.59.66")
	pub := net.ParseIP("103.6.4.0")
	clientECS := "203.0.113.50/32"
	ip, bits, src := cnUpstreamECSSelect(pub, clientECS, def)
	if bits != 32 || !ip.Equal(net.ParseIP("203.0.113.50")) || src != "client_edns" {
		t.Fatalf("expected client EDNS, got %v/%d %s", ip, bits, src)
	}
}

func TestCnUpstreamECSSelect_prefersMappedOverDefault(t *testing.T) {
	def := net.ParseIP("58.56.59.66")
	pub := net.ParseIP("103.6.4.50")
	clientECS := "10.1.1.1/24"
	ip, bits, src := cnUpstreamECSSelect(pub, clientECS, def)
	if bits != 24 || !ip.Equal(net.ParseIP("103.6.4.50")) || src != "vip_mapped" {
		t.Fatalf("expected mapped /24 vip_mapped, got %v/%d %s", ip, bits, src)
	}
}

func TestCnUpstreamECSSelect_noDefaultUsesClientThenMapped(t *testing.T) {
	pub := net.ParseIP("203.0.113.50")
	clientECS := "192.0.2.0/24"
	ip, bits, src := cnUpstreamECSSelect(pub, clientECS, nil)
	if bits != 24 || src != "client_edns" {
		t.Fatalf("bits: %d src %s", bits, src)
	}
	if !ip.Equal(net.ParseIP("192.0.2.0")) {
		t.Fatalf("expected client ECS address, got %v", ip)
	}
}

func TestOutUpstreamECS_prefersOutDefault(t *testing.T) {
	out := net.ParseIP("8.8.8.8")
	pub := net.ParseIP("103.6.4.0")
	ip, bits := outUpstreamECS(pub, "", out)
	if bits != 24 || !ip.Equal(out) {
		t.Fatalf("expected default_out_ecs, got %v/%d", ip, bits)
	}
}

func TestOutUpstreamECS_neverUsesCnDefault_usesMappedOrOmits(t *testing.T) {
	pub := net.ParseIP("103.6.4.0")
	ip, bits := outUpstreamECS(pub, "", nil)
	if bits != 24 || !ip.Equal(pub) {
		t.Fatalf("expected mapped public /24, got %v/%d", ip, bits)
	}
	ip2, bits2 := outUpstreamECS(nil, "", nil)
	if ip2 != nil || bits2 != 0 {
		t.Fatalf("expected no ECS without mapped/out default, got %v/%d", ip2, bits2)
	}
}

func TestOutUpstreamECS_clientPublicEDNSOverMapped(t *testing.T) {
	pub := net.ParseIP("103.6.4.0")
	ip, bits := outUpstreamECS(pub, "192.0.2.0/24", nil)
	if bits != 24 || !ip.Equal(net.ParseIP("192.0.2.0")) {
		t.Fatalf("expected client public ECS first, got %v/%d", ip, bits)
	}
}
