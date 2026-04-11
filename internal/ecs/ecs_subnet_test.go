package ecs

import (
	"net"
	"testing"
)

func TestValidNormalizedSubnet_rejectsSlashZero(t *testing.T) {
	if ValidNormalizedSubnet("58.56.59.0/0") != "" {
		t.Fatal("expected empty for /0")
	}
	if ValidNormalizedSubnet("2001:db8::/0") != "" {
		t.Fatal("expected empty for ipv6 /0")
	}
	if v := ValidNormalizedSubnet("58.56.59.0/18"); v == "" || v != "58.56.0.0/18" {
		t.Fatalf("got %q", v)
	}
}

func TestSubnetKeyForStore_prefersEcho(t *testing.T) {
	ip := net.ParseIP("58.56.59.1")
	got := SubnetKeyForStore("58.56.59.0/18", "58.56.59.0/24", "", ip)
	if got != "58.56.0.0/18" {
		t.Fatalf("got %q", got)
	}
}

func TestSubnetKeyForStore_invalidEchoUsesSent(t *testing.T) {
	ip := net.ParseIP("58.56.59.1")
	got := SubnetKeyForStore("58.56.59.0/0", "58.56.59.0/24", "", ip)
	if got != "58.56.59.0/24" {
		t.Fatalf("got %q", got)
	}
}

func TestSubnetKeyForRead_usesMapped(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	got := SubnetKeyForRead("58.56.59.0/18", "58.56.59.0/24", "", ip)
	if got != "58.56.0.0/18" {
		t.Fatalf("got %q", got)
	}
}
