package ecs

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// SubnetForECS returns aggregated subnet string for cache key: IPv4 /24, IPv6 /48.
func SubnetForECS(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return "unknown"
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip4[3] = 0
		return fmt.Sprintf("%s/24", ip4.String())
	}
	// IPv6: zero last 80 bits for /48
	for i := 6; i < 16; i++ {
		ip[i] = 0
	}
	return fmt.Sprintf("%s/48", ip.String())
}

// FromClientOrIP picks ECS subnet: client EDNS subnet if valid, else derived from real IP.
func FromClientOrIP(clientECS string, realIP net.IP) string {
	if clientECS != "" {
		if _, ipNet, err := net.ParseCIDR(clientECS); err == nil && ipNet != nil {
			if ones, _ := ipNet.Mask.Size(); ones > 0 {
				return normalizeSubnet(ipNet)
			}
		}
	}
	if realIP != nil {
		return SubnetForECS(realIP)
	}
	return "0.0.0.0/24"
}

// GoogleSubnetQueryParam builds the edns_client_subnet query value for Google JSON GET
// (same semantics as the wire EDNS ECS sent to other upstreams).
func GoogleSubnetQueryParam(ip net.IP, bits int) string {
	if ip == nil || bits <= 0 {
		return ""
	}
	if ip4 := ip.To4(); ip4 != nil {
		if bits > 32 {
			bits = 32
		}
		m := net.CIDRMask(bits, 32)
		n := ip4.Mask(m)
		return fmt.Sprintf("%s/%d", n.String(), bits)
	}
	ip6 := ip.To16()
	if ip6 == nil {
		return ""
	}
	if bits > 128 {
		bits = 128
	}
	m := net.CIDRMask(bits, 128)
	n := ip6.Mask(m)
	return fmt.Sprintf("%s/%d", n.String(), bits)
}

// ValidNormalizedSubnet parses a CIDR string and returns a canonical form suitable
// for cache keys. Empty string is returned for invalid input or prefix length 0 (/0).
func ValidNormalizedSubnet(cidr string) string {
	s := strings.TrimSpace(cidr)
	if s == "" {
		return ""
	}
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil || ipNet == nil {
		return ""
	}
	ones, bits := ipNet.Mask.Size()
	if ones <= 0 || bits <= 0 {
		return ""
	}
	return normalizeSubnet(ipNet)
}

// SubnetKeyForRead picks the ECS dimension for cache lookup: mapped Google echo (from Redis),
// else the subnet sent to upstream (Google JSON param or equivalent), else FromClientOrIP.
func SubnetKeyForRead(mappedEffective, sentToUpstream, clientECS string, subnetIP net.IP) string {
	if mappedEffective != "" {
		if v := ValidNormalizedSubnet(mappedEffective); v != "" {
			return v
		}
	}
	if sentToUpstream != "" {
		if v := ValidNormalizedSubnet(sentToUpstream); v != "" {
			return v
		}
	}
	return FromClientOrIP(clientECS, subnetIP)
}

// SubnetKeyForStore picks the ECS dimension to store after an upstream response.
// Prefer a valid Google JSON echo; otherwise sent param; otherwise FromClientOrIP.
func SubnetKeyForStore(googleEcho, sentToUpstream, clientECS string, subnetIP net.IP) string {
	if googleEcho != "" {
		if v := ValidNormalizedSubnet(googleEcho); v != "" {
			return v
		}
	}
	if sentToUpstream != "" {
		if v := ValidNormalizedSubnet(sentToUpstream); v != "" {
			return v
		}
	}
	return FromClientOrIP(clientECS, subnetIP)
}

func normalizeSubnet(ipNet *net.IPNet) string {
	ip := ipNet.IP
	ones, bits := ipNet.Mask.Size()
	if bits == 32 {
		mask := net.CIDRMask(ones, 32)
		n := ip.Mask(mask)
		if n4 := n.To4(); n4 != nil {
			return fmt.Sprintf("%s/%d", n4.String(), ones)
		}
	}
	if bits == 128 {
		mask := net.CIDRMask(ones, 128)
		n := ip.Mask(mask)
		return fmt.Sprintf("%s/%d", n.String(), ones)
	}
	return ipNet.String()
}

// EDNS0Subnet extracts client subnet from EDNS0 OPT if present (first ECS option).
func EDNS0Subnet(msg *dns.Msg) string {
	if msg == nil {
		return ""
	}
	opt := msg.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_SUBNET); ok {
			if e.Address == nil {
				continue
			}
			fam := uint16(1)
			bits := uint8(24)
			if e.Family == 2 {
				fam = 2
				bits = 48
			}
			maskBits := e.SourceNetmask
			if maskBits == 0 {
				maskBits = bits
			}
			ip := e.Address
			if fam == 1 {
				ip = ip.To4()
			}
			if ip == nil {
				continue
			}
			_, ipNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), maskBits))
			if err != nil {
				continue
			}
			return ipNet.String()
		}
	}
	return ""
}
