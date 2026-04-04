package ecs

import (
	"fmt"
	"net"

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
