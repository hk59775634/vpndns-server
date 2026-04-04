package geoip

import (
	"encoding/binary"
	"net"
	"sort"
)

type ipv4Range struct {
	lo, hi uint32
}

func ipv4Bounds(n *net.IPNet) (lo, hi uint32, ok bool) {
	ip := n.IP.To4()
	if ip == nil {
		return 0, 0, false
	}
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return 0, 0, false
	}
	base := binary.BigEndian.Uint32(ip)
	if ones >= 32 {
		return base, base, true
	}
	hostBits := 32 - ones
	mask := ^uint32(0) << hostBits
	lo = base & mask
	hi = lo | (^mask & 0xffffffff)
	return lo, hi, true
}

func buildIPv4Ranges(nets []*net.IPNet) []ipv4Range {
	var tmp []ipv4Range
	for _, n := range nets {
		lo, hi, ok := ipv4Bounds(n)
		if !ok {
			continue
		}
		tmp = append(tmp, ipv4Range{lo: lo, hi: hi})
	}
	if len(tmp) == 0 {
		return nil
	}
	sort.Slice(tmp, func(i, j int) bool {
		if tmp[i].lo != tmp[j].lo {
			return tmp[i].lo < tmp[j].lo
		}
		return tmp[i].hi < tmp[j].hi
	})
	var out []ipv4Range
	cur := tmp[0]
	for i := 1; i < len(tmp); i++ {
		nx := tmp[i]
		if nx.lo <= cur.hi+1 {
			if nx.hi > cur.hi {
				cur.hi = nx.hi
			}
			continue
		}
		out = append(out, cur)
		cur = nx
	}
	out = append(out, cur)
	return out
}

func ipv4ToU32(ip net.IP) (uint32, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip4), true
}

func containsV4Ranges(rs []ipv4Range, ip net.IP) bool {
	u, ok := ipv4ToU32(ip)
	if !ok || len(rs) == 0 {
		return false
	}
	i := sort.Search(len(rs), func(i int) bool { return rs[i].hi >= u })
	return i < len(rs) && rs[i].lo <= u && u <= rs[i].hi
}
