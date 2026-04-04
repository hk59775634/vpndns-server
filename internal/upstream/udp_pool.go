package upstream

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

type udpConnPoolGroup struct {
	slots []udpSlot
	rr    uint64
}

type udpSlot struct {
	mu   sync.Mutex
	conn *dns.Conn
	addr string
}

func normalizeUDPAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return addr
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, "53")
	}
	return addr
}

func (g *udpConnPoolGroup) exchange(ctx context.Context, client *dns.Client, m *dns.Msg) (*dns.Msg, error) {
	if len(g.slots) == 0 {
		return nil, nil
	}
	i := atomic.AddUint64(&g.rr, 1) % uint64(len(g.slots))
	return g.slots[i].exchange(ctx, client, m)
}

func (s *udpSlot) exchange(ctx context.Context, client *dns.Client, m *dns.Msg) (*dns.Msg, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		co, err := client.DialContext(ctx, s.addr)
		if err != nil {
			return nil, err
		}
		s.conn = co
	}
	co := s.conn
	co.UDPSize = dns.MaxMsgSize
	r, _, err := client.ExchangeWithConnContext(ctx, m, co)
	if err != nil {
		_ = co.Close()
		s.conn = nil
	}
	return r, err
}

func (p *Pool) resetUDPPools() {
	p.udpPoolsMu.Lock()
	defer p.udpPoolsMu.Unlock()
	for _, g := range p.udpPools {
		for i := range g.slots {
			g.slots[i].mu.Lock()
			if g.slots[i].conn != nil {
				_ = g.slots[i].conn.Close()
				g.slots[i].conn = nil
			}
			g.slots[i].mu.Unlock()
		}
	}
	p.udpPools = make(map[string]*udpConnPoolGroup)
}

func (p *Pool) getUDPPool(addr string) *udpConnPoolGroup {
	addr = normalizeUDPAddr(addr)
	p.udpPoolsMu.Lock()
	defer p.udpPoolsMu.Unlock()
	if g, ok := p.udpPools[addr]; ok {
		return g
	}
	n := p.udpSlots
	if n <= 0 {
		n = 1
	}
	g := &udpConnPoolGroup{slots: make([]udpSlot, n)}
	for i := range g.slots {
		g.slots[i].addr = addr
	}
	p.udpPools[addr] = g
	return g
}
