package mapper

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const defaultPublicIPURL = "https://api.ipify.org"

// publicIPCache holds server egress IP for VIP fallback when mapper API URL is empty.
type publicIPCache struct {
	mu      sync.RWMutex
	ip      net.IP
	fetched time.Time
	ttl     time.Duration
	url     string
	client  *http.Client
}

func newPublicIPCache(probeURL string) *publicIPCache {
	u := strings.TrimSpace(probeURL)
	if u == "" {
		u = defaultPublicIPURL
	}
	return &publicIPCache{
		ttl:    5 * time.Minute,
		url:    u,
		client: &http.Client{Timeout: 8 * time.Second},
	}
}

func (p *publicIPCache) setProbeURL(u string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	u = strings.TrimSpace(u)
	if u == "" {
		u = defaultPublicIPURL
	}
	p.url = u
}

func (p *publicIPCache) get(ctx context.Context) net.IP {
	p.mu.RLock()
	ip := p.ip
	at := p.fetched
	u := p.url
	ttl := p.ttl
	cl := p.client
	p.mu.RUnlock()
	if ip != nil && time.Since(at) < ttl {
		return ip
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ip != nil && time.Since(p.fetched) < p.ttl {
		return p.ip
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return p.ip
	}
	resp, err := cl.Do(req)
	if err != nil {
		return p.ip
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil || resp.StatusCode != http.StatusOK {
		return p.ip
	}
	line := strings.TrimSpace(strings.Split(string(b), "\n")[0])
	if parsed := net.ParseIP(line); parsed != nil {
		p.ip = parsed
		p.fetched = time.Now()
		return p.ip
	}
	return p.ip
}
