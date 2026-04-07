package mapper

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// VIPRedisKey returns redis key for VIP mapping.
func VIPRedisKey(vip string) string {
	return "vip:" + strings.TrimSpace(vip)
}

// Mapper resolves VPN virtual IP to real public IP via Redis then HTTP API.
type Mapper struct {
	mu                      sync.RWMutex
	rdb                     *redis.Client
	apiURL                  string
	ttl                     time.Duration
	client                  *http.Client
	pub                     *publicIPCache
	httpMaxIdle             int
	httpMaxIdleConnsPerHost int
}

// New builds a mapper. maxIdle / maxPerHost tune outbound HTTP to mapper API (0 = use caller defaults from config).
func New(rdb *redis.Client, apiURL string, ttlSeconds int, publicProbeURL string, maxIdle, maxPerHost int) *Mapper {
	m := &Mapper{rdb: rdb, pub: newPublicIPCache(publicProbeURL)}
	m.Reload(apiURL, ttlSeconds, publicProbeURL, maxIdle, maxPerHost)
	return m
}

func (m *Mapper) buildClientLocked() {
	mi, mh := m.httpMaxIdle, m.httpMaxIdleConnsPerHost
	if mi < 1 {
		mi = 128
	}
	if mh < 1 {
		mh = 32
	}
	m.client = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        mi,
			MaxIdleConnsPerHost: mh,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// Reload updates API URL, TTL, public-IP probe URL, and HTTP client pool limits.
func (m *Mapper) Reload(apiURL string, ttlSeconds int, publicProbeURL string, maxIdle, maxPerHost int) {
	if ttlSeconds <= 0 {
		ttlSeconds = 300
	}
	m.mu.Lock()
	m.apiURL = strings.TrimSpace(apiURL)
	m.ttl = time.Duration(ttlSeconds) * time.Second
	if maxIdle > 0 {
		m.httpMaxIdle = maxIdle
	}
	if maxPerHost > 0 {
		m.httpMaxIdleConnsPerHost = maxPerHost
	}
	m.buildClientLocked()
	m.mu.Unlock()
	if m.pub != nil {
		m.pub.setProbeURL(publicProbeURL)
	}
}

// PublicUnicastIP returns ip if it is a globally routable unicast address, otherwise nil.
// Used when choosing EDNS Client Subnet for upstreams: private / VPN addresses must not block
// mapper.default_cn_ecs / default_out_ecs fallbacks.
func PublicUnicastIP(ip net.IP) net.IP {
	if isPublicUnicastIP(ip) {
		return ip
	}
	return nil
}

// isPublicUnicastIP reports whether ip is a globally routable unicast address (not loopback, ULA, RFC1918, link-local, CGNAT 100.64/10, etc.).
func isPublicUnicastIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip = ip.To16()
	if ip == nil {
		return false
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		// RFC 6598 shared address space (carrier-grade NAT), not public Internet.
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return false
		}
	}
	return true
}

// GetRealIP returns mapped real IP. If vip is already a public unicast IP, it is returned immediately (no Redis / mapper API / egress probe).
// Otherwise: Redis cache, then HTTP mapper API or server's public egress IP when api_url is empty, then parsing vip as any IP.
func (m *Mapper) GetRealIP(ctx context.Context, vip string) (net.IP, error) {
	vip = strings.TrimSpace(vip)
	if vip == "" {
		return nil, fmt.Errorf("empty vip")
	}
	if ip := net.ParseIP(vip); ip != nil && isPublicUnicastIP(ip) {
		return ip, nil
	}
	if m.rdb != nil {
		s, err := m.rdb.Get(ctx, VIPRedisKey(vip)).Result()
		if err == nil && s != "" {
			if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
				return ip, nil
			}
		}
	}
	m.mu.RLock()
	apiURL := m.apiURL
	ttl := m.ttl
	m.mu.RUnlock()
	if apiURL != "" {
		ip, err := m.fetchAPI(ctx, vip, apiURL)
		if err == nil && ip != nil {
			if m.rdb != nil {
				_ = m.rdb.Set(ctx, VIPRedisKey(vip), ip.String(), ttl).Err()
			}
			return ip, nil
		}
	} else if m.pub != nil {
		if ip := m.pub.get(ctx); ip != nil {
			if m.rdb != nil {
				_ = m.rdb.Set(ctx, VIPRedisKey(vip), ip.String(), ttl).Err()
			}
			return ip, nil
		}
	}
	if ip := net.ParseIP(vip); ip != nil {
		return ip, nil
	}
	return nil, fmt.Errorf("no mapping for vip %q", vip)
}

func (m *Mapper) fetchAPI(ctx context.Context, vip, apiURL string) (net.IP, error) {
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("ip", vip)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	cli := m.client
	m.mu.RUnlock()
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return nil, err
	}
	line := strings.TrimSpace(strings.Split(string(b), "\n")[0])
	if ip := net.ParseIP(line); ip != nil {
		return ip, nil
	}
	return nil, fmt.Errorf("invalid api response %q", line)
}
