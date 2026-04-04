package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

const (
	defaultGeoIPCIDRListURL = "https://ispip.clang.cn/all_cn.txt"
	defaultGeoIPDatCNURL    = "https://github.com/v2fly/geoip/releases/latest/download/cn.dat"
)

// Config is the full runtime configuration (hot-reloadable fields marked).
type Config struct {
	Listen struct {
		UDP        string `yaml:"udp" json:"udp"`
		TCP        string `yaml:"tcp" json:"tcp"`
		DoH        string `yaml:"doh" json:"doh"`
		Admin      string `yaml:"admin" json:"admin"`
		DoHTLS     bool   `yaml:"doh_tls" json:"doh_tls"`
		TLSCert    string `yaml:"tls_cert" json:"tls_cert"`
		TLSKey     string `yaml:"tls_key" json:"tls_key"`
		TLSCertPEM string `yaml:"tls_cert_pem" json:"tls_cert_pem"`
		TLSKeyPEM  string `yaml:"tls_key_pem" json:"tls_key_pem"`
		// MaxTCPDNSConnections limits concurrent inbound TCP DNS connections (0 = unlimited).
		MaxTCPDNSConnections int `yaml:"max_tcp_dns_connections" json:"max_tcp_dns_connections"`
	} `yaml:"listen" json:"listen"`

	Redis struct {
		Addr         string `yaml:"addr" json:"addr"`
		Password     string `yaml:"password" json:"password"`
		DB           int    `yaml:"db" json:"db"`
		PoolSize     int    `yaml:"pool_size" json:"pool_size"`             // go-redis 连接池大小（0=默认 256）
		MinIdleConns int    `yaml:"min_idle_conns" json:"min_idle_conns"` // 池中最小空闲连接（0=默认 32）
		// PoolFIFO: nil 或 true 时使用 FIFO；仅当显式 false 时关闭。
		PoolFIFO *bool `yaml:"pool_fifo,omitempty" json:"pool_fifo,omitempty"`
	} `yaml:"redis" json:"redis"`

	CNDNS  []UpstreamSpec `yaml:"cn_dns" json:"cn_dns"`
	OUTDNS []UpstreamSpec `yaml:"out_dns" json:"out_dns"`

	Mapper struct {
		APIURL           string `yaml:"api_url" json:"api_url"`
		TTL              int    `yaml:"ttl_seconds" json:"ttl_seconds"`
		PublicIPProbeURL string `yaml:"public_ip_probe_url" json:"public_ip_probe_url"`
		// HTTPMaxIdleConns / PerHost：外呼 mapper API 的 http.Transport 空闲连接上限（0=默认 128 / 32）。
		HTTPMaxIdleConns        int `yaml:"http_max_idle_conns" json:"http_max_idle_conns"`
		HTTPMaxIdleConnsPerHost int `yaml:"http_max_idle_conns_per_host" json:"http_max_idle_conns_per_host"`
		// DefaultCNECS is used as EDNS Client Subnet source when asking cn_dns and VIP→IP mapping yields no usable IP (after mapper + client VIP parse).
		DefaultCNECS string `yaml:"default_cn_ecs" json:"default_cn_ecs"`
		// DefaultOUTECS is used as ECS when asking out_dns (after client EDNS subnet and mapped real IP, if any).
		DefaultOUTECS string `yaml:"default_out_ecs" json:"default_out_ecs"`
	} `yaml:"mapper" json:"mapper"`

	Resolver struct {
		MaxCacheTTLSeconds int    `yaml:"max_cache_ttl_seconds" json:"max_cache_ttl_seconds"`
		NonWhitelistAction string `yaml:"non_whitelist_action" json:"non_whitelist_action"` // nxdomain | localhost
		QueryTimeoutMS     int    `yaml:"query_timeout_ms" json:"query_timeout_ms"`
		UpstreamRetries    int    `yaml:"upstream_retries" json:"upstream_retries"`
		// DisableIPv6 when true: AAAA queries get NODATA; AAAA RRs are stripped from all answers.
		DisableIPv6 bool `yaml:"disable_ipv6" json:"disable_ipv6"`

		// MaxInflightUpstream caps concurrent upstream (DoH/UDP) queries process-wide (0 = unlimited).
		MaxInflightUpstream int `yaml:"max_inflight_upstream" json:"max_inflight_upstream"`
		// GlobalResolveQPS token bucket for accepted resolves (after per-IP limit); 0 = disabled.
		GlobalResolveQPS   float64 `yaml:"global_resolve_qps" json:"global_resolve_qps"`
		GlobalResolveBurst int     `yaml:"global_resolve_burst" json:"global_resolve_burst"`
		// OverloadDNSResponse when global limit rejects: servfail | refused.
		OverloadDNSResponse string `yaml:"overload_dns_response" json:"overload_dns_response"`

		DoHMaxIdleConns        int `yaml:"doh_max_idle_conns" json:"doh_max_idle_conns"`
		DoHMaxIdleConnsPerHost int `yaml:"doh_max_idle_conns_per_host" json:"doh_max_idle_conns_per_host"`
		// UDPConnsPerUpstream parallel UDP sockets per upstream address (0 = legacy single-use dial per query).
		UDPConnsPerUpstream int `yaml:"udp_conns_per_upstream" json:"udp_conns_per_upstream"`
		// UpstreamOrderedFallback: on retry, try cn_dns/out_dns in YAML order instead of re-weighting.
		UpstreamOrderedFallback bool `yaml:"upstream_ordered_fallback" json:"upstream_ordered_fallback"`

		// L1 in-memory DNS cache in front of Redis (0 = disabled).
		L1CacheMaxEntries    int `yaml:"l1_cache_max_entries" json:"l1_cache_max_entries"`
		L1CacheTTLCapSeconds int `yaml:"l1_cache_ttl_cap_seconds" json:"l1_cache_ttl_cap_seconds"`
		// CoalesceUpstream: 相同上游查询在并发下合并为单次回源（singleflight）。nil 视为 true。
		CoalesceUpstream *bool `yaml:"coalesce_upstream,omitempty" json:"coalesce_upstream,omitempty"`
	} `yaml:"resolver" json:"resolver"`

	GeoIP struct {
		ChnrouteURL  string `yaml:"chnroute_url" json:"chnroute_url"`   // CIDR text list URL
		GeoIPDatURL  string `yaml:"geoip_dat_url" json:"geoip_dat_url"` // V2Ray geoip.dat / cn.dat URL
		RefreshMin   int    `yaml:"refresh_minutes" json:"refresh_minutes"`
		SourceFormat string `yaml:"source_format" json:"source_format"` // cidr | geoip_dat
	} `yaml:"geoip" json:"geoip"`

	RateLimit struct {
		// QPSPerIP: tokens refill rate per client IP (DNS UDP/TCP + DoH). nil = default 500; *0 = unlimited (no per-IP limit).
		QPSPerIP *float64 `yaml:"qps_per_ip,omitempty" json:"qps_per_ip,omitempty"`
		// Burst: token bucket capacity per IP. nil = default 1000; *0 with qps>0 = unlimited burst; ignored when qps is unlimited.
		Burst *int `yaml:"burst,omitempty" json:"burst,omitempty"`
		// PerIPLimiterIdleMinutes: drop per-IP limiter state if untouched this long (0 = use default 20).
		PerIPLimiterIdleMinutes int `yaml:"per_ip_limiter_idle_minutes" json:"per_ip_limiter_idle_minutes"`
	} `yaml:"rate_limit" json:"rate_limit"`

	Security struct {
		Blacklist []string `yaml:"blacklist" json:"blacklist"`
		DoHAuth   struct {
			Enabled bool   `yaml:"enabled" json:"enabled"`
			Token   string `yaml:"bearer_token" json:"bearer_token"`
		} `yaml:"doh_auth" json:"doh_auth"`
	} `yaml:"security" json:"security"`

	Whitelist struct {
		SubscribeURLs []string `yaml:"subscribe_urls" json:"subscribe_urls"`
		RefreshMin    int      `yaml:"refresh_minutes" json:"refresh_minutes"`
	} `yaml:"whitelist" json:"whitelist"`

	Warmup struct {
		Domains []string `yaml:"domains" json:"domains"`
		QTypes  []string `yaml:"qtypes" json:"qtypes"`
	} `yaml:"warmup" json:"warmup"`

	Stats struct {
		PersistIntervalSec int    `yaml:"persist_interval_seconds" json:"persist_interval_seconds"`
		RedisKey           string `yaml:"redis_key" json:"redis_key"`
	} `yaml:"stats" json:"stats"`

	QueryLog struct {
		RedisKey   string `yaml:"redis_key" json:"redis_key"`
		MaxEntries int    `yaml:"max_entries" json:"max_entries"` // >0: Redis capped list (RPUSH+LTRIM); 0: in-memory ring only
	} `yaml:"query_log" json:"query_log"`

	Admin struct {
		Username       string `yaml:"username" json:"username"`
		PasswordBcrypt string `yaml:"password_bcrypt" json:"password_bcrypt"`
		SessionSecret  string `yaml:"session_secret" json:"session_secret"`
		APIKey         string `yaml:"api_key" json:"api_key"`
	} `yaml:"admin" json:"admin"`
}

// UpstreamSpec describes one DNS upstream (DoH URL or host:port for UDP).
type UpstreamSpec struct {
	Name    string `yaml:"name" json:"name"`
	URL     string `yaml:"url" json:"url"`         // https://.../dns-query
	Address string `yaml:"address" json:"address"` // 223.5.5.5:53
	Weight  int    `yaml:"weight" json:"weight"`
}

// Defaults fills zero values.
func (c *Config) Defaults() {
	if c.Listen.UDP == "" {
		c.Listen.UDP = ":53"
	}
	if c.Listen.TCP == "" {
		c.Listen.TCP = ":53"
	}
	if c.Listen.DoH == "" {
		c.Listen.DoH = ":8053"
	}
	if c.Listen.Admin == "" {
		c.Listen.Admin = ":8080"
	}
	if c.Redis.Addr == "" {
		c.Redis.Addr = "127.0.0.1:6379"
	}
	if c.Redis.PoolSize <= 0 {
		c.Redis.PoolSize = 256
	}
	if c.Redis.MinIdleConns <= 0 {
		c.Redis.MinIdleConns = 32
	}
	if c.Mapper.HTTPMaxIdleConns <= 0 {
		c.Mapper.HTTPMaxIdleConns = 128
	}
	if c.Mapper.HTTPMaxIdleConnsPerHost <= 0 {
		c.Mapper.HTTPMaxIdleConnsPerHost = 32
	}
	if c.Mapper.TTL <= 0 {
		c.Mapper.TTL = 300
	}
	if c.Resolver.MaxCacheTTLSeconds <= 0 {
		c.Resolver.MaxCacheTTLSeconds = 3600
	}
	if c.Resolver.NonWhitelistAction == "" {
		c.Resolver.NonWhitelistAction = "nxdomain"
	}
	if c.Resolver.QueryTimeoutMS <= 0 {
		c.Resolver.QueryTimeoutMS = 3000
	}
	if c.Resolver.UpstreamRetries <= 0 {
		c.Resolver.UpstreamRetries = 2
	}
	if c.Resolver.GlobalResolveQPS > 0 && c.Resolver.GlobalResolveBurst <= 0 {
		c.Resolver.GlobalResolveBurst = 10000
	}
	if strings.TrimSpace(c.Resolver.OverloadDNSResponse) == "" {
		c.Resolver.OverloadDNSResponse = "servfail"
	}
	if c.Resolver.DoHMaxIdleConns <= 0 {
		c.Resolver.DoHMaxIdleConns = 2048
	}
	if c.Resolver.DoHMaxIdleConnsPerHost <= 0 {
		c.Resolver.DoHMaxIdleConnsPerHost = 512
	}
	if c.Resolver.UDPConnsPerUpstream < 0 {
		c.Resolver.UDPConnsPerUpstream = 0
	}
	if c.Resolver.L1CacheTTLCapSeconds <= 0 {
		c.Resolver.L1CacheTTLCapSeconds = 60
	}
	if c.Resolver.CoalesceUpstream == nil {
		b := true
		c.Resolver.CoalesceUpstream = &b
	}
	if c.RateLimit.PerIPLimiterIdleMinutes <= 0 {
		c.RateLimit.PerIPLimiterIdleMinutes = 20
	}
	if c.GeoIP.RefreshMin <= 0 {
		c.GeoIP.RefreshMin = 1440
	}
	sf := strings.ToLower(strings.TrimSpace(c.GeoIP.SourceFormat))
	if sf == "" {
		sf = "cidr"
	}
	c.GeoIP.SourceFormat = sf
	// Migrate legacy single-field configs: geoip_dat used to store URL in chnroute_url only.
	if sf == "geoip_dat" && strings.TrimSpace(c.GeoIP.GeoIPDatURL) == "" {
		u := strings.TrimSpace(c.GeoIP.ChnrouteURL)
		low := strings.ToLower(u)
		if u != "" && (strings.HasSuffix(low, ".dat") || strings.Contains(low, "geoip")) {
			c.GeoIP.GeoIPDatURL = u
			c.GeoIP.ChnrouteURL = ""
		}
	}
	if strings.TrimSpace(c.GeoIP.ChnrouteURL) == "" {
		c.GeoIP.ChnrouteURL = defaultGeoIPCIDRListURL
	}
	if strings.TrimSpace(c.GeoIP.GeoIPDatURL) == "" {
		c.GeoIP.GeoIPDatURL = defaultGeoIPDatCNURL
	}
	if c.RateLimit.QPSPerIP == nil {
		v := 500.0
		c.RateLimit.QPSPerIP = &v
	}
	if c.RateLimit.Burst == nil {
		v := 1000
		c.RateLimit.Burst = &v
	}
	if c.Whitelist.RefreshMin <= 0 {
		c.Whitelist.RefreshMin = 60
	}
	if c.Stats.RedisKey == "" {
		c.Stats.RedisKey = "vpndns:stats:counters"
	}
	if c.QueryLog.RedisKey == "" {
		c.QueryLog.RedisKey = "vpndns:querylog"
	}
	if c.QueryLog.MaxEntries < 0 {
		c.QueryLog.MaxEntries = 0
	}
	for i := range c.CNDNS {
		if c.CNDNS[i].Weight <= 0 {
			c.CNDNS[i].Weight = 1
		}
	}
	for i := range c.OUTDNS {
		if c.OUTDNS[i].Weight <= 0 {
			c.OUTDNS[i].Weight = 1
		}
	}
	if c.Admin.Username == "" {
		c.Admin.Username = "admin"
	}
}

// Load reads YAML from path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	c.Defaults()
	return &c, nil
}

// Save writes YAML to path (atomic replace).
func Save(path string, c *Config) error {
	if c == nil {
		return errors.New("nil config")
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Store holds the current config with atomic swap.
type Store struct {
	mu  sync.RWMutex
	cfg *Config
}

func NewStore(initial *Config) *Store {
	return &Store{cfg: initial}
}

func (s *Store) Get() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *Store) Set(c *Config) {
	s.mu.Lock()
	s.cfg = c
	s.mu.Unlock()
}

// Watch reloads config on file change and invokes onReload after a successful parse.
func (s *Store) Watch(ctx context.Context, path string, onReload func(*Config)) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	dir := path
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		dir = dirParent(path)
	}
	if err := w.Add(dir); err != nil {
		_ = w.Close()
		return fmt.Errorf("watch %s: %w", dir, err)
	}
	go func() {
		defer w.Close()
		var debounce *time.Timer
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if !sameConfigPath(ev.Name, path) {
					continue
				}
				if ev.Op&(fsnotify.Write|fsnotify.Create) == 0 {
					continue
				}
				if debounce != nil {
					debounce.Stop()
				}
				debounce = time.AfterFunc(200*time.Millisecond, func() {
					c, err := Load(path)
					if err != nil {
						return
					}
					s.Set(c)
					if onReload != nil {
						onReload(c)
					}
				})
			case _, ok := <-w.Errors:
				if !ok {
					return
				}
			}
		}
	}()
	return nil
}

func dirParent(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/"
			}
			return p[:i]
		}
	}
	return "."
}

func sameConfigPath(eventName, path string) bool {
	a, err1 := filepath.Abs(path)
	b, err2 := filepath.Abs(eventName)
	if err1 != nil || err2 != nil {
		return filepath.Clean(eventName) == filepath.Clean(path)
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// ResolveGeoIPDownloadURL returns the download URL for the active geoip.source_format.
func ResolveGeoIPDownloadURL(c *Config) string {
	if c == nil {
		return ""
	}
	if strings.EqualFold(strings.TrimSpace(c.GeoIP.SourceFormat), "geoip_dat") {
		return strings.TrimSpace(c.GeoIP.GeoIPDatURL)
	}
	return strings.TrimSpace(c.GeoIP.ChnrouteURL)
}

// Validate returns an error if config is unusable.
func Validate(c *Config) error {
	if c == nil {
		return errors.New("nil config")
	}
	if len(c.CNDNS) == 0 {
		return errors.New("cn_dns: at least one upstream required")
	}
	if len(c.OUTDNS) == 0 {
		return errors.New("out_dns: at least one upstream required")
	}
	switch strings.ToLower(strings.TrimSpace(c.GeoIP.SourceFormat)) {
	case "cidr", "geoip_dat":
	default:
		return fmt.Errorf("geoip.source_format must be \"cidr\" or \"geoip_dat\", got %q", c.GeoIP.SourceFormat)
	}
	switch strings.ToLower(strings.TrimSpace(c.Resolver.OverloadDNSResponse)) {
	case "servfail", "refused":
	default:
		return fmt.Errorf("resolver.overload_dns_response must be \"servfail\" or \"refused\", got %q", c.Resolver.OverloadDNSResponse)
	}
	if c.Listen.MaxTCPDNSConnections < 0 {
		return errors.New("listen.max_tcp_dns_connections must be >= 0")
	}
	if c.Resolver.MaxInflightUpstream < 0 {
		return errors.New("resolver.max_inflight_upstream must be >= 0")
	}
	if c.Resolver.GlobalResolveQPS < 0 {
		return errors.New("resolver.global_resolve_qps must be >= 0")
	}
	if c.Resolver.L1CacheMaxEntries < 0 {
		return errors.New("resolver.l1_cache_max_entries must be >= 0")
	}
	if c.RateLimit.QPSPerIP != nil && *c.RateLimit.QPSPerIP < 0 {
		return errors.New("rate_limit.qps_per_ip must be >= 0 (0 = unlimited)")
	}
	if c.RateLimit.Burst != nil && *c.RateLimit.Burst < 0 {
		return errors.New("rate_limit.burst must be >= 0 (0 = unlimited burst when qps>0)")
	}
	if c.Redis.PoolSize < 1 {
		return errors.New("redis.pool_size must be >= 1")
	}
	if c.Redis.MinIdleConns < 0 {
		return errors.New("redis.min_idle_conns must be >= 0")
	}
	if c.Redis.MinIdleConns > c.Redis.PoolSize {
		return errors.New("redis.min_idle_conns must be <= redis.pool_size")
	}
	if c.Mapper.HTTPMaxIdleConns < 1 {
		return errors.New("mapper.http_max_idle_conns must be >= 1")
	}
	if c.Mapper.HTTPMaxIdleConnsPerHost < 1 {
		return errors.New("mapper.http_max_idle_conns_per_host must be >= 1")
	}
	return nil
}
