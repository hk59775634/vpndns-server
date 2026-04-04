package stats

import (
	"sync/atomic"
	"time"

	"github.com/vpndns/cdn/internal/resolver"
)

// Collector holds DNS/DoH counters (lock-free hot path).
type Collector struct {
	start time.Time

	queries          uint64 // 有效 DNS 问题且已通过限速，进入业务处理
	rateLimited      uint64
	malformed        uint64
	dohUnauthorized  uint64
	overloadRejected uint64

	logged             uint64
	blockedBlacklist   uint64
	blockedWhitelist   uint64
	cacheHits          uint64
	resolvedCN         uint64
	resolvedOUT        uint64
	errors             uint64
	latencySumMs       uint64
	latencySampleCount uint64
}

// Snapshot is returned by the admin API (JSON).
type Snapshot struct {
	UptimeSeconds int64 `json:"uptime_seconds"`

	DNSQueries uint64 `json:"dns_queries"`

	BlockedBlacklist uint64 `json:"blocked_blacklist"`
	BlockedWhitelist uint64 `json:"blocked_whitelist"`
	BlockedPolicy    uint64 `json:"blocked_policy"` // 黑名单 + 非白名单

	RateLimited      uint64 `json:"rate_limited"`
	Malformed        uint64 `json:"malformed"`
	DoHAuthFail      uint64 `json:"doh_auth_fail"`
	OverloadRejected uint64 `json:"overload_rejected"`

	CacheHits   uint64 `json:"cache_hits"`
	ResolvedCN  uint64 `json:"resolved_cn"`
	ResolvedOUT uint64 `json:"resolved_out"`
	Errors      uint64 `json:"errors"`

	LoggedRows     uint64  `json:"logged_rows"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
	PercentBlocked float64 `json:"percent_blocked"` // 相对 dns_queries 的策略拦截比例
}

// New creates a collector with process start time for uptime.
func New() *Collector {
	return &Collector{start: time.Now()}
}

func (c *Collector) RecordDNSQuery() {
	atomic.AddUint64(&c.queries, 1)
}

func (c *Collector) RecordRateLimited() {
	atomic.AddUint64(&c.rateLimited, 1)
}

func (c *Collector) RecordMalformed() {
	atomic.AddUint64(&c.malformed, 1)
}

func (c *Collector) RecordDoHUnauthorized() {
	atomic.AddUint64(&c.dohUnauthorized, 1)
}

func (c *Collector) RecordOverload() {
	atomic.AddUint64(&c.overloadRejected, 1)
}

// RecordLog updates breakdown from one query log row (after handling completes).
func (c *Collector) RecordLog(r resolver.LogRecord) {
	atomic.AddUint64(&c.logged, 1)
	atomic.AddUint64(&c.latencySumMs, uint64(r.LatencyMS))
	atomic.AddUint64(&c.latencySampleCount, 1)

	switch r.Route {
	case "黑名单":
		atomic.AddUint64(&c.blockedBlacklist, 1)
	case "非白名单":
		atomic.AddUint64(&c.blockedWhitelist, 1)
	case "缓存":
		atomic.AddUint64(&c.cacheHits, 1)
	case "国内":
		atomic.AddUint64(&c.resolvedCN, 1)
	case "海外":
		atomic.AddUint64(&c.resolvedOUT, 1)
	case "错误", "过载":
		atomic.AddUint64(&c.errors, 1)
	}
}

// Reset zeros all counters and restarts uptime from now (dashboard / Prometheus gauges).
func (c *Collector) Reset() {
	if c == nil {
		return
	}
	c.start = time.Now()
	atomic.StoreUint64(&c.queries, 0)
	atomic.StoreUint64(&c.rateLimited, 0)
	atomic.StoreUint64(&c.malformed, 0)
	atomic.StoreUint64(&c.dohUnauthorized, 0)
	atomic.StoreUint64(&c.overloadRejected, 0)
	atomic.StoreUint64(&c.logged, 0)
	atomic.StoreUint64(&c.blockedBlacklist, 0)
	atomic.StoreUint64(&c.blockedWhitelist, 0)
	atomic.StoreUint64(&c.cacheHits, 0)
	atomic.StoreUint64(&c.resolvedCN, 0)
	atomic.StoreUint64(&c.resolvedOUT, 0)
	atomic.StoreUint64(&c.errors, 0)
	atomic.StoreUint64(&c.latencySumMs, 0)
	atomic.StoreUint64(&c.latencySampleCount, 0)
}

// Read returns a point-in-time snapshot for JSON.
func (c *Collector) Read() Snapshot {
	q := atomic.LoadUint64(&c.queries)
	bl := atomic.LoadUint64(&c.blockedBlacklist)
	wl := atomic.LoadUint64(&c.blockedWhitelist)
	policy := bl + wl

	var avg float64
	n := atomic.LoadUint64(&c.latencySampleCount)
	if n > 0 {
		avg = float64(atomic.LoadUint64(&c.latencySumMs)) / float64(n)
	}

	var pctBlocked float64
	if q > 0 {
		pctBlocked = float64(policy) * 100 / float64(q)
	}

	return Snapshot{
		UptimeSeconds: int64(time.Since(c.start).Seconds()),

		DNSQueries: q,

		BlockedBlacklist: bl,
		BlockedWhitelist: wl,
		BlockedPolicy:    policy,

		RateLimited:      atomic.LoadUint64(&c.rateLimited),
		Malformed:        atomic.LoadUint64(&c.malformed),
		DoHAuthFail:      atomic.LoadUint64(&c.dohUnauthorized),
		OverloadRejected: atomic.LoadUint64(&c.overloadRejected),

		CacheHits:   atomic.LoadUint64(&c.cacheHits),
		ResolvedCN:  atomic.LoadUint64(&c.resolvedCN),
		ResolvedOUT: atomic.LoadUint64(&c.resolvedOUT),
		Errors:      atomic.LoadUint64(&c.errors),

		LoggedRows:     atomic.LoadUint64(&c.logged),
		AvgLatencyMs:   avg,
		PercentBlocked: pctBlocked,
	}
}
