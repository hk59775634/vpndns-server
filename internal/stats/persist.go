package stats

import (
	"context"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const defaultRedisKey = "vpndns:stats:counters"

// Restore merges Redis HASH into in-memory counters (additive baseline at startup).
func (c *Collector) Restore(ctx context.Context, rdb *redis.Client, key string) {
	if rdb == nil || key == "" {
		return
	}
	m, err := rdb.HGetAll(ctx, key).Result()
	if err != nil || len(m) == 0 {
		return
	}
	load := func(s string, dst *uint64) {
		if s == "" {
			return
		}
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return
		}
		atomic.StoreUint64(dst, v)
	}
	load(m["dns_queries"], &c.queries)
	load(m["rate_limited"], &c.rateLimited)
	load(m["malformed"], &c.malformed)
	load(m["doh_unauthorized"], &c.dohUnauthorized)
	load(m["overload_rejected"], &c.overloadRejected)
	load(m["logged"], &c.logged)
	load(m["blocked_blacklist"], &c.blockedBlacklist)
	load(m["blocked_whitelist"], &c.blockedWhitelist)
	load(m["cache_hits"], &c.cacheHits)
	load(m["resolved_cn"], &c.resolvedCN)
	load(m["resolved_out"], &c.resolvedOUT)
	load(m["errors"], &c.errors)
	load(m["latency_sum_ms"], &c.latencySumMs)
	load(m["latency_samples"], &c.latencySampleCount)
}

// Persist writes current counters to Redis.
func (c *Collector) Persist(ctx context.Context, rdb *redis.Client, key string) error {
	if rdb == nil || key == "" {
		return nil
	}
	return rdb.HSet(ctx, key,
		"dns_queries", strconv.FormatUint(atomic.LoadUint64(&c.queries), 10),
		"rate_limited", strconv.FormatUint(atomic.LoadUint64(&c.rateLimited), 10),
		"malformed", strconv.FormatUint(atomic.LoadUint64(&c.malformed), 10),
		"doh_unauthorized", strconv.FormatUint(atomic.LoadUint64(&c.dohUnauthorized), 10),
		"overload_rejected", strconv.FormatUint(atomic.LoadUint64(&c.overloadRejected), 10),
		"logged", strconv.FormatUint(atomic.LoadUint64(&c.logged), 10),
		"blocked_blacklist", strconv.FormatUint(atomic.LoadUint64(&c.blockedBlacklist), 10),
		"blocked_whitelist", strconv.FormatUint(atomic.LoadUint64(&c.blockedWhitelist), 10),
		"cache_hits", strconv.FormatUint(atomic.LoadUint64(&c.cacheHits), 10),
		"resolved_cn", strconv.FormatUint(atomic.LoadUint64(&c.resolvedCN), 10),
		"resolved_out", strconv.FormatUint(atomic.LoadUint64(&c.resolvedOUT), 10),
		"errors", strconv.FormatUint(atomic.LoadUint64(&c.errors), 10),
		"latency_sum_ms", strconv.FormatUint(atomic.LoadUint64(&c.latencySumMs), 10),
		"latency_samples", strconv.FormatUint(atomic.LoadUint64(&c.latencySampleCount), 10),
		"saved_at", strconv.FormatInt(time.Now().Unix(), 10),
	).Err()
}

// RunPersistLoop writes stats every interval until ctx done.
func (c *Collector) RunPersistLoop(ctx context.Context, rdb *redis.Client, key string, every time.Duration) {
	if rdb == nil || every <= 0 {
		return
	}
	if key == "" {
		key = defaultRedisKey
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = c.Persist(context.Background(), rdb, key)
			return
		case <-t.C:
			_ = c.Persist(ctx, rdb, key)
		}
	}
}
