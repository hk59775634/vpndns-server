package ratelimit

import (
	"context"
	"hash/fnv"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// PerIP token bucket limiter per client IP (DNS + DoH).
// qps <= 0 disables limiting (Allow always true).
// qps > 0 and burst <= 0 uses a very large bucket (effectively unlimited burst).
type PerIP struct {
	shards    [shardCount]ipShard
	unlimited bool
	qps       rate.Limit
	burst     int
}

type ipShard struct {
	mu       sync.Mutex
	limiters map[string]*limEntry
}

const shardCount = 256

type limEntry struct {
	lim  *rate.Limiter
	last int64 // unix nano; accessed with atomic
}

const unlimitedBurst = 1 << 30 // fits int32; large enough for practical spikes

func shardIndex(ip string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ip))
	return int(h.Sum32() % shardCount)
}

func New(qps float64, burst int) *PerIP {
	if qps <= 0 {
		p := &PerIP{unlimited: true}
		for i := range p.shards {
			p.shards[i].limiters = make(map[string]*limEntry)
		}
		return p
	}
	b := burst
	if b <= 0 {
		b = unlimitedBurst
	}
	p := &PerIP{
		qps:   rate.Limit(qps),
		burst: b,
	}
	for i := range p.shards {
		p.shards[i].limiters = make(map[string]*limEntry)
	}
	return p
}

// Allow uses a per-IP token bucket; updates last-seen time for pruning.
func (p *PerIP) Allow(ip string) bool {
	if p.unlimited {
		return true
	}
	sh := &p.shards[shardIndex(ip)]
	sh.mu.Lock()
	e, ok := sh.limiters[ip]
	if !ok {
		e = &limEntry{lim: rate.NewLimiter(p.qps, p.burst)}
		sh.limiters[ip] = e
	}
	okb := e.lim.Allow()
	atomic.StoreInt64(&e.last, time.Now().UnixNano())
	sh.mu.Unlock()
	return okb
}

// Reload updates limits and drops per-IP limiter state so new rates apply immediately.
func (p *PerIP) Reload(qps float64, burst int) {
	if qps <= 0 {
		p.muLockAllShards()
		p.unlimited = true
		p.qps = 0
		p.burst = 0
		for i := range p.shards {
			p.shards[i].limiters = make(map[string]*limEntry)
		}
		p.muUnlockAllShards()
		return
	}
	b := burst
	if b <= 0 {
		b = unlimitedBurst
	} else if b > math.MaxInt32 {
		b = math.MaxInt32
	}
	p.muLockAllShards()
	p.unlimited = false
	p.qps = rate.Limit(qps)
	p.burst = b
	for i := range p.shards {
		p.shards[i].limiters = make(map[string]*limEntry)
	}
	p.muUnlockAllShards()
}

func (p *PerIP) muLockAllShards() {
	for i := range p.shards {
		p.shards[i].mu.Lock()
	}
}

func (p *PerIP) muUnlockAllShards() {
	for i := range p.shards {
		p.shards[i].mu.Unlock()
	}
}

// RunPruneLoop periodically removes limiter entries idle longer than maxIdle.
func (p *PerIP) RunPruneLoop(ctx context.Context, maxIdle time.Duration) {
	if maxIdle <= 0 {
		maxIdle = 20 * time.Minute
	}
	t := time.NewTicker(maxIdle / 2)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.prune(maxIdle)
		}
	}
}

func (p *PerIP) prune(maxIdle time.Duration) {
	if p.unlimited {
		return
	}
	cutoff := time.Now().Add(-maxIdle).UnixNano()
	for i := range p.shards {
		sh := &p.shards[i]
		sh.mu.Lock()
		for k, e := range sh.limiters {
			if atomic.LoadInt64(&e.last) < cutoff {
				delete(sh.limiters, k)
			}
		}
		sh.mu.Unlock()
	}
}
