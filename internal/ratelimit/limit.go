package ratelimit

import (
	"context"
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
	mu        sync.Mutex
	limiters  map[string]*limEntry
	unlimited bool
	qps       rate.Limit
	burst     int
}

type limEntry struct {
	lim  *rate.Limiter
	last int64 // unix nano; accessed with atomic
}

const unlimitedBurst = 1 << 30 // fits int32; large enough for practical spikes

func New(qps float64, burst int) *PerIP {
	if qps <= 0 {
		return &PerIP{
			unlimited: true,
			limiters:  make(map[string]*limEntry),
		}
	}
	b := burst
	if b <= 0 {
		b = unlimitedBurst
	}
	return &PerIP{
		limiters: make(map[string]*limEntry),
		qps:      rate.Limit(qps),
		burst:    b,
	}
}

// Allow uses a per-IP token bucket; updates last-seen time for pruning.
func (p *PerIP) Allow(ip string) bool {
	if p.unlimited {
		return true
	}
	p.mu.Lock()
	e, ok := p.limiters[ip]
	if !ok {
		e = &limEntry{lim: rate.NewLimiter(p.qps, p.burst)}
		p.limiters[ip] = e
	}
	okb := e.lim.Allow()
	atomic.StoreInt64(&e.last, time.Now().UnixNano())
	p.mu.Unlock()
	return okb
}

// Reload updates limits and drops per-IP limiter state so new rates apply immediately.
func (p *PerIP) Reload(qps float64, burst int) {
	p.mu.Lock()
	if qps <= 0 {
		p.unlimited = true
		p.qps = 0
		p.burst = 0
		p.limiters = make(map[string]*limEntry)
		p.mu.Unlock()
		return
	}
	p.unlimited = false
	p.qps = rate.Limit(qps)
	if burst <= 0 {
		p.burst = unlimitedBurst
	} else if burst > math.MaxInt32 {
		p.burst = math.MaxInt32
	} else {
		p.burst = burst
	}
	p.limiters = make(map[string]*limEntry)
	p.mu.Unlock()
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
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, e := range p.limiters {
		if atomic.LoadInt64(&e.last) < cutoff {
			delete(p.limiters, k)
		}
	}
}
