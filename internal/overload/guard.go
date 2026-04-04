package overload

import (
	"context"
	"sync"

	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"
)

// Guard limits global resolve rate and concurrent upstream queries.
type Guard struct {
	mu sync.RWMutex

	sem *semaphore.Weighted // upstream inflight; nil = unlimited
	lim *rate.Limiter       // global resolve QPS; nil = disabled
}

// NewGuard returns a guard with limits applied via Reload.
func NewGuard() *Guard {
	return &Guard{}
}

// Reload replaces limits (safe at runtime).
func (g *Guard) Reload(maxInflight int64, globalQPS float64, globalBurst int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if maxInflight > 0 {
		g.sem = semaphore.NewWeighted(maxInflight)
	} else {
		g.sem = nil
	}
	if globalQPS > 0 && globalBurst > 0 {
		g.lim = rate.NewLimiter(rate.Limit(globalQPS), globalBurst)
	} else {
		g.lim = nil
	}
}

// AllowGlobal returns false when global resolve QPS bucket is empty.
func (g *Guard) AllowGlobal() bool {
	g.mu.RLock()
	lim := g.lim
	g.mu.RUnlock()
	if lim == nil {
		return true
	}
	return lim.Allow()
}

// AcquireUpstream blocks until a upstream slot is available or ctx is done.
func (g *Guard) AcquireUpstream(ctx context.Context) (release func(), err error) {
	g.mu.RLock()
	sem := g.sem
	g.mu.RUnlock()
	if sem == nil {
		return func() {}, nil
	}
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	return func() { sem.Release(1) }, nil
}
