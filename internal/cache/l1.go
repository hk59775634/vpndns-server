package cache

import (
	"encoding/base64"
	"hash/fnv"
	"sync"
	"time"

	"github.com/vpndns/cdn/internal/models"
)

const l1ShardCount = 64

// L1 is a small process-local cache in front of Redis (same wire encoding as Redis values).
type L1 struct {
	maxPerShard int
	ttlCap      time.Duration
	shards      [l1ShardCount]l1Shard
}

type l1Shard struct {
	mu sync.RWMutex
	m  map[string]l1Entry
}

type l1Entry struct {
	enc     string
	expUnix int64
	minTTL  uint32
}

// NewL1 returns nil if maxEntries <= 0.
func NewL1(maxEntries int, ttlCapSec int) *L1 {
	if maxEntries <= 0 {
		return nil
	}
	per := maxEntries / l1ShardCount
	if per < 64 {
		per = 64
	}
	l := &L1{
		maxPerShard: per,
		ttlCap:      time.Duration(ttlCapSec) * time.Second,
	}
	for i := range l.shards {
		l.shards[i].m = make(map[string]l1Entry, per)
	}
	return l
}

func (l *L1) shard(key string) *l1Shard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &l.shards[h.Sum32()%l1ShardCount]
}

// Get returns a cached response if present and not expired.
func (l *L1) Get(key string) (*models.DNSResponse, bool) {
	if l == nil {
		return nil, false
	}
	sh := l.shard(key)
	now := time.Now().Unix()
	sh.mu.RLock()
	e, ok := sh.m[key]
	sh.mu.RUnlock()
	if !ok || e.expUnix <= now {
		return nil, false
	}
	msg, err := DecodeStoredDNS(e.enc)
	if err != nil || msg == nil {
		return nil, false
	}
	return &models.DNSResponse{Msg: msg, MinTTL: e.minTTL}, true
}

// Set stores a copy of the response with TTL capped by L1 ttlCap.
func (l *L1) Set(key string, resp *models.DNSResponse, ttlSeconds int) {
	if l == nil || resp == nil || resp.Msg == nil {
		return
	}
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttl <= 0 {
		ttl = l.ttlCap
	}
	if ttl > l.ttlCap {
		ttl = l.ttlCap
	}
	if ttl <= 0 {
		return
	}
	packed, err := resp.Msg.Pack()
	if err != nil {
		return
	}
	enc := base64.StdEncoding.EncodeToString(packed)
	exp := time.Now().Add(ttl).Unix()
	minTTL := models.MinAnswerTTL(resp.Msg, 300)

	sh := l.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if len(sh.m) >= l.maxPerShard {
		for k := range sh.m {
			delete(sh.m, k)
			break
		}
	}
	sh.m[key] = l1Entry{enc: enc, expUnix: exp, minTTL: minTTL}
}
