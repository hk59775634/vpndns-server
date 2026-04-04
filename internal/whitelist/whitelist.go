package whitelist

import (
	"context"
	"strings"
	"sync"

	"github.com/redis/go-redis/v9"
)

const redisSetKey = "whitelist:set"

// Matcher supports exact and *.suffix patterns (stored in Redis set).
type Matcher struct {
	rdb   *redis.Client
	mu    sync.RWMutex
	rules []string
}

func New(rdb *redis.Client) *Matcher {
	return &Matcher{rdb: rdb}
}

// LoadFromRedis refreshes local trie cache from Redis SET.
func (m *Matcher) LoadFromRedis(ctx context.Context) error {
	if m.rdb == nil {
		return nil
	}
	mem, err := m.rdb.SMembers(ctx, redisSetKey).Result()
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.rules = append([]string(nil), mem...)
	m.mu.Unlock()
	return nil
}

// Allowed returns true if domain is allowed for OUT resolution.
func (m *Matcher) Allowed(domain string) bool {
	d := strings.TrimSuffix(strings.ToLower(domain), ".")
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, rule := range m.rules {
		r := strings.TrimSpace(strings.ToLower(rule))
		if r == "" {
			continue
		}
		if strings.HasPrefix(r, "*.") {
			suffix := strings.TrimPrefix(r, "*.")
			if d == suffix {
				return true
			}
			if strings.HasSuffix(d, "."+suffix) {
				return true
			}
			continue
		}
		if d == r {
			return true
		}
	}
	return false
}

// AddToRedis adds patterns to the whitelist set.
func AddToRedis(ctx context.Context, rdb *redis.Client, patterns ...string) error {
	if rdb == nil || len(patterns) == 0 {
		return nil
	}
	args := make([]interface{}, len(patterns))
	for i, p := range patterns {
		args[i] = strings.TrimSpace(strings.ToLower(p))
	}
	return rdb.SAdd(ctx, redisSetKey, args...).Err()
}

// AddToRedisCount adds patterns and returns how many were new members of the set.
func AddToRedisCount(ctx context.Context, rdb *redis.Client, patterns ...string) (int64, error) {
	if rdb == nil || len(patterns) == 0 {
		return 0, nil
	}
	args := make([]interface{}, len(patterns))
	for i, p := range patterns {
		args[i] = strings.TrimSpace(strings.ToLower(p))
	}
	return rdb.SAdd(ctx, redisSetKey, args...).Result()
}

// RemoveFromRedis removes patterns.
func RemoveFromRedis(ctx context.Context, rdb *redis.Client, patterns ...string) error {
	if rdb == nil || len(patterns) == 0 {
		return nil
	}
	args := make([]interface{}, len(patterns))
	for i, p := range patterns {
		args[i] = strings.TrimSpace(strings.ToLower(p))
	}
	return rdb.SRem(ctx, redisSetKey, args...).Err()
}

// RemoveBySubstring removes every set member whose string contains substr (case-insensitive).
// Returns how many members were removed.
func RemoveBySubstring(ctx context.Context, rdb *redis.Client, substr string) (int64, error) {
	substr = strings.TrimSpace(substr)
	if rdb == nil || substr == "" {
		return 0, nil
	}
	sublow := strings.ToLower(substr)
	mem, err := rdb.SMembers(ctx, redisSetKey).Result()
	if err != nil {
		return 0, err
	}
	var rem []string
	for _, p := range mem {
		if strings.Contains(strings.ToLower(p), sublow) {
			rem = append(rem, p)
		}
	}
	if len(rem) == 0 {
		return 0, nil
	}
	if err := RemoveFromRedis(ctx, rdb, rem...); err != nil {
		return 0, err
	}
	return int64(len(rem)), nil
}

// ClearRedis deletes the entire whitelist set in Redis. Returns how many members existed before delete.
func ClearRedis(ctx context.Context, rdb *redis.Client) (removed int64, err error) {
	if rdb == nil {
		return 0, nil
	}
	n, err := rdb.SCard(ctx, redisSetKey).Result()
	if err != nil {
		return 0, err
	}
	if err := rdb.Del(ctx, redisSetKey).Err(); err != nil {
		return 0, err
	}
	return n, nil
}

// RedisKey exposes the set key for admin API.
func RedisKey() string { return redisSetKey }
