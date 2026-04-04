package cache

import (
	"context"
	"encoding/base64"
	"sort"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"

	"github.com/vpndns/cdn/internal/models"
)

// Redis implements Cache backed by Redis.
type Redis struct {
	rdb *redis.Client
}

func NewRedis(rdb *redis.Client) *Redis {
	return &Redis{rdb: rdb}
}

// DecodeStoredDNS decodes a base64-wired DNS message as stored in Redis cache values.
func DecodeStoredDNS(encoded string) (*dns.Msg, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return nil, err
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(raw); err != nil {
		return nil, err
	}
	return msg, nil
}

func (c *Redis) Get(ctx context.Context, key string) (*models.DNSResponse, bool) {
	s, err := c.rdb.Get(ctx, key).Result()
	if err == redis.Nil || err != nil {
		return nil, false
	}
	msg, err := DecodeStoredDNS(s)
	if err != nil || msg == nil {
		return nil, false
	}
	return &models.DNSResponse{Msg: msg, MinTTL: models.MinAnswerTTL(msg, 300)}, true
}

func (c *Redis) Set(ctx context.Context, key string, resp *models.DNSResponse, ttlSeconds int) error {
	if resp == nil || resp.Msg == nil {
		return nil
	}
	packed, err := resp.Msg.Pack()
	if err != nil {
		return err
	}
	enc := base64.StdEncoding.EncodeToString(packed)
	return c.rdb.Set(ctx, key, enc, time.Duration(ttlSeconds)*time.Second).Err()
}

func (c *Redis) Del(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	return c.rdb.Del(ctx, keys...).Err()
}

func (c *Redis) Keys(ctx context.Context, pattern string) ([]string, error) {
	return c.rdb.Keys(ctx, pattern).Result()
}

// ScanKeysSorted returns all keys matching pattern using SCAN (non-blocking), sorted lexicographically.
func (c *Redis) ScanKeysSorted(ctx context.Context, pattern string) ([]string, error) {
	var all []string
	var cur uint64
	for {
		keys, next, err := c.rdb.Scan(ctx, cur, pattern, 512).Result()
		if err != nil {
			return nil, err
		}
		all = append(all, keys...)
		cur = next
		if cur == 0 {
			break
		}
	}
	sort.Strings(all)
	return all, nil
}
