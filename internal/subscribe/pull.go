package subscribe

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/vpndns/cdn/internal/whitelist"
)

// PullReport is the result of an immediate subscription fetch (for API / UI).
type PullReport struct {
	URLsTried      int    `json:"urls_tried"`
	URLsOK         int    `json:"urls_ok"`
	PatternsParsed int64  `json:"patterns_parsed"`
	PatternsAdded  int64  `json:"patterns_added"`
	TotalInSet     int64  `json:"total_in_set"`
	LastError      string `json:"last_error,omitempty"`
}

// PullNow fetches all subscribe URLs, parses rules, merges into Redis, and returns counts.
func PullNow(ctx context.Context, rdb *redis.Client, urls []string) PullReport {
	var rep PullReport
	if rdb == nil {
		rep.LastError = "redis unavailable"
		return rep
	}
	client := &http.Client{Timeout: 120 * time.Second}
	for _, raw := range urls {
		u := strings.TrimSpace(raw)
		if u == "" {
			continue
		}
		rep.URLsTried++
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			if rep.LastError == "" {
				rep.LastError = err.Error()
			}
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			if rep.LastError == "" {
				rep.LastError = err.Error()
			}
			continue
		}
		func() {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				if rep.LastError == "" {
					rep.LastError = fmt.Sprintf("%s: HTTP %d", u, resp.StatusCode)
				}
				return
			}
			patterns, err := readPatterns(resp.Body)
			if err != nil {
				if rep.LastError == "" {
					rep.LastError = err.Error()
				}
				return
			}
			rep.URLsOK++
			rep.PatternsParsed += int64(len(patterns))
			if len(patterns) == 0 {
				return
			}
			added, err := whitelist.AddToRedisCount(ctx, rdb, patterns...)
			if err != nil {
				if rep.LastError == "" {
					rep.LastError = err.Error()
				}
				return
			}
			rep.PatternsAdded += added
		}()
	}
	if n, err := rdb.SCard(ctx, whitelist.RedisKey()).Result(); err == nil {
		rep.TotalInSet = n
	}
	return rep
}

// PullAll is used by the background ticker (discards structured report).
func PullAll(ctx context.Context, rdb *redis.Client, urls []string) {
	_ = PullNow(ctx, rdb, urls)
}
