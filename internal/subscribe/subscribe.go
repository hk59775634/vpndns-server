package subscribe

import (
	"bufio"
	"context"
	"io"
	"time"

	"github.com/redis/go-redis/v9"
)

// RunWhitelistPull periodically fetches line-based domain lists into Redis.
func RunWhitelistPull(ctx context.Context, rdb *redis.Client, urls []string, every time.Duration) {
	if len(urls) == 0 || rdb == nil {
		return
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	do := func() {
		PullAll(context.Background(), rdb, urls)
	}
	do()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			do()
		}
	}
}

func readPatterns(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	const maxLine = 1024 * 1024
	buf := make([]byte, maxLine)
	sc.Buffer(buf, maxLine)
	for sc.Scan() {
		if p, ok := parseSubscribeLine(sc.Text()); ok {
			out = append(out, p)
		}
	}
	return out, sc.Err()
}
