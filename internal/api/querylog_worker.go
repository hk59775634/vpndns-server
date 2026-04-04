package api

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vpndns/cdn/internal/resolver"
)

const (
	queryLogChanCap   = 16384
	queryLogBatchMax  = 512
	queryLogFlushTick = 50 * time.Millisecond
)

func (s *Server) startQueryLogDrainer() {
	go s.runQueryLogDrainer()
}

func (s *Server) runQueryLogDrainer() {
	batch := make([]resolver.LogRecord, 0, queryLogBatchMax)
	tick := time.NewTicker(queryLogFlushTick)
	defer tick.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.persistQueryLogBatch(batch)
		batch = batch[:0]
	}
	for {
		select {
		case r := <-s.logCh:
			batch = append(batch, r)
			if len(batch) >= queryLogBatchMax {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func (s *Server) persistQueryLogBatch(batch []resolver.LogRecord) {
	cfg := s.cfgStore.Get()
	max := 0
	key := "vpndns:querylog"
	if cfg != nil {
		max = cfg.QueryLog.MaxEntries
		if t := strings.TrimSpace(cfg.QueryLog.RedisKey); t != "" {
			key = t
		}
	}
	if max > 0 && s.rdb != nil {
		args := make([]interface{}, 0, len(batch))
		for i := range batch {
			b, err := json.Marshal(batch[i])
			if err != nil {
				continue
			}
			args = append(args, string(b))
		}
		if len(args) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		pipe := s.rdb.Pipeline()
		_ = pipe.RPush(ctx, key, args...)
		pipe.LTrim(ctx, key, int64(-max), -1)
		_, _ = pipe.Exec(ctx)
		return
	}
	s.logMu.Lock()
	s.memLogs = append(s.memLogs, batch...)
	if len(s.memLogs) > s.memLogMax {
		s.memLogs = s.memLogs[len(s.memLogs)-s.memLogMax:]
	}
	s.logMu.Unlock()
}

func (s *Server) enqueueQueryLog(r resolver.LogRecord) {
	select {
	case s.logCh <- r:
	default:
		atomic.AddUint64(&s.logDropped, 1)
	}
}
