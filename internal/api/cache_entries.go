package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/vpndns/cdn/internal/cache"
	"github.com/vpndns/cdn/internal/querylog"
)

type cacheEntryDTO struct {
	Key         string  `json:"key"`
	TTLSeconds  float64 `json:"ttl_seconds"` // Redis: -2 missing, -1 no expiry, else remaining seconds
	Summary     string  `json:"summary"`
	ValueLength int     `json:"value_length"` // base64 payload length (chars)
}

type cacheListResponse struct {
	Total   int             `json:"total"`
	Page    int             `json:"page"`
	PerPage int             `json:"per_page"`
	Entries []cacheEntryDTO `json:"entries"`
}

func (s *Server) listCacheEntries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pat := r.URL.Query().Get("pattern")
	if pat == "" {
		pat = "dns:*"
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	switch per {
	case 20, 50, 100, 500:
	default:
		per = 20
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	keys, err := s.rc.ScanKeysSorted(ctx, pat)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	total := len(keys)
	start := (page - 1) * per
	if start > total {
		start = total
	}
	end := start + per
	if end > total {
		end = total
	}

	entries := make([]cacheEntryDTO, 0, end-start)
	for _, k := range keys[start:end] {
		row := cacheEntryDTO{Key: k}
		sVal, err := s.rdb.Get(ctx, k).Result()
		if err != nil {
			row.TTLSeconds = -2
			row.Summary = "（键不存在或已过期）"
			entries = append(entries, row)
			continue
		}
		row.ValueLength = len(sVal)
		ttl, err := s.rdb.TTL(ctx, k).Result()
		if err != nil {
			row.TTLSeconds = -2
		} else {
			row.TTLSeconds = ttl.Seconds()
		}
		msg, derr := cache.DecodeStoredDNS(sVal)
		if derr != nil || msg == nil {
			row.Summary = "（无法解码缓存值）"
		} else {
			row.Summary = querylog.AnswerSummary(msg)
		}
		entries = append(entries, row)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cacheListResponse{
		Total:   total,
		Page:    page,
		PerPage: per,
		Entries: entries,
	})
}
