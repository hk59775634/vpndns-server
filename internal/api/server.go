package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/vpndns/cdn/internal/cache"
	"github.com/vpndns/cdn/internal/config"
	"github.com/vpndns/cdn/internal/geoip"
	"github.com/vpndns/cdn/internal/resolver"
	"github.com/vpndns/cdn/internal/stats"
	"github.com/vpndns/cdn/internal/subscribe"
	"github.com/vpndns/cdn/internal/upstream"
	"github.com/vpndns/cdn/internal/whitelist"
)

// Server exposes REST for the control plane.
type Server struct {
	cfgPath       string
	cfgStore      *config.Store
	sessionSecret string
	rdb           *redis.Client
	rc            *cache.Redis
	wl            *whitelist.Matcher
	cn            *geoip.CN
	pool          *upstream.Pool
	applyRuntime  func(*config.Config)
	st            *stats.Collector
	logCh         chan resolver.LogRecord
	logDropped    uint64 // async queue overflow; atomic
	logMu         sync.Mutex
	memLogs       []resolver.LogRecord
	memLogMax     int
}

func New(cfgPath string, cfg *config.Store, rdb *redis.Client, rc *cache.Redis, wl *whitelist.Matcher, cn *geoip.CN, pool *upstream.Pool, applyRuntime func(*config.Config), st *stats.Collector) *Server {
	s := &Server{
		cfgPath:       cfgPath,
		cfgStore:      cfg,
		sessionSecret: newSessionSecret(cfg.Get()),
		rdb:           rdb,
		rc:            rc,
		wl:            wl,
		cn:            cn,
		pool:          pool,
		applyRuntime:  applyRuntime,
		st:            st,
		logCh:         make(chan resolver.LogRecord, queryLogChanCap),
		memLogMax:     500,
	}
	s.startQueryLogDrainer()
	return s
}

func (s *Server) PushLog(r resolver.LogRecord) {
	if s.st != nil {
		s.st.RecordLog(r)
	}
	s.enqueueQueryLog(r)
}

// SyncSessionSecretFromConfig updates the signing key from the current config or VPNDNS_SESSION_SECRET.
// Call after hot-reload so explicit session_secret in YAML takes effect without restart.
func (s *Server) SyncSessionSecretFromConfig() {
	c := s.cfgStore.Get()
	if c == nil {
		return
	}
	if sec := strings.TrimSpace(c.Admin.SessionSecret); sec != "" {
		s.sessionSecret = sec
		return
	}
	if sec := strings.TrimSpace(os.Getenv("VPNDNS_SESSION_SECRET")); sec != "" {
		s.sessionSecret = sec
	}
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.sessionUser(r) != "" {
			next.ServeHTTP(w, r)
			return
		}
		key := strings.TrimSpace(s.cfgStore.Get().Admin.APIKey)
		if key != "" && r.Header.Get("X-API-Key") == key {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func (s *Server) Handler(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/auth/login", s.handleAuthLogin)
	mux.HandleFunc("/api/v1/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("/api/v1/auth/me", s.handleAuthMe)
	mux.Handle("/api/v1/auth/password", s.auth(http.HandlerFunc(s.handleAuthPassword)))
	mux.Handle("/api/v1/", s.auth(http.HandlerFunc(s.handleAPI)))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	switch {
	case p == "whitelist" && r.Method == http.MethodGet:
		s.listWhitelist(w, r)
	case p == "whitelist" && r.Method == http.MethodPost:
		s.addWhitelist(w, r)
	case p == "whitelist" && r.Method == http.MethodDelete:
		s.delWhitelist(w, r)
	case p == "whitelist/stats" && r.Method == http.MethodGet:
		s.whitelistStats(w, r)
	case p == "whitelist/subscribe/pull" && r.Method == http.MethodPost:
		s.whitelistSubscribePull(w, r)
	case p == "cache/entries" && r.Method == http.MethodGet:
		s.listCacheEntries(w, r)
	case p == "cache" && r.Method == http.MethodDelete:
		s.flushCache(w, r)
	case p == "logs" && r.Method == http.MethodGet:
		s.getLogs(w, r)
	case p == "logs" && r.Method == http.MethodDelete:
		s.clearLogs(w, r)
	case p == "stats/reset" && r.Method == http.MethodPost:
		s.resetStats(w, r)
	case p == "stats" && r.Method == http.MethodGet:
		s.getStats(w, r)
	case p == "meta" && r.Method == http.MethodGet:
		s.getMeta(w, r)
	case p == "config" && r.Method == http.MethodGet:
		s.getConfig(w, r)
	case p == "config" && r.Method == http.MethodPut:
		s.putConfig(w, r)
	case p == "config/reload" && r.Method == http.MethodPost:
		s.reloadConfig(w, r)
	case p == "geoip/cidrs" && r.Method == http.MethodGet:
		s.listGeoIPCIDRs(w, r)
	case p == "geoip/refresh" && r.Method == http.MethodPost:
		s.refreshGeo(w, r)
	default:
		http.NotFound(w, r)
	}
}

type wlBody struct {
	Patterns []string `json:"patterns"`
	Query    string   `json:"query"` // optional: delete all members containing this substring (case-insensitive)
	All      bool     `json:"all"`   // optional: delete entire whitelist set (mutually exclusive with query/patterns)
}

type whitelistListResponse struct {
	TotalInSet   int      `json:"total_in_set"`
	TotalMatched int      `json:"total_matched"`
	Page         int      `json:"page"`
	PerPage      int      `json:"per_page"`
	Patterns     []string `json:"patterns"`
}

func (s *Server) listWhitelist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mem, err := s.rdb.SMembers(ctx, whitelist.RedisKey()).Result()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sort.Strings(mem)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	qlow := strings.ToLower(q)
	var matched []string
	if qlow == "" {
		matched = mem
	} else {
		for _, p := range mem {
			if strings.Contains(strings.ToLower(p), qlow) {
				matched = append(matched, p)
			}
		}
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if per != 20 {
		per = 20
	}
	totalInSet := len(mem)
	totalMatched := len(matched)
	start := (page - 1) * per
	if start > totalMatched {
		start = totalMatched
	}
	end := start + per
	if end > totalMatched {
		end = totalMatched
	}
	var pageSlice []string
	if start < end {
		pageSlice = matched[start:end]
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(whitelistListResponse{
		TotalInSet:   totalInSet,
		TotalMatched: totalMatched,
		Page:         page,
		PerPage:      per,
		Patterns:     pageSlice,
	})
}

func (s *Server) addWhitelist(w http.ResponseWriter, r *http.Request) {
	var b wlBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := whitelist.AddToRedis(r.Context(), s.rdb, b.Patterns...); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.wl.LoadFromRedis(context.Background())
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) whitelistStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	n, err := s.rdb.SCard(ctx, whitelist.RedisKey()).Result()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int64{"count": n})
}

func (s *Server) whitelistSubscribePull(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	cfg := s.cfgStore.Get()
	urls := cfg.Whitelist.SubscribeURLs
	rep := subscribe.PullNow(ctx, s.rdb, urls)
	_ = s.wl.LoadFromRedis(ctx)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rep)
}

func (s *Server) delWhitelist(w http.ResponseWriter, r *http.Request) {
	var b wlBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if b.All {
		q := strings.TrimSpace(b.Query)
		if q != "" || len(b.Patterns) > 0 {
			http.Error(w, "all=true cannot be combined with query or patterns", http.StatusBadRequest)
			return
		}
		n, err := whitelist.ClearRedis(r.Context(), s.rdb)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = s.wl.LoadFromRedis(context.Background())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int64{"removed": n})
		return
	}
	q := strings.TrimSpace(b.Query)
	if q != "" && len(b.Patterns) > 0 {
		http.Error(w, "use either query or patterns, not both", http.StatusBadRequest)
		return
	}
	if q != "" {
		n, err := whitelist.RemoveBySubstring(r.Context(), s.rdb, q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = s.wl.LoadFromRedis(context.Background())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int64{"removed": n})
		return
	}
	if len(b.Patterns) == 0 {
		http.Error(w, "patterns or query required", http.StatusBadRequest)
		return
	}
	if err := whitelist.RemoveFromRedis(r.Context(), s.rdb, b.Patterns...); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.wl.LoadFromRedis(context.Background())
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) flushCache(w http.ResponseWriter, r *http.Request) {
	pat := r.URL.Query().Get("pattern")
	if pat == "" {
		pat = "dns:*"
	}
	keys, err := s.rc.Keys(r.Context(), pat)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(keys) > 0 {
		if err := s.rc.Del(r.Context(), keys...); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"deleted": len(keys)})
}

type logsListResponse struct {
	TotalAll   int                  `json:"total_all"`
	Total      int                  `json:"total"`
	HasFilters bool                 `json:"has_filters"`
	Page       int                  `json:"page"`
	PerPage    int                  `json:"per_page"`
	Entries    []resolver.LogRecord `json:"entries"`
}

func (s *Server) getLogs(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	switch per {
	case 20, 50, 100:
	default:
		per = 20
	}
	domainQ := r.URL.Query().Get("domain")
	vipQ := r.URL.Query().Get("vip")
	realQ := r.URL.Query().Get("real_ip")
	freeQ := r.URL.Query().Get("q")
	hasFilters := logFilterActive(domainQ, vipQ, realQ, freeQ)

	cfg := s.cfgStore.Get()
	max := 0
	key := ""
	if cfg != nil {
		max = cfg.QueryLog.MaxEntries
		key = strings.TrimSpace(cfg.QueryLog.RedisKey)
	}
	if key == "" {
		key = "vpndns:querylog"
	}

	var out []resolver.LogRecord
	if max > 0 && s.rdb != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		vals, err := s.rdb.LRange(ctx, key, 0, -1).Result()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out = make([]resolver.LogRecord, 0, len(vals))
		for _, v := range vals {
			var rec resolver.LogRecord
			if json.Unmarshal([]byte(v), &rec) == nil {
				out = append(out, rec)
			}
		}
	} else {
		s.logMu.Lock()
		out = append([]resolver.LogRecord(nil), s.memLogs...)
		s.logMu.Unlock()
	}

	totalAll := len(out)
	filtered := out
	if hasFilters {
		tmp := make([]resolver.LogRecord, 0)
		for i := range out {
			if logMatchesQuery(&out[i], domainQ, vipQ, realQ, freeQ) {
				tmp = append(tmp, out[i])
			}
		}
		filtered = tmp
	}

	// filtered: chronological oldest → newest. UI shows newest first; page 1 = latest among filtered.
	total := len(filtered)
	start := (page - 1) * per
	var pageSlice []resolver.LogRecord
	if start < total {
		end := start + per
		if end > total {
			end = total
		}
		pageSlice = make([]resolver.LogRecord, 0, end-start)
		for k := start; k < end; k++ {
			pageSlice = append(pageSlice, filtered[total-1-k])
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(logsListResponse{
		TotalAll:   totalAll,
		Total:      total,
		HasFilters: hasFilters,
		Page:       page,
		PerPage:    per,
		Entries:    pageSlice,
	})
}

func (s *Server) clearLogs(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgStore.Get()
	max := 0
	key := ""
	if cfg != nil {
		max = cfg.QueryLog.MaxEntries
		key = strings.TrimSpace(cfg.QueryLog.RedisKey)
	}
	if key == "" {
		key = "vpndns:querylog"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if max > 0 && s.rdb != nil {
		if err := s.rdb.Del(ctx, key).Err(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		s.logMu.Lock()
		s.memLogs = nil
		s.logMu.Unlock()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
}

func (s *Server) resetStats(w http.ResponseWriter, r *http.Request) {
	if s.st != nil {
		s.st.Reset()
	}
	atomic.StoreUint64(&s.logDropped, 0)
	cfg := s.cfgStore.Get()
	statsKey := ""
	if cfg != nil {
		statsKey = strings.TrimSpace(cfg.Stats.RedisKey)
	}
	if statsKey == "" {
		statsKey = "vpndns:stats:counters"
	}
	if s.rdb != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		_ = s.rdb.Del(ctx, statsKey).Err()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "reset"})
}

func (s *Server) getStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.st == nil {
		_ = json.NewEncoder(w).Encode(stats.Snapshot{})
		return
	}
	_ = json.NewEncoder(w).Encode(s.st.Read())
}

func (s *Server) getMeta(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgStore.Get()
	if cfg == nil {
		http.Error(w, "no config", http.StatusInternalServerError)
		return
	}
	out := map[string]interface{}{
		"config_path":                     s.cfgPath,
		"metrics_path":                    "/metrics",
		"geoip_chnroute_entries":          s.cn.NetCount(),
		"stats_persist_key":               cfg.Stats.RedisKey,
		"stats_persist_interval_sec":      cfg.Stats.PersistIntervalSec,
		"warmup_domains":                  len(cfg.Warmup.Domains),
		"mapper_api_url_empty":            strings.TrimSpace(cfg.Mapper.APIURL) == "",
		"mapper_public_ip_probe_url":      cfg.Mapper.PublicIPProbeURL,
		"query_log_redis_key":             cfg.QueryLog.RedisKey,
		"query_log_max_entries":           cfg.QueryLog.MaxEntries,
		"resolver_max_inflight_upstream":  cfg.Resolver.MaxInflightUpstream,
		"resolver_global_resolve_qps":     cfg.Resolver.GlobalResolveQPS,
		"resolver_udp_conns_per_upstream": cfg.Resolver.UDPConnsPerUpstream,
		"resolver_l1_cache_max_entries":   cfg.Resolver.L1CacheMaxEntries,
		"listen_max_tcp_dns_connections":  cfg.Listen.MaxTCPDNSConnections,
		"doh_tls":                         cfg.Listen.DoHTLS,
		"doh_tls_use_inline_pem":          strings.TrimSpace(cfg.Listen.TLSCertPEM) != "" && strings.TrimSpace(cfg.Listen.TLSKeyPEM) != "",
		"doh_tls_cert_file_set":           strings.TrimSpace(cfg.Listen.TLSCert) != "",
		"listen": map[string]string{
			"udp":   cfg.Listen.UDP,
			"tcp":   cfg.Listen.TCP,
			"doh":   cfg.Listen.DoH,
			"admin": cfg.Listen.Admin,
		},
	}
	if s.st != nil {
		out["uptime_seconds"] = s.st.Read().UptimeSeconds
	}
	if cfg.QueryLog.MaxEntries > 0 {
		out["query_log_backend"] = "redis"
	} else {
		out["query_log_backend"] = "memory"
	}
	out["query_log_async_queue_cap"] = queryLogChanCap
	out["query_log_async_dropped"] = atomic.LoadUint64(&s.logDropped)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func sanitizeConfigForAPI(c *config.Config) config.Config {
	out := *c
	out.Admin.PasswordBcrypt = ""
	out.Admin.SessionSecret = ""
	// TLS 证书路径仅通过 YAML 配置；控制台只维护 PEM，响应中不返回路径以免误导
	out.Listen.TLSCert = ""
	out.Listen.TLSKey = ""
	return out
}

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	c := s.cfgStore.Get()
	if c == nil {
		http.Error(w, "no config", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(sanitizeConfigForAPI(c))
}

func (s *Server) putConfig(w http.ResponseWriter, r *http.Request) {
	var c config.Config
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	cur := s.cfgStore.Get()
	if cur != nil {
		if strings.TrimSpace(c.Admin.PasswordBcrypt) == "" {
			c.Admin.PasswordBcrypt = cur.Admin.PasswordBcrypt
		}
		if strings.TrimSpace(c.Admin.SessionSecret) == "" {
			c.Admin.SessionSecret = cur.Admin.SessionSecret
		}
		// 界面不编辑证书路径：提交空则保留磁盘上的 tls_cert / tls_key；PEM 空则保留原 PEM
		if strings.TrimSpace(c.Listen.TLSCert) == "" {
			c.Listen.TLSCert = cur.Listen.TLSCert
		}
		if strings.TrimSpace(c.Listen.TLSKey) == "" {
			c.Listen.TLSKey = cur.Listen.TLSKey
		}
		// PEM 以请求正文为准（不合并），便于在界面清空内联证书
	}
	c.Defaults()
	if err := config.Validate(&c); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := config.Save(s.cfgPath, &c); err != nil {
		http.Error(w, "save: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.cfgStore.Set(&c)
	s.SyncSessionSecretFromConfig()
	if s.applyRuntime != nil {
		s.applyRuntime(&c)
	}
	_ = s.wl.LoadFromRedis(context.Background())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
}

func (s *Server) reloadConfig(w http.ResponseWriter, r *http.Request) {
	c, err := config.Load(s.cfgPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := config.Validate(c); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.cfgStore.Set(c)
	s.SyncSessionSecretFromConfig()
	if s.applyRuntime != nil {
		s.applyRuntime(c)
	}
	_ = s.wl.LoadFromRedis(context.Background())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

func (s *Server) refreshGeo(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := s.cn.Refresh(ctx); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
