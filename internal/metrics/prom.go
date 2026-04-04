package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/vpndns/cdn/internal/geoip"
	"github.com/vpndns/cdn/internal/stats"
)

// RegisterVPNDNS registers gauges backed by live collector / geoip.
func RegisterVPNDNS(st *stats.Collector, cn *geoip.CN) {
	if st == nil {
		return
	}
	ns := "vpndns"
	promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Name: "dns_queries_total", Help: "DNS queries passed rate limit with valid question"}, func() float64 {
		return float64(st.Read().DNSQueries)
	})
	promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Name: "rate_limited_total", Help: "Requests rejected by per-IP rate limit"}, func() float64 {
		return float64(st.Read().RateLimited)
	})
	promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Name: "malformed_total", Help: "Malformed DNS / bad DoH payload"}, func() float64 {
		return float64(st.Read().Malformed)
	})
	promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Name: "doh_unauthorized_total", Help: "DoH requests failed auth"}, func() float64 {
		return float64(st.Read().DoHAuthFail)
	})
	promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Name: "overload_rejected_total", Help: "Queries rejected by global overload / QPS limit"}, func() float64 {
		return float64(st.Read().OverloadRejected)
	})
	promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Name: "blocked_blacklist_total", Help: "Queries blocked by domain blacklist"}, func() float64 {
		return float64(st.Read().BlockedBlacklist)
	})
	promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Name: "blocked_whitelist_total", Help: "Queries blocked by OUT whitelist policy"}, func() float64 {
		return float64(st.Read().BlockedWhitelist)
	})
	promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Name: "cache_hits_total", Help: "Responses served from Redis DNS cache"}, func() float64 {
		return float64(st.Read().CacheHits)
	})
	promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Name: "resolved_cn_total", Help: "Answers from domestic upstream path"}, func() float64 {
		return float64(st.Read().ResolvedCN)
	})
	promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Name: "resolved_out_total", Help: "Answers from overseas upstream path"}, func() float64 {
		return float64(st.Read().ResolvedOUT)
	})
	promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Name: "resolve_errors_total", Help: "Resolution failures (SERVFAIL etc.)"}, func() float64 {
		return float64(st.Read().Errors)
	})
	promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Name: "uptime_seconds", Help: "Process uptime"}, func() float64 {
		return float64(st.Read().UptimeSeconds)
	})
	if cn != nil {
		promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Name: "geoip_chnroute_entries", Help: "China CIDR rows loaded"}, func() float64 {
			return float64(cn.NetCount())
		})
	}
}
