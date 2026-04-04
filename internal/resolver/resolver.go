package resolver

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"github.com/vpndns/cdn/internal/cache"
	"github.com/vpndns/cdn/internal/config"
	"github.com/vpndns/cdn/internal/ecs"
	"github.com/vpndns/cdn/internal/geoip"
	"github.com/vpndns/cdn/internal/mapper"
	"github.com/vpndns/cdn/internal/models"
	"github.com/vpndns/cdn/internal/overload"
	"github.com/vpndns/cdn/internal/upstream"
	"github.com/vpndns/cdn/internal/whitelist"
)

// Resolver implements smart CN/OUT resolution per spec.
type Resolver struct {
	cfgStore *config.Store
	cache    *cache.Redis
	l1       *cache.L1
	mapper   *mapper.Mapper
	wl       *whitelist.Matcher
	cn       *geoip.CN
	pool     *upstream.Pool
	guard    *overload.Guard
	sf       singleflight.Group
}

func New(cfg *config.Store, c *cache.Redis, l1 *cache.L1, m *mapper.Mapper, wl *whitelist.Matcher, cn *geoip.CN, pool *upstream.Pool, guard *overload.Guard) *Resolver {
	return &Resolver{
		cfgStore: cfg,
		cache:    c,
		l1:       l1,
		mapper:   m,
		wl:       wl,
		cn:       cn,
		pool:     pool,
		guard:    guard,
	}
}

func (r *Resolver) Resolve(ctx context.Context, req *models.DNSRequest) (*models.DNSResponse, error) {
	cfg := r.cfgStore.Get()
	if req == nil || req.Msg == nil || len(req.Msg.Question) == 0 {
		return nil, fmt.Errorf("bad request")
	}
	if cfg.Resolver.DisableIPv6 && req.QuestionType() == dns.TypeAAAA {
		return ipv6DisabledAAAAResponse(req.Msg), nil
	}
	resp, err := r.resolveCore(ctx, req, cfg)
	if err != nil || resp == nil || resp.Msg == nil || !cfg.Resolver.DisableIPv6 {
		return resp, err
	}
	resp.Msg = stripAAAARecords(resp.Msg)
	if resp.Msg != nil {
		resp.MinTTL = models.MinAnswerTTL(resp.Msg, resp.MinTTL)
	}
	return resp, err
}

func ipv6DisabledAAAAResponse(req *dns.Msg) *models.DNSResponse {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Rcode = dns.RcodeSuccess
	m.Authoritative = false
	m.Answer = nil
	return &models.DNSResponse{Msg: m, MinTTL: 60, Log: models.ResolveLog{}}
}

func stripAAAARecords(m *dns.Msg) *dns.Msg {
	if m == nil {
		return nil
	}
	out := m.Copy()
	out.Answer = stripAAAASlice(out.Answer)
	out.Ns = stripAAAASlice(out.Ns)
	out.Extra = stripAAAASlice(out.Extra)
	return out
}

func stripAAAASlice(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return rrs
	}
	var out []dns.RR
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		if rr.Header().Rrtype == dns.TypeAAAA {
			continue
		}
		out = append(out, rr)
	}
	return out
}

func (r *Resolver) resolveCore(ctx context.Context, req *models.DNSRequest, cfg *config.Config) (*models.DNSResponse, error) {
	if r.guard != nil && !r.guard.AllowGlobal() {
		return nil, ErrOverload
	}

	qname := req.QuestionName()
	qtype := req.QuestionType()

	realIP, err := r.mapper.GetRealIP(ctx, req.ClientVIP)
	if err != nil {
		realIP = net.ParseIP(req.ClientVIP)
	}
	clientECS := req.ClientECS
	if clientECS == "" {
		clientECS = ecs.EDNS0Subnet(req.Msg)
	}
	cnECSDefault := parseIP(cfg.Mapper.DefaultCNECS)
	subnetIP := realIP
	if subnetIP == nil {
		subnetIP = cnECSDefault
	}
	subnetKey := ecs.FromClientOrIP(clientECS, subnetIP)

	ecsIP, ecsBits := ecsNetForQuery(realIP, clientECS, cnECSDefault)

	// 6. ECS-scoped cache
	ecsCacheKey := cache.ECSKey(qname, qtype, subnetKey)
	if resp, ok := r.l1HitECS(ecsCacheKey, req, realIP, subnetKey); ok {
		return resp, nil
	}
	if resp, ok := r.cache.Get(ctx, ecsCacheKey); ok && resp != nil && resp.Msg != nil {
		out := resp.Msg.Copy()
		out.SetReply(req.Msg)
		return &models.DNSResponse{
			Msg: out, MinTTL: resp.MinTTL,
			Log: models.ResolveLog{Cached: true, RealIP: ipString(realIP), ClientSubnet: subnetKey},
		}, nil
	}

	// Non A/AAAA: CN only path (no IP-based split)
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		cnResp, err := r.queryCNCoalesced(ctx, cfg, req, ecsIP, ecsBits, ecsCacheKey)
		if err != nil {
			return nil, err
		}
		ttl := effectiveTTL(cnResp, cfg.Resolver.MaxCacheTTLSeconds)
		r.setBothCaches(ctx, ecsCacheKey, cnResp, ttl)
		out := cnResp.Msg.Copy()
		out.SetReply(req.Msg)
		return &models.DNSResponse{
			Msg: out, MinTTL: uint32(ttl),
			Log: models.ResolveLog{CNOnly: true, RealIP: ipString(realIP), ClientSubnet: subnetKey},
		}, nil
	}

	// 7–9 CN path with IP classification
	cnResp, err := r.queryCNCoalesced(ctx, cfg, req, ecsIP, ecsBits, ecsCacheKey)
	if err != nil {
		return nil, err
	}
	ips := models.ExtractIPs(cnResp.Msg)
	if len(ips) == 0 {
		ttl := effectiveTTL(cnResp, cfg.Resolver.MaxCacheTTLSeconds)
		r.setBothCaches(ctx, ecsCacheKey, cnResp, ttl)
		out := cnResp.Msg.Copy()
		out.SetReply(req.Msg)
		return &models.DNSResponse{
			Msg: out, MinTTL: uint32(ttl),
			Log: models.ResolveLog{CNOnly: true, RealIP: ipString(realIP), ClientSubnet: subnetKey},
		}, nil
	}

	allCN, cnIPs, _ := r.cn.ClassifyIPs(ips)
	if allCN {
		ttl := effectiveTTL(cnResp, cfg.Resolver.MaxCacheTTLSeconds)
		r.setBothCaches(ctx, ecsCacheKey, cnResp, ttl)
		out := cnResp.Msg.Copy()
		out.SetReply(req.Msg)
		return &models.DNSResponse{
			Msg: out, MinTTL: uint32(ttl),
			Log: models.ResolveLog{CNOnly: true, RealIP: ipString(realIP), ClientSubnet: subnetKey},
		}, nil
	}
	if len(cnIPs) > 0 {
		filtered := filterAnswersByIPs(cnResp.Msg, cnIPs)
		fr := &models.DNSResponse{Msg: filtered, MinTTL: models.MinAnswerTTL(filtered, 60)}
		ttl := effectiveTTL(fr, cfg.Resolver.MaxCacheTTLSeconds)
		r.setBothCaches(ctx, ecsCacheKey, fr, ttl)
		out := filtered.Copy()
		out.SetReply(req.Msg)
		return &models.DNSResponse{
			Msg: out, MinTTL: uint32(ttl),
			Log: models.ResolveLog{CNOnly: true, RealIP: ipString(realIP), ClientSubnet: subnetKey},
		}, nil
	}

	// 10 whitelist (OUT only)
	if !r.wl.Allowed(qname) {
		return blocked(req.Msg, cfg.Resolver.NonWhitelistAction, realIP, subnetKey), nil
	}

	gkey := cache.GlobalKey(qname, qtype)
	if resp, ok := r.l1HitGlobal(gkey, req, realIP, subnetKey); ok {
		return resp, nil
	}
	if resp, ok := r.cache.Get(ctx, gkey); ok && resp != nil && resp.Msg != nil {
		out := resp.Msg.Copy()
		out.SetReply(req.Msg)
		return &models.DNSResponse{
			Msg: out, MinTTL: resp.MinTTL,
			Log: models.ResolveLog{Cached: true, RealIP: ipString(realIP), ClientSubnet: subnetKey},
		}, nil
	}

	outECSDefault := parseIP(cfg.Mapper.DefaultOUTECS)
	outEcsIP, outEcsBits := ecsNetForQuery(realIP, clientECS, outECSDefault)
	outResp, err := r.queryOUTCoalesced(ctx, cfg, req, outEcsIP, outEcsBits, gkey)
	if err != nil {
		return nil, err
	}
	ttl := effectiveTTL(outResp, cfg.Resolver.MaxCacheTTLSeconds)
	r.setBothCaches(ctx, gkey, outResp, ttl)
	out := outResp.Msg.Copy()
	out.SetReply(req.Msg)
	return &models.DNSResponse{
		Msg: out, MinTTL: uint32(ttl),
		Log: models.ResolveLog{WentOUT: true, RealIP: ipString(realIP), ClientSubnet: subnetKey},
	}, nil
}

func (r *Resolver) setBothCaches(ctx context.Context, key string, resp *models.DNSResponse, ttl int) {
	if resp == nil || resp.Msg == nil {
		return
	}
	_ = r.cache.Set(ctx, key, resp, ttl)
	if r.l1 != nil {
		r.l1.Set(key, resp, ttl)
	}
}

func (r *Resolver) l1HitECS(ecsCacheKey string, req *models.DNSRequest, realIP net.IP, subnetKey string) (*models.DNSResponse, bool) {
	if r.l1 == nil {
		return nil, false
	}
	resp, ok := r.l1.Get(ecsCacheKey)
	if !ok || resp == nil || resp.Msg == nil {
		return nil, false
	}
	out := resp.Msg.Copy()
	out.SetReply(req.Msg)
	return &models.DNSResponse{
		Msg: out, MinTTL: resp.MinTTL,
		Log: models.ResolveLog{Cached: true, RealIP: ipString(realIP), ClientSubnet: subnetKey},
	}, true
}

func (r *Resolver) l1HitGlobal(gkey string, req *models.DNSRequest, realIP net.IP, subnetKey string) (*models.DNSResponse, bool) {
	if r.l1 == nil {
		return nil, false
	}
	resp, ok := r.l1.Get(gkey)
	if !ok || resp == nil || resp.Msg == nil {
		return nil, false
	}
	out := resp.Msg.Copy()
	out.SetReply(req.Msg)
	return &models.DNSResponse{
		Msg: out, MinTTL: resp.MinTTL,
		Log: models.ResolveLog{Cached: true, RealIP: ipString(realIP), ClientSubnet: subnetKey},
	}, true
}

func parseIP(s string) net.IP {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return net.ParseIP(s)
}

// ecsNetForQuery builds EDNS0 subnet for upstreams: client ECS if present, else mapped real IP, else fallback (e.g. configured default public IP).
func ecsNetForQuery(realIP net.IP, clientECS string, fallback net.IP) (ip net.IP, bits int) {
	if clientECS != "" {
		ipAddr, ipNet, err := net.ParseCIDR(clientECS)
		if err == nil && ipNet != nil {
			ones, bitsTotal := ipNet.Mask.Size()
			if bitsTotal == 32 {
				return ipAddr.To4(), ones
			}
			if bitsTotal == 128 {
				return ipAddr.To16(), ones
			}
		}
	}
	if realIP != nil {
		if ip4 := realIP.To4(); ip4 != nil {
			return ip4, 24
		}
		return realIP.To16(), 48
	}
	if fallback != nil {
		if ip4 := fallback.To4(); ip4 != nil {
			return ip4, 24
		}
		return fallback.To16(), 48
	}
	return nil, 0
}

// nxdomainCacheTTLSeconds is Redis cache TTL for NXDOMAIN answers (override short/empty RR TTLs).
const nxdomainCacheTTLSeconds = 3600

func effectiveTTL(resp *models.DNSResponse, maxSec int) int {
	if resp == nil || resp.Msg == nil {
		return maxSec
	}
	if resp.Msg.Rcode == dns.RcodeNameError {
		t := nxdomainCacheTTLSeconds
		if maxSec > 0 && t > maxSec {
			t = maxSec
		}
		if t < 5 {
			t = 5
		}
		return t
	}
	t := int(resp.MinTTL)
	if t <= 0 {
		t = maxSec
	}
	if t > maxSec {
		t = maxSec
	}
	if t < 5 {
		t = 5
	}
	return t
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// PolicyBlockResponse returns the same DNS answer shape as non-whitelist blocking (NXDOMAIN or localhost A/AAAA per action).
func PolicyBlockResponse(req *dns.Msg, action string, realIP net.IP, subnetKey string) *models.DNSResponse {
	return blocked(req, action, realIP, subnetKey)
}

func blocked(req *dns.Msg, action string, realIP net.IP, subnetKey string) *models.DNSResponse {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.Rcode = dns.RcodeSuccess
	qt := dns.TypeA
	if len(req.Question) > 0 {
		qt = req.Question[0].Qtype
	}
	name := "."
	if len(req.Question) > 0 {
		name = req.Question[0].Name
	}
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "localhost", "127", "loopback":
		if qt == dns.TypeAAAA {
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN AAAA ::1", name))
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		} else {
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A 127.0.0.1", name))
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		}
	default:
		m.Rcode = dns.RcodeNameError
	}
	return &models.DNSResponse{
		Msg: m, MinTTL: 60,
		Log: models.ResolveLog{BlockedWL: true, RealIP: ipString(realIP), ClientSubnet: subnetKey},
	}
}

func ipEqual(a, b net.IP) bool {
	return a != nil && b != nil && a.Equal(b)
}

func filterAnswersByIPs(msg *dns.Msg, keep []net.IP) *dns.Msg {
	out := msg.Copy()
	var ans []dns.RR
	for _, rr := range out.Answer {
		switch v := rr.(type) {
		case *dns.A:
			for _, k := range keep {
				if ipEqual(v.A, k) {
					ans = append(ans, rr)
					break
				}
			}
		case *dns.AAAA:
			for _, k := range keep {
				if ipEqual(v.AAAA, k) {
					ans = append(ans, rr)
					break
				}
			}
		default:
			ans = append(ans, rr)
		}
	}
	out.Answer = ans
	return out
}

func ecsUpstreamKeyForFlight(ip net.IP, bits int) string {
	if ip == nil || bits <= 0 {
		return "noecs"
	}
	return ip.String() + "/" + strconv.Itoa(bits)
}

func (r *Resolver) queryCNCoalesced(ctx context.Context, cfg *config.Config, req *models.DNSRequest, ecsIP net.IP, ecsBits int, ecsCacheKey string) (*models.DNSResponse, error) {
	if cfg == nil {
		return r.pool.QueryCN(ctx, req, ecsIP, ecsBits)
	}
	if cfg.Resolver.CoalesceUpstream != nil && !*cfg.Resolver.CoalesceUpstream {
		return r.pool.QueryCN(ctx, req, ecsIP, ecsBits)
	}
	to := time.Duration(cfg.Resolver.QueryTimeoutMS) * time.Millisecond
	if to <= 0 {
		to = 3 * time.Second
	}
	key := "cn|" + ecsCacheKey + ":" + ecsUpstreamKeyForFlight(ecsIP, ecsBits)
	v, err, _ := r.sf.Do(key, func() (interface{}, error) {
		uctx, cancel := context.WithTimeout(context.Background(), to)
		defer cancel()
		return r.pool.QueryCN(uctx, req, ecsIP, ecsBits)
	})
	if err != nil {
		return nil, err
	}
	return v.(*models.DNSResponse), nil
}

func (r *Resolver) queryOUTCoalesced(ctx context.Context, cfg *config.Config, req *models.DNSRequest, ecsIP net.IP, ecsBits int, gkey string) (*models.DNSResponse, error) {
	if cfg == nil {
		return r.pool.QueryOUT(ctx, req, ecsIP, ecsBits)
	}
	if cfg.Resolver.CoalesceUpstream != nil && !*cfg.Resolver.CoalesceUpstream {
		return r.pool.QueryOUT(ctx, req, ecsIP, ecsBits)
	}
	to := time.Duration(cfg.Resolver.QueryTimeoutMS) * time.Millisecond
	if to <= 0 {
		to = 3 * time.Second
	}
	key := "out|" + gkey + ":" + ecsUpstreamKeyForFlight(ecsIP, ecsBits)
	v, err, _ := r.sf.Do(key, func() (interface{}, error) {
		uctx, cancel := context.WithTimeout(context.Background(), to)
		defer cancel()
		return r.pool.QueryOUT(uctx, req, ecsIP, ecsBits)
	})
	if err != nil {
		return nil, err
	}
	return v.(*models.DNSResponse), nil
}

// LogRecord is emitted for admin query logs (optional hook).
type LogRecord struct {
	Time          time.Time `json:"time"`
	Domain        string    `json:"domain"`
	QType         string    `json:"qtype"`
	VIP           string    `json:"vip"`
	RealIP        string    `json:"real_ip"`
	ClientSubnet  string    `json:"client_subnet"`
	Route         string    `json:"route"`
	CNOnly        bool      `json:"cn_only"`
	WentOUT       bool      `json:"went_out"`
	Cached        bool      `json:"cached"`
	BlockedWL     bool      `json:"blocked_wl"`
	LatencyMS     int64     `json:"latency_ms"`
	Rcode         int       `json:"rcode"`
	AnswerSummary string    `json:"answer_summary"`
}
