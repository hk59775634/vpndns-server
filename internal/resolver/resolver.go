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
		return ipv6DisabledAAAAResponse(req), nil
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

func ipv6DisabledAAAAResponse(req *models.DNSRequest) *models.DNSResponse {
	m := new(dns.Msg)
	m.SetReply(req.Msg)
	m.Rcode = dns.RcodeSuccess
	m.Authoritative = false
	m.Answer = nil
	qline := questionSummaryLine(req)
	return &models.DNSResponse{
		Msg: m, MinTTL: 60,
		Log: models.ResolveLog{
			Trace: &models.ResolveTrace{
				Question: qline,
				Steps:    []string{"已配置 disable_ipv6，AAAA 直接返回无数据（未访问上游）"},
			},
		},
	}
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
	// Upstream ECS and ECS-scoped cache use public unicast only; mapped or raw VPN/private
	// VIPs must fall through to default_cn_ecs (see mapper docs).
	ecsSourceIP := mapper.PublicUnicastIP(realIP)
	clientECS := req.ClientECS
	if clientECS == "" {
		clientECS = ecs.EDNS0Subnet(req.Msg)
	}
	cnECSDefault := parseIP(cfg.Mapper.DefaultCNECS)
	ecsIP, ecsBits, cnECSSource := cnUpstreamECSSelect(ecsSourceIP, clientECS, cnECSDefault)

	// ECS 缓存维度与 effectiveSubnetECS：与国内上游 ECS 优先级一致（客户端公章网 EDNS → 映射公网 → default_cn_ecs）。
	var subnetIP net.IP
	effectiveSubnetECS := ""
	switch cnECSSource {
	case "client_edns":
		effectiveSubnetECS = clientECS
		if ecsSourceIP != nil {
			subnetIP = ecsSourceIP
		} else if cnECSDefault != nil {
			subnetIP = cnECSDefault
		}
	case "vip_mapped":
		subnetIP = ecsSourceIP
	case "default_cn":
		if cnECSDefault != nil {
			subnetIP = cnECSDefault
		}
	default:
		subnetIP = ecsSourceIP
		if subnetIP == nil {
			subnetIP = cnECSDefault
		}
	}
	sentParam := ecs.GoogleSubnetQueryParam(ecsIP, ecsBits)
	mappedECS, _ := r.cache.GetGoogleECSMap(ctx, sentParam)
	lookupSubnet := ecs.SubnetKeyForRead(mappedECS, sentParam, effectiveSubnetECS, subnetIP)
	subnetKey := lookupSubnet

	tr := buildTracePrelude(req, qname, qtype, req.ClientVIP, realIP, ecsSourceIP, clientECS, subnetKey, ecsIP, ecsBits, cnECSDefault, cnECSSource)

	// 6. ECS-scoped cache (lookup uses Google-echo mapping + sent subnet; store key may differ after upstream)
	lookupECSKey := cache.ECSKey(qname, qtype, lookupSubnet)
	if resp, ok := r.l1HitECS(lookupECSKey, req, realIP, subnetKey); ok {
		tr.FromCache = "l1_ecs"
		tr.Steps = append(tr.Steps, "命中进程内 L1 缓存（ECS 键），未访问上游")
		resp.Log.Trace = tr
		return resp, nil
	}
	if resp, ok := r.cache.Get(ctx, lookupECSKey); ok && resp != nil && resp.Msg != nil {
		tr.FromCache = "redis_ecs"
		tr.Steps = append(tr.Steps, "命中 Redis 缓存（ECS 键），未访问上游")
		out := resp.Msg.Copy()
		out.SetReply(req.Msg)
		return &models.DNSResponse{
			Msg: out, MinTTL: resp.MinTTL,
			Log: models.ResolveLog{Cached: true, RealIP: ipString(realIP), ClientSubnet: subnetKey, Trace: tr},
		}, nil
	}

	// Non A/AAAA: CN only path (no IP-based split)
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		cnResp, storeKey, storeSubnet, err := r.queryCNWithECSTrace(ctx, cfg, req, ecsIP, ecsBits, qname, qtype, sentParam, effectiveSubnetECS, subnetIP, tr)
		if err != nil {
			return nil, wrapResolveErr(tr, err)
		}
		subnetKey = storeSubnet
		tr.IPClassification = "非 A/AAAA"
		tr.Steps = append(tr.Steps, "记录类型非 A/AAAA，不做境内外 IP 分类，仅使用国内上游结果")
		ttl := effectiveTTL(cnResp, cfg.Resolver.MaxCacheTTLSeconds)
		r.setBothCaches(ctx, storeKey, cnResp, ttl)
		out := cnResp.Msg.Copy()
		out.SetReply(req.Msg)
		return &models.DNSResponse{
			Msg: out, MinTTL: uint32(ttl),
			Log: models.ResolveLog{CNOnly: true, RealIP: ipString(realIP), ClientSubnet: subnetKey, Trace: tr},
		}, nil
	}

	// 7–9 CN path with IP classification
	cnResp, storeKey, storeSubnet, err := r.queryCNWithECSTrace(ctx, cfg, req, ecsIP, ecsBits, qname, qtype, sentParam, effectiveSubnetECS, subnetIP, tr)
	if err != nil {
		return nil, wrapResolveErr(tr, err)
	}
	subnetKey = storeSubnet
	ips := models.ExtractIPs(cnResp.Msg)
	if len(ips) == 0 {
		tr.IPClassification = "无 A/AAAA 地址"
		tr.Steps = append(tr.Steps, "国内 IP 分类：结果中无 A/AAAA 地址")
		ttl := effectiveTTL(cnResp, cfg.Resolver.MaxCacheTTLSeconds)
		r.setBothCaches(ctx, storeKey, cnResp, ttl)
		out := cnResp.Msg.Copy()
		out.SetReply(req.Msg)
		return &models.DNSResponse{
			Msg: out, MinTTL: uint32(ttl),
			Log: models.ResolveLog{CNOnly: true, RealIP: ipString(realIP), ClientSubnet: subnetKey, Trace: tr},
		}, nil
	}

	allCN, cnIPs, _ := r.cn.ClassifyIPs(ips)
	if allCN {
		tr.IPClassification = "全部为国内 IP"
		tr.Steps = append(tr.Steps, "国内 IP 分类：结果均为国内地址，仅使用国内上游结果")
		ttl := effectiveTTL(cnResp, cfg.Resolver.MaxCacheTTLSeconds)
		r.setBothCaches(ctx, storeKey, cnResp, ttl)
		out := cnResp.Msg.Copy()
		out.SetReply(req.Msg)
		return &models.DNSResponse{
			Msg: out, MinTTL: uint32(ttl),
			Log: models.ResolveLog{CNOnly: true, RealIP: ipString(realIP), ClientSubnet: subnetKey, Trace: tr},
		}, nil
	}
	if len(cnIPs) > 0 {
		tr.IPClassification = "混合（含国内与海外），已过滤为仅国内"
		tr.Steps = append(tr.Steps, "国内 IP 分类：同时含国内与海外地址，已过滤为仅保留国内 IP")
		filtered := filterAnswersByIPs(cnResp.Msg, cnIPs)
		fr := &models.DNSResponse{Msg: filtered, MinTTL: models.MinAnswerTTL(filtered, 60)}
		ttl := effectiveTTL(fr, cfg.Resolver.MaxCacheTTLSeconds)
		r.setBothCaches(ctx, storeKey, fr, ttl)
		out := filtered.Copy()
		out.SetReply(req.Msg)
		return &models.DNSResponse{
			Msg: out, MinTTL: uint32(ttl),
			Log: models.ResolveLog{CNOnly: true, RealIP: ipString(realIP), ClientSubnet: subnetKey, Trace: tr},
		}, nil
	}

	tr.IPClassification = "无国内 IP"
	tr.Steps = append(tr.Steps, "国内 IP 分类：解析结果中无国内地址，需判断白名单后是否查询海外上游")

	// 10 whitelist (OUT only)
	if !r.wl.Allowed(qname) {
		return blocked(req.Msg, cfg.Resolver.NonWhitelistAction, realIP, subnetKey, tr), nil
	}

	gkey := cache.GlobalKey(qname, qtype)
	if resp, ok := r.l1HitGlobal(gkey, req, realIP, subnetKey); ok {
		tr.FromCache = "l1_global"
		tr.Steps = append(tr.Steps, "命中进程内 L1 缓存（全局键），未访问上游")
		resp.Log.Trace = tr
		return resp, nil
	}
	if resp, ok := r.cache.Get(ctx, gkey); ok && resp != nil && resp.Msg != nil {
		tr.FromCache = "redis_global"
		tr.Steps = append(tr.Steps, "命中 Redis 缓存（全局键），未访问上游")
		out := resp.Msg.Copy()
		out.SetReply(req.Msg)
		return &models.DNSResponse{
			Msg: out, MinTTL: resp.MinTTL,
			Log: models.ResolveLog{Cached: true, RealIP: ipString(realIP), ClientSubnet: subnetKey, Trace: tr},
		}, nil
	}

	outECSDefault := parseIP(cfg.Mapper.DefaultOUTECS)
	outEcsIP, outEcsBits := outUpstreamECS(ecsSourceIP, clientECS, outECSDefault, cnECSDefault)
	outResp, err := r.queryOUTCoalesced(ctx, cfg, req, outEcsIP, outEcsBits, gkey)
	if err != nil {
		return nil, wrapResolveErr(tr, err)
	}
	annotateOUTTrace(tr, outResp, outEcsIP, outEcsBits)
	ttl := effectiveTTL(outResp, cfg.Resolver.MaxCacheTTLSeconds)
	r.setBothCaches(ctx, gkey, outResp, ttl)
	out := outResp.Msg.Copy()
	out.SetReply(req.Msg)
	return &models.DNSResponse{
		Msg: out, MinTTL: uint32(ttl),
		Log: models.ResolveLog{WentOUT: true, RealIP: ipString(realIP), ClientSubnet: subnetKey, Trace: tr},
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

// cnUpstreamECSSelect picks ECS for all cn_dns transports (UDP / DoH). Priority:
//  1) Client EDNS subnet if anchor IP is public unicast (RFC7871-style)
//  2) Else VIP→realIP mapped public unicast (ecsSourceIP)
//  3) Else default_cn_ecs if configured (/24 v4 or /48 v6)
//  4) Else same as ecsNetForQuery with no inputs (typically nil)
//
// Returned source is "client_edns" | "vip_mapped" | "default_cn" | "none" for trace text.
func cnUpstreamECSSelect(ecsSourceIP net.IP, clientECS string, cnDefault net.IP) (ip net.IP, bits int, source string) {
	if ip, bits, ok := clientPublicECSNet(clientECS); ok {
		return ip, bits, "client_edns"
	}
	if ecsSourceIP != nil {
		ip, bits := ecsNetForQuery(ecsSourceIP, "", nil)
		if ip != nil && bits > 0 {
			return ip, bits, "vip_mapped"
		}
	}
	if cnDefault != nil {
		if ip4 := cnDefault.To4(); ip4 != nil {
			return ip4, 24, "default_cn"
		}
		return cnDefault.To16(), 48, "default_cn"
	}
	ip, bits = ecsNetForQuery(nil, "", nil)
	return ip, bits, "none"
}

// clientPublicECSNet returns ECS ip/bits when clientECS parses as CIDR and the address is public unicast.
func clientPublicECSNet(clientECS string) (ip net.IP, bits int, ok bool) {
	s := strings.TrimSpace(clientECS)
	if s == "" {
		return nil, 0, false
	}
	ipAddr, ipNet, err := net.ParseCIDR(s)
	if err != nil || ipNet == nil {
		return nil, 0, false
	}
	if mapper.PublicUnicastIP(ipAddr) == nil {
		return nil, 0, false
	}
	ones, bitsTotal := ipNet.Mask.Size()
	if bitsTotal == 32 {
		ip4 := ipAddr.To4()
		if ip4 == nil || ones <= 0 {
			return nil, 0, false
		}
		return ip4, ones, true
	}
	if bitsTotal == 128 {
		ip6 := ipAddr.To16()
		if ip6 == nil || ones <= 0 {
			return nil, 0, false
		}
		return ip6, ones, true
	}
	return nil, 0, false
}

// outUpstreamECS selects ECS for out_dns: default_out_ecs or default_cn_ecs 作为固定源时
// 不采用 VIP 映射公网 IP（仍优先客户端 EDNS 子网）；否则按映射公网 IP。
func outUpstreamECS(ecsSourceIP net.IP, clientECS string, outDefault, cnDefault net.IP) (ip net.IP, bits int) {
	if outDefault != nil {
		return ecsNetForQuery(nil, clientECS, outDefault)
	}
	if cnDefault != nil {
		return ecsNetForQuery(nil, clientECS, cnDefault)
	}
	return ecsNetForQuery(ecsSourceIP, clientECS, nil)
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
	return blocked(req, action, realIP, subnetKey, nil)
}

func blocked(req *dns.Msg, action string, realIP net.IP, subnetKey string, tr *models.ResolveTrace) *models.DNSResponse {
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
	if tr != nil {
		tr.BlockedReason = "非白名单"
		tr.Steps = append(tr.Steps, "域名未在白名单内，不查询海外上游，按策略返回（NXDOMAIN 或 localhost）")
	}
	return &models.DNSResponse{
		Msg: m, MinTTL: 60,
		Log: models.ResolveLog{BlockedWL: true, RealIP: ipString(realIP), ClientSubnet: subnetKey, Trace: tr},
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

func coalesceCNUpstreamKey(qname string, qtype uint16, ecsIP net.IP, ecsBits int) string {
	d := strings.TrimSuffix(strings.ToLower(qname), ".")
	return "cn|" + d + "|" + cache.QTypeString(qtype) + "|" + ecsUpstreamKeyForFlight(ecsIP, ecsBits)
}

// queryCNWithECSTrace runs coalesced CN upstream, persists Google ECS map, updates trace (EffectiveSubnet + annotateCNTrace).
func (r *Resolver) queryCNWithECSTrace(ctx context.Context, cfg *config.Config, req *models.DNSRequest, ecsIP net.IP, ecsBits int, qname string, qtype uint16, sentParam, effectiveSubnetECS string, subnetIP net.IP, tr *models.ResolveTrace) (*models.DNSResponse, string, string, error) {
	cnResp, err := r.queryCNCoalesced(ctx, cfg, req, ecsIP, ecsBits, qname, qtype)
	if err != nil {
		return nil, "", "", err
	}
	storeKey, storeSubnet := r.cnStoreECSKey(ctx, qname, qtype, sentParam, effectiveSubnetECS, subnetIP, cnResp)
	if tr != nil {
		tr.EffectiveSubnet = storeSubnet
	}
	annotateCNTrace(tr, cnResp)
	return cnResp, storeKey, storeSubnet, nil
}

func (r *Resolver) cnStoreECSKey(ctx context.Context, qname string, qtype uint16, sentParam, effectiveSubnetECS string, subnetIP net.IP, cnResp *models.DNSResponse) (storeKey string, storeSubnet string) {
	echo := ""
	if cnResp != nil {
		echo = cnResp.GoogleEchoedECS
	}
	storeSubnet = ecs.SubnetKeyForStore(echo, sentParam, effectiveSubnetECS, subnetIP)
	if sentParam != "" && cnResp != nil {
		if echoNorm := ecs.ValidNormalizedSubnet(cnResp.GoogleEchoedECS); echoNorm != "" {
			_ = r.cache.SetGoogleECSMap(ctx, sentParam, echoNorm, 0)
		}
	}
	return cache.ECSKey(qname, qtype, storeSubnet), storeSubnet
}

func (r *Resolver) queryCNCoalesced(ctx context.Context, cfg *config.Config, req *models.DNSRequest, ecsIP net.IP, ecsBits int, qname string, qtype uint16) (*models.DNSResponse, error) {
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
	key := coalesceCNUpstreamKey(qname, qtype, ecsIP, ecsBits)
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
	Trace         *models.ResolveTrace `json:"trace,omitempty"`
}
