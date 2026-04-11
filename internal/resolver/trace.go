package resolver

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/vpndns/cdn/internal/mapper"
	"github.com/vpndns/cdn/internal/models"
)

const traceWireMax = 6000

// maxDoHPostLogBytes caps stored POST body in query logs (hex length = 2×).
const maxDoHPostLogBytes = 16384

func applyTransportFromRequest(req *models.DNSRequest, t *models.ResolveTrace) {
	if req == nil {
		return
	}
	switch strings.TrimSpace(req.Transport) {
	case "doh":
		t.Transport = "doh"
		t.DoHURL = req.DoHFullURL
		if len(req.DoHPostWire) > 0 {
			n := len(req.DoHPostWire)
			if n > maxDoHPostLogBytes {
				t.DoHPostBodyTruncated = true
				n = maxDoHPostLogBytes
			}
			t.DoHPostBodyHex = hex.EncodeToString(req.DoHPostWire[:n])
		}
		u := req.DoHFullURL
		if u == "" {
			u = "（未知）"
		}
		t.Steps = append(t.Steps,
			"传输：DNS-over-HTTPS（RFC 8484，POST application/dns-message）",
			"请求 URL："+u,
		)
		if t.DoHPostBodyHex != "" {
			t.Steps = append(t.Steps, "POST body（application/dns-message，十六进制见下方「POST 数据」）")
			if t.DoHPostBodyTruncated {
				t.Steps = append(t.Steps, fmt.Sprintf("（仅记录前 %d 字节 POST body，避免日志过大）", maxDoHPostLogBytes))
			}
		}
	case "doh-json":
		t.Transport = "doh-json"
		t.DoHURL = req.DoHFullURL
		u := req.DoHFullURL
		if u == "" {
			u = "（未知）"
		}
		t.Steps = append(t.Steps,
			"传输：DNS-over-HTTPS（Google JSON，GET application/dns-json）",
			"请求 URL（含查询参数）："+u,
		)
	case "udp", "udp4", "udp6":
		t.Transport = "udp"
		t.Steps = append(t.Steps, "传输：DNS/UDP")
	case "tcp", "tcp4", "tcp6":
		t.Transport = "tcp"
		t.Steps = append(t.Steps, "传输：DNS/TCP")
	}
}

// TransportTracePreflight builds transport-only trace for logs when Resolve is not reached (e.g. errors).
func TransportTracePreflight(req *models.DNSRequest) *models.ResolveTrace {
	if req == nil || strings.TrimSpace(req.Transport) == "" {
		return nil
	}
	t := &models.ResolveTrace{}
	applyTransportFromRequest(req, t)
	if len(t.Steps) == 0 {
		return nil
	}
	return t
}

func describeECS(ip net.IP, bits int) string {
	if ip == nil || bits <= 0 {
		return "否（未携带 EDNS Client Subnet）"
	}
	return fmt.Sprintf("是，%s/%d", ip.String(), bits)
}

func tracePublicIPForECS(realIP, ecsSourceIP net.IP, cnDefault net.IP, cnECSSource string) string {
	switch cnECSSource {
	case "client_edns":
		if pub := mapper.PublicUnicastIP(realIP); pub != nil {
			return "映射公网 " + pub.String() + "；国内上游 ECS 使用客户端 EDNS 公章网子网"
		}
		return "国内上游 ECS 使用客户端 EDNS 公章网子网（当前无映射公网单播地址）"
	case "vip_mapped":
		if pub := mapper.PublicUnicastIP(realIP); pub != nil {
			return pub.String() + "（作为国内上游 ECS：VIP→realIP 映射）"
		}
		if ecsSourceIP != nil {
			return ecsSourceIP.String()
		}
		return "（映射公网）"
	case "default_cn":
		if cnDefault == nil {
			return "（未配置 default_cn_ecs）"
		}
		if pub := mapper.PublicUnicastIP(realIP); pub != nil {
			return "映射公网 " + pub.String() + "；国内上游 ECS 使用 mapper.default_cn_ecs " + cnDefault.String() + "（客户端无公章网子网）"
		}
		return "国内上游 ECS 使用 mapper.default_cn_ecs " + cnDefault.String() + "（无公章网客户端子网且无映射公网）"
	default:
		if pub := mapper.PublicUnicastIP(realIP); pub != nil {
			return pub.String()
		}
		return "（无公网单播地址；国内 ECS 见「发往国内上游时 EDNS」）"
	}
}

func dnsMsgWireTrunc(m *dns.Msg, max int) string {
	if m == nil {
		return ""
	}
	s := m.String()
	if len(s) > max {
		return s[:max] + "\n…（已截断）"
	}
	return s
}

func qTypeName(qt uint16) string {
	if s, ok := dns.TypeToString[qt]; ok && s != "" {
		return s
	}
	return fmt.Sprintf("TYPE%d", qt)
}

func questionSummaryLine(req *models.DNSRequest) string {
	if req == nil || req.Msg == nil || len(req.Msg.Question) == 0 {
		return "—"
	}
	q := req.Msg.Question[0]
	return qTypeName(q.Qtype) + " " + q.Name
}

// buildTracePrelude fills common routing context for admin query logs.
// cnECSSource is "client_edns" | "vip_mapped" | "default_cn" | "none" from cnUpstreamECSSelect.
func buildTracePrelude(req *models.DNSRequest, qname string, qtype uint16, vip string, realIP, ecsSourceIP net.IP, clientEDNS, subnetKey string, ecsIP net.IP, ecsBits int, cnDefault net.IP, cnECSSource string) *models.ResolveTrace {
	t := &models.ResolveTrace{
		VIP:               vip,
		RealIPMapped:      ipString(realIP),
		Question:          qTypeName(qtype) + " " + qname,
		ClientEDNS:        clientEDNS,
		EffectiveSubnet:   subnetKey,
		CNECSWithUpstream: describeECS(ecsIP, ecsBits),
	}
	applyTransportFromRequest(req, t)
	t.PublicIPForECS = tracePublicIPForECS(realIP, ecsSourceIP, cnDefault, cnECSSource)
	t.Steps = append(t.Steps,
		"解析请求："+t.Question,
		"客户端源地址（VIP）："+vip,
		"映射得到的 IP（含私网回退）："+t.RealIPMapped,
		"用于 ECS 的公网 IP："+t.PublicIPForECS,
	)
	if clientEDNS != "" {
		t.Steps = append(t.Steps, "客户端查询中 EDNS Client Subnet："+clientEDNS)
	} else {
		t.Steps = append(t.Steps, "客户端查询未携带 EDNS Client Subnet")
	}
	if cnDefault != nil {
		t.Steps = append(t.Steps, "已配置 mapper.default_cn_ecs：作为国内 ECS 保底（仅当客户端无公章网 EDNS 且无映射公网单播地址时使用）")
	}
	switch cnECSSource {
	case "client_edns":
		t.Steps = append(t.Steps, "本次国内上游 ECS 来源：客户端 EDNS Client Subnet（公章网）")
	case "vip_mapped":
		t.Steps = append(t.Steps, "本次国内上游 ECS 来源：VIP→realIP 映射公网地址")
	case "default_cn":
		t.Steps = append(t.Steps, "本次国内上游 ECS 来源：mapper.default_cn_ecs 保底")
	}
	t.Steps = append(t.Steps,
		"缓存维度（ECS 子网键）："+subnetKey,
		"发往国内上游时 EDNS Client Subnet："+t.CNECSWithUpstream,
	)
	return t
}

func annotateCNTrace(tr *models.ResolveTrace, cnResp *models.DNSResponse) {
	if tr == nil || cnResp == nil || cnResp.Msg == nil {
		return
	}
	tr.CNUpstreamUsed = true
	tr.CNUpstreamEndpoint = cnResp.UpstreamEndpoint
	tr.CNQuerySummary = tr.Question
	tr.CNResponseSummary = models.AnswerSummary(cnResp.Msg)
	tr.CNResponseWire = dnsMsgWireTrunc(cnResp.Msg, traceWireMax)
	if cnResp.UpstreamRequestURL != "" {
		tr.CNUpstreamRequestURL = cnResp.UpstreamRequestURL
		tr.Steps = append(tr.Steps,
			"国内上游实际请求（Google JSON GET）："+cnResp.UpstreamRequestURL,
		)
	}
	if echo := strings.TrimSpace(cnResp.GoogleEchoedECS); echo != "" {
		tr.GoogleEchoedSubnet = echo
		tr.Steps = append(tr.Steps, "Google JSON 响应中的 edns_client_subnet："+echo)
	}
	if cnResp.UpstreamEndpoint != "" {
		tr.Steps = append(tr.Steps,
			"国内上游回源："+cnResp.UpstreamEndpoint,
			"下方「国内上游响应（文本）」为解码后的 DNS 报文（与经 DoH 或 UDP 传输无关，仅为应答内容）",
		)
	} else {
		tr.Steps = append(tr.Steps, "已查询国内上游（cn_dns）")
	}
	tr.Steps = append(tr.Steps, "国内上游响应摘要："+tr.CNResponseSummary)
}

func annotateOUTTrace(tr *models.ResolveTrace, outResp *models.DNSResponse, outEcsIP net.IP, outEcsBits int) {
	if tr == nil || outResp == nil || outResp.Msg == nil {
		return
	}
	tr.OUTUpstreamUsed = true
	tr.OUTUpstreamEndpoint = outResp.UpstreamEndpoint
	tr.OUTECSWithUpstream = describeECS(outEcsIP, outEcsBits)
	tr.OUTResponseSummary = models.AnswerSummary(outResp.Msg)
	tr.OUTResponseWire = dnsMsgWireTrunc(outResp.Msg, traceWireMax)
	tr.Steps = append(tr.Steps,
		"发往海外上游时 EDNS Client Subnet："+tr.OUTECSWithUpstream,
	)
	if outResp.UpstreamRequestURL != "" {
		tr.OUTUpstreamRequestURL = outResp.UpstreamRequestURL
		tr.Steps = append(tr.Steps,
			"海外上游实际请求（Google JSON GET）："+outResp.UpstreamRequestURL,
		)
	}
	if outResp.UpstreamEndpoint != "" {
		tr.Steps = append(tr.Steps,
			"海外上游回源："+outResp.UpstreamEndpoint,
			"下方「海外上游响应（文本）」为解码后的 DNS 报文（与经 DoH 或 UDP 传输无关）",
		)
	} else {
		tr.Steps = append(tr.Steps, "已查询海外上游（out_dns）")
	}
	tr.Steps = append(tr.Steps, "海外上游响应摘要："+tr.OUTResponseSummary)
}
