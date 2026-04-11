package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/vpndns/cdn/internal/ecs"
)

// JSON shapes for Google Public DNS HTTPS JSON API (GET /resolve).
// See https://developers.google.com/speed/public-dns/docs/doh/json

type googleResolveJSON struct {
	Status   int               `json:"Status"`
	TC       bool              `json:"TC"`
	RD       bool              `json:"RD"`
	RA       bool              `json:"RA"`
	AD       bool              `json:"AD"`
	CD       bool              `json:"CD"`
	// EdnsClientSubnet is echoed by Google when applicable (requires disable_dnssec for a meaningful scope).
	EdnsClientSubnet string            `json:"edns_client_subnet,omitempty"`
	Question         []googleJSONQ     `json:"Question,omitempty"`
	Answer           []googleJSONAnswer `json:"Answer,omitempty"`
}

type googleJSONQ struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

type googleJSONAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

func isGoogleJSONResolveURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" {
		return false
	}
	path := strings.TrimSuffix(strings.TrimSpace(u.Path), "/")
	return strings.HasSuffix(path, "/resolve")
}

func (p *Pool) exchangeGoogleJSONResolve(ctx context.Context, rawURL string, msg *dns.Msg, ecsIP net.IP, ecsBits int) (*dns.Msg, string, string, error) {
	if msg == nil || len(msg.Question) == 0 {
		return nil, "", "", fmt.Errorf("google json resolve: no question")
	}
	base, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, "", "", err
	}
	base.RawQuery = ""
	base.Fragment = ""

	q := msg.Question[0]
	name := strings.TrimSuffix(q.Name, ".")
	qs := url.Values{}
	qs.Set("name", name)
	qs.Set("type", strconv.Itoa(int(q.Qtype)))
	qs.Set("disable_dnssec", "true")
	if sub := ecs.GoogleSubnetQueryParam(ecsIP, ecsBits); sub != "" {
		qs.Set("edns_client_subnet", sub)
	}
	base.RawQuery = qs.Encode()
	fullURL := base.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fullURL, "", err
	}
	req.Header.Set("Accept", "application/dns-json")

	p.mu.RLock()
	client := p.httpClient
	p.mu.RUnlock()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fullURL, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fullURL, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fullURL, "", fmt.Errorf("google json resolve: http %d", resp.StatusCode)
	}
	var gj googleResolveJSON
	if err := json.Unmarshal(body, &gj); err != nil {
		return nil, fullURL, "", fmt.Errorf("google json resolve: decode: %w", err)
	}
	echo := strings.TrimSpace(gj.EdnsClientSubnet)
	out, err := googleResolveJSONToMsg(msg, &gj)
	if err != nil {
		return nil, fullURL, echo, err
	}
	return out, fullURL, echo, nil
}

func googleResolveJSONToMsg(req *dns.Msg, gj *googleResolveJSON) (*dns.Msg, error) {
	if gj == nil {
		return nil, fmt.Errorf("empty json")
	}
	out := new(dns.Msg)
	out.Id = req.Id
	out.Response = true
	out.Rcode = gj.Status
	out.Truncated = gj.TC
	out.RecursionDesired = gj.RD
	out.RecursionAvailable = gj.RA
	out.AuthenticatedData = gj.AD
	out.CheckingDisabled = gj.CD

	for _, qq := range gj.Question {
		out.Question = append(out.Question, dns.Question{
			Name:   dns.Fqdn(qq.Name),
			Qtype:  uint16(qq.Type),
			Qclass: dns.ClassINET,
		})
	}
	for _, a := range gj.Answer {
		rr, err := googleAnswerToRR(a)
		if err != nil {
			continue
		}
		out.Answer = append(out.Answer, rr)
	}
	if len(out.Question) == 0 && len(req.Question) > 0 {
		out.Question = append([]dns.Question(nil), req.Question...)
	}
	return out, nil
}

func googleAnswerToRR(a googleJSONAnswer) (dns.RR, error) {
	name := dns.Fqdn(a.Name)
	ttl := a.TTL
	typ := uint16(a.Type)
	data := strings.TrimSpace(a.Data)

	switch typ {
	case dns.TypeA:
		return dns.NewRR(fmt.Sprintf("%s %d IN A %s", name, ttl, data))
	case dns.TypeAAAA:
		return dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s", name, ttl, data))
	case dns.TypeCNAME:
		if !strings.HasSuffix(data, ".") {
			data = dns.Fqdn(data)
		}
		return dns.NewRR(fmt.Sprintf("%s %d IN CNAME %s", name, ttl, data))
	case dns.TypePTR:
		if !strings.HasSuffix(data, ".") {
			data = dns.Fqdn(data)
		}
		return dns.NewRR(fmt.Sprintf("%s %d IN PTR %s", name, ttl, data))
	case dns.TypeNS:
		if !strings.HasSuffix(data, ".") {
			data = dns.Fqdn(data)
		}
		return dns.NewRR(fmt.Sprintf("%s %d IN NS %s", name, ttl, data))
	case dns.TypeTXT:
		return dns.NewRR(fmt.Sprintf("%s %d IN TXT %s", name, ttl, strconv.Quote(data)))
	case dns.TypeMX:
		return dns.NewRR(fmt.Sprintf("%s %d IN MX %s", name, ttl, data))
	case dns.TypeSRV:
		return dns.NewRR(fmt.Sprintf("%s %d IN SRV %s", name, ttl, data))
	default:
		ts := dns.TypeToString[typ]
		if ts == "" {
			ts = fmt.Sprintf("TYPE%d", typ)
		}
		return dns.NewRR(fmt.Sprintf("%s %d IN %s %s", name, ttl, ts, data))
	}
}
