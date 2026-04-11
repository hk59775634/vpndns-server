package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/http2"

	"github.com/vpndns/cdn/internal/config"
	"github.com/vpndns/cdn/internal/models"
	"github.com/vpndns/cdn/internal/overload"
)

// Pool queries CN/OUT upstreams with DoH or UDP.
type Pool struct {
	mu         sync.RWMutex
	rngMu      sync.Mutex
	rng        *rand.Rand
	cn         []config.UpstreamSpec
	out        []config.UpstreamSpec
	timeout    time.Duration
	retries    int
	udpClient  *dns.Client
	httpClient *http.Client
	transport  *http.Transport

	udpPoolsMu sync.Mutex
	udpPools   map[string]*udpConnPoolGroup
	udpSlots   int

	orderedFallback bool
	guard           *overload.Guard

	bufPool sync.Pool // *bytes.Buffer for DoH response bodies
}

// NewPool builds a pool from runtime config slices and resolver tuning.
func NewPool(cn, out []config.UpstreamSpec, timeoutMS, retries int, c *config.Config, guard *overload.Guard) *Pool {
	if retries < 1 {
		retries = 1
	}
	tr := buildDoHTransport(c)
	httpClient := &http.Client{
		Timeout:   time.Duration(timeoutMS) * time.Millisecond,
		Transport: tr,
	}
	udpSlots := 0
	ordered := false
	if c != nil {
		udpSlots = c.Resolver.UDPConnsPerUpstream
		ordered = c.Resolver.UpstreamOrderedFallback
	}
	p := &Pool{
		cn:              cn,
		out:             out,
		rng:             rand.New(rand.NewSource(time.Now().UnixNano())),
		timeout:         time.Duration(timeoutMS) * time.Millisecond,
		retries:         retries,
		udpClient:       &dns.Client{Net: "udp", Timeout: time.Duration(timeoutMS) * time.Millisecond},
		httpClient:      httpClient,
		transport:       tr,
		udpPools:        make(map[string]*udpConnPoolGroup),
		udpSlots:        udpSlots,
		orderedFallback: ordered,
		guard:           guard,
	}
	p.bufPool.New = func() interface{} { return new(bytes.Buffer) }
	return p
}

func buildDoHTransport(c *config.Config) *http.Transport {
	maxIdle := 2048
	maxPerHost := 512
	if c != nil {
		if c.Resolver.DoHMaxIdleConns > 0 {
			maxIdle = c.Resolver.DoHMaxIdleConns
		}
		if c.Resolver.DoHMaxIdleConnsPerHost > 0 {
			maxPerHost = c.Resolver.DoHMaxIdleConnsPerHost
		}
	}
	tr := &http.Transport{
		MaxIdleConns:          maxIdle,
		MaxIdleConnsPerHost:   maxPerHost,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	_ = http2.ConfigureTransport(tr)
	return tr
}

// Reload replaces upstream lists and clears UDP connection pools.
func (p *Pool) Reload(cn, out []config.UpstreamSpec) {
	p.resetUDPPools()
	p.mu.Lock()
	p.cn = cn
	p.out = out
	p.mu.Unlock()
}

// ApplyRuntime updates transport limits, UDP pool width, fallback mode, and overload guard reference.
func (p *Pool) ApplyRuntime(c *config.Config, guard *overload.Guard) {
	if c == nil {
		return
	}
	p.resetUDPPools()
	p.mu.Lock()
	p.udpSlots = c.Resolver.UDPConnsPerUpstream
	p.orderedFallback = c.Resolver.UpstreamOrderedFallback
	p.guard = guard
	p.mu.Unlock()

	newTr := buildDoHTransport(c)
	p.mu.Lock()
	old := p.transport
	p.transport = newTr
	p.httpClient.Transport = newTr
	p.mu.Unlock()
	if old != nil {
		old.CloseIdleConnections()
	}
}

func (p *Pool) pickWeighted(list []config.UpstreamSpec) *config.UpstreamSpec {
	if len(list) == 0 {
		return nil
	}
	var total int
	for _, u := range list {
		w := u.Weight
		if w <= 0 {
			w = 1
		}
		total += w
	}
	p.rngMu.Lock()
	defer p.rngMu.Unlock()
	if total <= 0 {
		return &list[p.rng.Intn(len(list))]
	}
	r := p.rng.Intn(total)
	for i := range list {
		w := list[i].Weight
		if w <= 0 {
			w = 1
		}
		if r < w {
			return &list[i]
		}
		r -= w
	}
	return &list[0]
}

func (p *Pool) pickUpstream(list []config.UpstreamSpec, attempt int) *config.UpstreamSpec {
	if len(list) == 0 {
		return nil
	}
	p.mu.RLock()
	ordered := p.orderedFallback
	p.mu.RUnlock()
	if ordered && attempt < len(list) {
		return &list[attempt]
	}
	return p.pickWeighted(list)
}

// QueryCN runs against a weighted-random CN upstream.
func (p *Pool) QueryCN(ctx context.Context, req *models.DNSRequest, ecsIP net.IP, ecsBits int) (*models.DNSResponse, error) {
	p.mu.RLock()
	list := p.cn
	p.mu.RUnlock()
	return p.query(ctx, list, req, ecsIP, ecsBits)
}

// QueryOUT runs against a weighted-random OUT upstream.
func (p *Pool) QueryOUT(ctx context.Context, req *models.DNSRequest, ecsIP net.IP, ecsBits int) (*models.DNSResponse, error) {
	p.mu.RLock()
	list := p.out
	p.mu.RUnlock()
	return p.query(ctx, list, req, ecsIP, ecsBits)
}

func (p *Pool) query(ctx context.Context, list []config.UpstreamSpec, req *models.DNSRequest, ecsIP net.IP, ecsBits int) (*models.DNSResponse, error) {
	if len(list) == 0 {
		return nil, fmt.Errorf("no upstreams")
	}
	var lastErr error
	for attempt := 0; attempt < p.retries; attempt++ {
		u := p.pickUpstream(list, attempt)
		if u == nil {
			break
		}
		msg := req.Msg.Copy()
		msg.Id = dns.Id()
		msg.RecursionDesired = true
		if ecsIP != nil && ecsBits > 0 {
			setECS(msg, ecsIP, ecsBits)
		}
		var resp *dns.Msg
		var reqURL string
		var googleEcho string
		var err error
		func() {
			p.mu.RLock()
			g := p.guard
			p.mu.RUnlock()
			if g == nil {
				resp, reqURL, googleEcho, err = p.exchange(ctx, u, msg, ecsIP, ecsBits)
				return
			}
			release, aerr := g.AcquireUpstream(ctx)
			if aerr != nil {
				err = aerr
				return
			}
			defer release()
			resp, reqURL, googleEcho, err = p.exchange(ctx, u, msg, ecsIP, ecsBits)
		}()
		if err != nil {
			lastErr = err
			continue
		}
		if resp == nil {
			lastErr = fmt.Errorf("empty response")
			continue
		}
		return &models.DNSResponse{
			Msg:                resp,
			MinTTL:             models.MinAnswerTTL(resp, 60),
			UpstreamEndpoint:   formatUpstreamSpec(u),
			UpstreamRequestURL: reqURL,
			GoogleEchoedECS:    googleEcho,
		}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all upstreams failed")
	}
	return nil, lastErr
}

// formatUpstreamSpec returns a short label for admin logs (DoH URL vs UDP address).
func formatUpstreamSpec(u *config.UpstreamSpec) string {
	if u == nil {
		return ""
	}
	name := strings.TrimSpace(u.Name)
	if strings.TrimSpace(u.URL) != "" {
		s := strings.TrimSpace(u.URL)
		if upstreamDoHIsJSON(u) {
			s = "Google JSON GET " + s
		} else {
			s = "DoH RFC8484 " + s
		}
		if name != "" {
			return s + " (" + name + ")"
		}
		return s
	}
	if strings.TrimSpace(u.Address) != "" {
		s := "UDP " + strings.TrimSpace(u.Address)
		if name != "" {
			return s + " (" + name + ")"
		}
		return s
	}
	if name != "" {
		return name
	}
	return ""
}

func (p *Pool) exchange(ctx context.Context, u *config.UpstreamSpec, msg *dns.Msg, ecsIP net.IP, ecsBits int) (*dns.Msg, string, string, error) {
	switch {
	case strings.TrimSpace(u.URL) != "":
		useJSON, err := pickDoHExchangeJSON(u)
		if err != nil {
			return nil, "", "", err
		}
		if useJSON {
			return p.exchangeGoogleJSONResolve(ctx, u.URL, msg, ecsIP, ecsBits)
		}
		m, err := p.exchangeDoH(ctx, u.URL, msg)
		return m, "", "", err
	case strings.TrimSpace(u.Address) != "":
		m, err := p.exchangeUDP(ctx, u.Address, msg)
		return m, "", "", err
	default:
		return nil, "", "", fmt.Errorf("upstream %q has no url or address", u.Name)
	}
}

func setECS(m *dns.Msg, ip net.IP, bits int) {
	if m == nil {
		return
	}
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetUDPSize(dns.DefaultMsgSize)
	e := new(dns.EDNS0_SUBNET)
	e.Code = dns.EDNS0SUBNET
	if ip4 := ip.To4(); ip4 != nil {
		e.Family = 1
		e.SourceNetmask = uint8(bits)
		e.Address = ip4
	} else {
		e.Family = 2
		e.SourceNetmask = uint8(bits)
		e.Address = ip.To16()
	}
	o.Option = append(o.Option, e)
	m.Extra = append(m.Extra, o)
}

func (p *Pool) exchangeDoH(ctx context.Context, rawURL string, msg *dns.Msg) (*dns.Msg, error) {
	u := strings.TrimSpace(rawURL)
	if !strings.HasPrefix(u, "https://") {
		return nil, fmt.Errorf("doh url must be https")
	}
	pack, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(pack))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	p.mu.RLock()
	client := p.httpClient
	p.mu.RUnlock()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bb := p.bufPool.Get().(*bytes.Buffer)
	bb.Reset()
	defer p.bufPool.Put(bb)
	_, err = bb.ReadFrom(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	raw := bb.Bytes()
	if len(raw) > 0 && raw[0] == '<' {
		return nil, fmt.Errorf("doh: response is HTML, not DNS wire (wrong URL path? RFC 8484 DoH uses a path like /dns-query; for Google Public DNS use https://dns.google/dns-query, not https://dns.google/query)")
	}
	ans := new(dns.Msg)
	if err := ans.Unpack(raw); err != nil {
		return nil, fmt.Errorf("doh: unpack DNS message: %w", err)
	}
	return ans, nil
}

func (p *Pool) exchangeUDP(ctx context.Context, addr string, msg *dns.Msg) (*dns.Msg, error) {
	p.mu.RLock()
	slots := p.udpSlots
	client := p.udpClient
	p.mu.RUnlock()

	c := *client
	if deadline, ok := ctx.Deadline(); ok {
		c.Timeout = time.Until(deadline)
		if c.Timeout <= 0 {
			c.Timeout = p.timeout
		}
	}
	if slots <= 0 {
		r, _, err := c.ExchangeContext(ctx, msg, addr)
		return r, err
	}
	g := p.getUDPPool(addr)
	return g.exchange(ctx, &c, msg)
}
