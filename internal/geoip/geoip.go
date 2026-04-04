package geoip

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GeoIP list source formats (config geoip.source_format).
const (
	SourceFormatCIDR     = "cidr"
	SourceFormatGeoIPDat = "geoip_dat"
)

// CN holds China CIDR list for classification.
type CN struct {
	mu        sync.RWMutex
	v4ranges  []ipv4Range
	v6nets    []*net.IPNet
	netTotal  int // raw CIDR rows (pre-merge), for metrics
	v4Count   int
	v6Count   int
	cidrLines []string // canonical CIDR per parsed row (for admin listing)
	client    *http.Client
	refresh   time.Duration
	url       string
	format    string // SourceFormatCIDR or SourceFormatGeoIPDat
}

func New(chnrouteURL string, refreshMin int, sourceFormat string) *CN {
	if refreshMin <= 0 {
		refreshMin = 1440
	}
	f := strings.ToLower(strings.TrimSpace(sourceFormat))
	if f == "" {
		f = SourceFormatCIDR
	}
	if f != SourceFormatCIDR && f != SourceFormatGeoIPDat {
		f = SourceFormatCIDR
	}
	return &CN{
		url:     chnrouteURL,
		format:  f,
		refresh: time.Duration(refreshMin) * time.Minute,
		client: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        8,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  false,
			},
		},
	}
}

// Start periodic refresh in background.
func (g *CN) Start(ctx context.Context) {
	_ = g.Refresh(ctx)
	go func() {
		t := time.NewTicker(g.refresh)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = g.Refresh(context.Background())
			}
		}
	}()
}

// SetSource updates download URL, format, and desired refresh interval (periodic ticker unchanged until process restart).
func (g *CN) SetSource(chnrouteURL string, refreshMin int, sourceFormat string) {
	if refreshMin <= 0 {
		refreshMin = 1440
	}
	f := strings.ToLower(strings.TrimSpace(sourceFormat))
	if f == "" {
		f = SourceFormatCIDR
	}
	if f != SourceFormatCIDR && f != SourceFormatGeoIPDat {
		f = SourceFormatCIDR
	}
	g.mu.Lock()
	g.url = chnrouteURL
	g.format = f
	g.refresh = time.Duration(refreshMin) * time.Minute
	g.mu.Unlock()
}

// Refresh downloads and parses chnroute list (one CIDR per line).
func (g *CN) Refresh(ctx context.Context) error {
	g.mu.RLock()
	u := g.url
	g.mu.RUnlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("chnroute http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	g.mu.RLock()
	srcFmt := g.format
	g.mu.RUnlock()
	var nets []*net.IPNet
	switch srcFmt {
	case SourceFormatGeoIPDat:
		nets, err = parseV2RayGeoIPDat(body)
		if err != nil {
			return fmt.Errorf("parse geoip.dat: %w", err)
		}
	default:
		nets, err = parseCIDRList(bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("parse chnroute: %w", err)
		}
		if len(nets) == 0 {
			return fmt.Errorf("parse chnroute: no CIDR rows")
		}
	}
	lines := make([]string, 0, len(nets))
	var v4, v6 []*net.IPNet
	v4c, v6c := 0, 0
	for _, n := range nets {
		lines = append(lines, n.String())
		if n.IP.To4() != nil {
			v4 = append(v4, n)
			v4c++
		} else {
			v6 = append(v6, n)
			v6c++
		}
	}
	g.mu.Lock()
	g.v4ranges = buildIPv4Ranges(v4)
	g.v6nets = v6
	g.netTotal = len(nets)
	g.v4Count = v4c
	g.v6Count = v6c
	g.cidrLines = lines
	g.mu.Unlock()
	return nil
}

func parseCIDRList(r io.Reader) ([]*net.IPNet, error) {
	var out []*net.IPNet
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		s := parts[0]
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				if ip4 := ip.To4(); ip4 != nil {
					s = ip4.String() + "/32"
				} else {
					s = ip.String() + "/128"
				}
			}
		}
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		out = append(out, ipNet)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Contains reports whether ip is inside mainland CN CIDRs.
func (g *CN) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.To4() != nil {
		g.mu.RLock()
		rs := g.v4ranges
		g.mu.RUnlock()
		return containsV4Ranges(rs, ip)
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, n := range g.v6nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// NetCount returns number of CIDR rows last loaded from chnroute.
func (g *CN) NetCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.netTotal
}

// Counts returns total CIDR rows and IPv4 / IPv6 split from the last successful refresh.
func (g *CN) Counts() (total, v4, v6 int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.netTotal, g.v4Count, g.v6Count
}

// CIDRListPage returns a slice of CIDR strings for the given 1-based page.
// perPage is clamped to [1, 500].
func (g *CN) CIDRListPage(page, perPage int) (total, v4, v6 int, rows []string) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	total = len(g.cidrLines)
	v4, v6 = g.v4Count, g.v6Count
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 100
	}
	if perPage > 500 {
		perPage = 500
	}
	start := (page - 1) * perPage
	if start >= total || total == 0 {
		return total, v4, v6, nil
	}
	end := start + perPage
	if end > total {
		end = total
	}
	rows = make([]string, end-start)
	copy(rows, g.cidrLines[start:end])
	return total, v4, v6, rows
}

// ClassifyIPs returns (allCN, cnIPs, outIPs).
func (g *CN) ClassifyIPs(ips []net.IP) (allCN bool, cn, out []net.IP) {
	if len(ips) == 0 {
		return true, nil, nil
	}
	for _, ip := range ips {
		if g.Contains(ip) {
			cn = append(cn, ip)
		} else {
			out = append(out, ip)
		}
	}
	allCN = len(out) == 0
	return allCN, cn, out
}
