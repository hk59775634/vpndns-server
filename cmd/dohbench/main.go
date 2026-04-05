// dohbench: DoH 压测，模式与 cmd/udpbench 对齐。
// -style rfc8484：Cloudflare 等通用的 RFC 8484 POST（application/dns-message）
// -style google：Google 公共 DNS 兼容的 GET /resolve（application/dns-json）
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

func main() {
	urlStr := flag.String("url", "http://127.0.0.1:8053/dns-query", "DoH URL：rfc8484 为完整 POST 地址（…/dns-query）；google 可为服务根或 …/resolve")
	style := flag.String("style", "rfc8484", "rfc8484=POST dns-message（Cloudflare 标准）| google=GET /resolve JSON（Google 标准）")
	domain := flag.String("domain", "example.com.", "查询域名")
	duration := flag.Duration("d", 20*time.Second, "压测时长")
	workers := flag.Int("w", 200, "并发 worker 数")
	qps := flag.Int("qps", 0, "目标总 QPS；0=不限速尽力打满。>0 时全局令牌桶 + 多 worker 并发 HTTP")
	burst := flag.Int("burst", 0, "与 -qps 配合：rate.Limiter 突发；0 则取 min(qps, 100000)")
	timeout := flag.Duration("timeout", 15*time.Second, "单次 HTTP 超时")
	insecure := flag.Bool("k", false, "HTTPS 时跳过证书校验（本地自签）")
	token := flag.String("token", "", "若 DoH 开启 Bearer 鉴权，在此填 token（等价 Authorization: Bearer）")
	flag.Parse()

	if *workers < 1 {
		*workers = 1
	}
	st := strings.ToLower(strings.TrimSpace(*style))
	if st != "rfc8484" && st != "google" {
		fmt.Fprintln(os.Stderr, "-style must be rfc8484 or google")
		os.Exit(1)
	}
	qname := dns.Fqdn(strings.TrimSpace(*domain))
	if qname == "." {
		fmt.Fprintln(os.Stderr, "empty domain")
		os.Exit(1)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.RecursionDesired = true
	wire, err := msg.Pack()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	deadline := time.Now().Add(*duration)
	var sent, ok, fail uint64
	var latSum int64
	var latN int64

	tr := &http.Transport{
		MaxIdleConns:        *workers * 4,
		MaxIdleConnsPerHost: *workers * 4,
		ForceAttemptHTTP2:   true,
		IdleConnTimeout:     90 * time.Second,
	}
	if strings.HasPrefix(strings.ToLower(*urlStr), "https://") && *insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	}
	client := &http.Client{Timeout: *timeout, Transport: tr}

	var wg sync.WaitGroup
	start := time.Now()

	doOne := func(ctx context.Context) bool {
		var req *http.Request
		var err error
		if st == "rfc8484" {
			body := bytes.NewReader(wire)
			req, err = http.NewRequestWithContext(ctx, http.MethodPost, *urlStr, body)
			if err != nil {
				return false
			}
			req.Header.Set("Content-Type", "application/dns-message")
			req.Header.Set("Accept", "application/dns-message")
		} else {
			u, perr := url.Parse(*urlStr)
			if perr != nil {
				return false
			}
			p := strings.TrimSuffix(u.Path, "/")
			switch {
			case strings.HasSuffix(p, "/resolve"):
				u.Path = p
			case strings.HasSuffix(p, "/dns-query"):
				u.Path = strings.TrimSuffix(p, "/dns-query") + "/resolve"
			case p == "":
				u.Path = "/resolve"
			default:
				u.Path = p + "/resolve"
			}
			q := u.Query()
			q.Set("name", strings.TrimSuffix(qname, "."))
			q.Set("type", strconv.Itoa(int(msg.Question[0].Qtype)))
			u.RawQuery = q.Encode()
			req, err = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			if err != nil {
				return false
			}
			req.Header.Set("Accept", "application/dns-json")
		}
		if t := strings.TrimSpace(*token); t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
		}
		t0 := time.Now()
		resp, err := client.Do(req)
		lat := time.Since(t0).Microseconds()
		if err != nil {
			return false
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if rerr != nil {
			return false
		}
		if resp.StatusCode != http.StatusOK {
			return false
		}
		if st == "rfc8484" {
			atomic.AddInt64(&latSum, lat)
			atomic.AddInt64(&latN, 1)
			return true
		}
		var gj struct {
			Status int `json:"Status"`
		}
		if json.Unmarshal(body, &gj) != nil {
			return false
		}
		if gj.Status != 0 {
			return false
		}
		atomic.AddInt64(&latSum, lat)
		atomic.AddInt64(&latN, 1)
		return true
	}

	if *qps <= 0 {
		for i := 0; i < *workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Now().Before(deadline) {
					ctx, cancel := context.WithTimeout(context.Background(), *timeout)
					atomic.AddUint64(&sent, 1)
					if doOne(ctx) {
						atomic.AddUint64(&ok, 1)
					} else {
						atomic.AddUint64(&fail, 1)
					}
					cancel()
				}
			}()
		}
	} else {
		q := *qps
		if q < 1 {
			q = 1
		}
		w := *workers
		b := *burst
		if b <= 0 {
			b = q
			if b > 100000 {
				b = 100000
			}
		}
		lim := rate.NewLimiter(rate.Limit(q), b)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		for i := 0; i < w; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					if err := lim.Wait(ctx); err != nil {
						return
					}
					rctx, rcancel := context.WithTimeout(ctx, *timeout)
					atomic.AddUint64(&sent, 1)
					if doOne(rctx) {
						atomic.AddUint64(&ok, 1)
					} else {
						atomic.AddUint64(&fail, 1)
					}
					rcancel()
				}
			}()
		}
	}

	wg.Wait()
	elapsed := time.Since(start).Seconds()
	if elapsed < 0.001 {
		elapsed = 0.001
	}

	if *qps > 0 {
		fmt.Printf("style=%s url=%s qname=%s target_qps=%d workers=%d duration=%s\n", st, *urlStr, qname, *qps, *workers, *duration)
	} else {
		fmt.Printf("style=%s url=%s qname=%s workers=%d duration=%s (flood)\n", st, *urlStr, qname, *workers, *duration)
	}
	fmt.Printf("elapsed=%.3fs sent=%d ok=%d fail=%d\n", elapsed, sent, ok, fail)
	fmt.Printf("achieved_send_qps=%.0f achieved_ok_qps=%.0f\n", float64(sent)/elapsed, float64(ok)/elapsed)
	if latN > 0 {
		fmt.Printf("avg_ok_latency_us=%d\n", latSum/latN)
	}
	if fail > sent/10 {
		fmt.Fprintf(os.Stderr, "\n提示: 失败率较高。检查 URL、-style、DoH TLS（-k）、Bearer（-token）、rate_limit、上游与 Redis。\n")
	}
}
