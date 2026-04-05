// udpbench: UDP/53 压力测试（miekg/dns Exchange）
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:53", "DNS 服务器 host:port")
	domain := flag.String("domain", "baidu.com.", "查询域名（需符合你方白名单/策略，否则仍会计一次请求）")
	duration := flag.Duration("d", 20*time.Second, "压测时长")
	workers := flag.Int("w", 200, "并发 worker 数")
	qps := flag.Int("qps", 0, "目标总 QPS；0=不限速尽力打满。>0 时用全局令牌桶，多 worker 并发 Exchange（可压满 RTT）")
	burst := flag.Int("burst", 0, "与 -qps 配合：rate.Limiter 突发容量；0 则取 min(qps, 100000)")
	timeout := flag.Duration("timeout", 3*time.Second, "单次 Exchange 超时")
	multiSrc := flag.Int("multi-src", 0, ">0 时 worker 绑定 127.0.0.(2+i%%N) 源地址，绕过「单 IP」rate_limit（需先在 lo 上 ip addr add 这些 /32）")
	flag.Parse()

	if *workers < 1 {
		*workers = 1
	}
	qname := dns.Fqdn(strings.TrimSpace(*domain))
	if qname == "." {
		fmt.Fprintln(os.Stderr, "empty domain")
		os.Exit(1)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.RecursionDesired = true

	deadline := time.Now().Add(*duration)
	var sent, ok, fail uint64
	var latSum int64
	var latN int64

	var wg sync.WaitGroup
	start := time.Now()

	clientFor := func(wid int) *dns.Client {
		c := &dns.Client{Net: "udp", Timeout: *timeout}
		if *multiSrc > 0 {
			oct := 2 + (wid % *multiSrc)
			if oct > 255 {
				oct = 2 + wid%253
			}
			ip := net.ParseIP(fmt.Sprintf("127.0.0.%d", oct))
			c.Dialer = &net.Dialer{LocalAddr: &net.UDPAddr{IP: ip, Port: 0}}
		}
		return c
	}

	if *qps <= 0 {
		// flood: each worker spins Exchange until deadline
		for i := 0; i < *workers; i++ {
			wid := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := clientFor(wid)
				for time.Now().Before(deadline) {
					atomic.AddUint64(&sent, 1)
					t0 := time.Now()
					r, _, err := c.Exchange(msg, *addr)
					lat := time.Since(t0).Microseconds()
					if err != nil || r == nil {
						atomic.AddUint64(&fail, 1)
						continue
					}
					atomic.AddUint64(&ok, 1)
					atomic.AddInt64(&latSum, lat)
					atomic.AddInt64(&latN, 1)
					_ = r // Rcode 非 0 仍算「有响应」
				}
			}()
		}
	} else {
		// 目标总 QPS：全局 rate.Limiter，多 worker 并发 Wait+Exchange（总速率 ≈ qps，不受单 worker RTT 串行限制）
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
			wid := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := clientFor(wid)
				for {
					if err := lim.Wait(ctx); err != nil {
						return
					}
					atomic.AddUint64(&sent, 1)
					t0 := time.Now()
					r, _, err := c.Exchange(msg, *addr)
					lat := time.Since(t0).Microseconds()
					if err != nil || r == nil {
						atomic.AddUint64(&fail, 1)
						continue
					}
					atomic.AddUint64(&ok, 1)
					atomic.AddInt64(&latSum, lat)
					atomic.AddInt64(&latN, 1)
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
		fmt.Printf("addr=%s qname=%s target_qps=%d workers=%d duration=%s\n", *addr, qname, *qps, *workers, *duration)
	} else {
		fmt.Printf("addr=%s qname=%s workers=%d duration=%s (flood)\n", *addr, qname, *workers, *duration)
	}
	fmt.Printf("elapsed=%.3fs sent=%d ok=%d fail=%d\n", elapsed, sent, ok, fail)
	fmt.Printf("achieved_send_qps=%.0f achieved_ok_qps=%.0f\n", float64(sent)/elapsed, float64(ok)/elapsed)
	if latN > 0 {
		fmt.Printf("avg_ok_latency_us=%d\n", latSum/latN)
	}
	if fail > sent/10 {
		fmt.Fprintf(os.Stderr, "\n提示: 失败率较高。若从本机压 127.0.0.1，请检查 rate_limit.qps_per_ip、白名单域名、上游与 Redis。\n")
	}
}
