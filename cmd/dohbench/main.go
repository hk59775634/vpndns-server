// dohbench: quick DoH POST load test (RFC 8484 application/dns-message).
package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

func main() {
	url := flag.String("url", "https://127.0.0.1:8053/dns-query", "DoH endpoint")
	duration := flag.Duration("d", 10*time.Second, "test duration")
	qps := flag.Int("qps", 200, "target aggregate QPS across workers")
	workers := flag.Int("w", 50, "concurrent workers")
	insecure := flag.Bool("k", false, "skip TLS certificate verification (local/dev)")
	flag.Parse()

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	wire, err := m.Pack()
	if err != nil {
		panic(err)
	}

	var ok, fail uint64
	var latSum int64
	var latN int64

	tr := &http.Transport{
		MaxIdleConns:        *workers * 2,
		MaxIdleConnsPerHost: *workers * 2,
		IdleConnTimeout:     90 * time.Second,
	}
	if *insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: tr}

	deadline := time.Now().Add(*duration)
	// each worker targets qps/workers sustained rate
	q := *qps
	if q < 1 {
		q = 1
	}
	w := *workers
	if w < 1 {
		w = 1
	}
	pause := time.Duration(float64(time.Second) * float64(w) / float64(q))

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < w; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				t0 := time.Now()
				req, err := http.NewRequest(http.MethodPost, *url, bytes.NewReader(wire))
				if err != nil {
					atomic.AddUint64(&fail, 1)
					time.Sleep(pause)
					continue
				}
				req.Header.Set("Content-Type", "application/dns-message")
				req.Header.Set("Accept", "application/dns-message")
				resp, err := client.Do(req)
				if err != nil {
					atomic.AddUint64(&fail, 1)
					time.Sleep(pause)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					atomic.AddUint64(&fail, 1)
				} else {
					atomic.AddUint64(&ok, 1)
					atomic.AddInt64(&latSum, time.Since(t0).Microseconds())
					atomic.AddInt64(&latN, 1)
				}
				elapsed := time.Since(t0)
				if elapsed < pause {
					time.Sleep(pause - elapsed)
				}
			}
		}()
	}
	wg.Wait()
	sec := time.Since(start).Seconds()

	avgMs := 0.0
	n := atomic.LoadInt64(&latN)
	if n > 0 {
		avgMs = float64(atomic.LoadInt64(&latSum)) / float64(n) / 1000.0
	}
	fmt.Printf("duration_sec=%.3f ok=%d fail=%d achieved_ok_qps=%.1f avg_latency_ms=%.3f\n",
		sec, atomic.LoadUint64(&ok), atomic.LoadUint64(&fail),
		float64(atomic.LoadUint64(&ok))/sec, avgMs)
}
