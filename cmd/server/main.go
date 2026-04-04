package main

import (
	"context"
	"crypto/tls"
	"embed"
	"flag"
	"io/fs"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"

	"github.com/vpndns/cdn/internal/api"
	"github.com/vpndns/cdn/internal/cache"
	"github.com/vpndns/cdn/internal/config"
	dnsserver "github.com/vpndns/cdn/internal/dns"
	"github.com/vpndns/cdn/internal/doh"
	"github.com/vpndns/cdn/internal/geoip"
	"github.com/vpndns/cdn/internal/mapper"
	"github.com/vpndns/cdn/internal/metrics"
	"github.com/vpndns/cdn/internal/overload"
	"github.com/vpndns/cdn/internal/ratelimit"
	"github.com/vpndns/cdn/internal/resolver"
	"github.com/vpndns/cdn/internal/stats"
	"github.com/vpndns/cdn/internal/subscribe"
	"github.com/vpndns/cdn/internal/tlscfg"
	"github.com/vpndns/cdn/internal/upstream"
	"github.com/vpndns/cdn/internal/warmup"
	"github.com/vpndns/cdn/internal/whitelist"
)

//go:embed all:web/static
var webStatic embed.FS

func main() {
	rand.Seed(time.Now().UnixNano())
	var cfgPathFlag string
	flag.StringVar(&cfgPathFlag, "config", "", "path to YAML config (overrides CONFIG env; default configs/config.yaml)")
	flag.Parse()

	cfgPath := cfgPathFlag
	if cfgPath == "" {
		cfgPath = os.Getenv("CONFIG")
	}
	if cfgPath == "" {
		cfgPath = "configs/config.yaml"
	}
	c, err := config.Load(cfgPath)
	if err != nil {
		log.Printf("load config %s: %v", cfgPath, err)
		os.Exit(1)
	}
	if err := config.Validate(c); err != nil {
		log.Printf("invalid config: %v", err)
		os.Exit(1)
	}
	store := config.NewStore(c)

	poolFIFO := true
	if c.Redis.PoolFIFO != nil {
		poolFIFO = *c.Redis.PoolFIFO
	}
	rdb := redis.NewClient(&redis.Options{
		Addr:         c.Redis.Addr,
		Password:     c.Redis.Password,
		DB:           c.Redis.DB,
		PoolSize:     c.Redis.PoolSize,
		MinIdleConns: c.Redis.MinIdleConns,
		PoolFIFO:     poolFIFO,
	})
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Printf("redis ping: %v", err)
		os.Exit(1)
	}

	rc := cache.NewRedis(rdb)
	mapperSvc := mapper.New(rdb, c.Mapper.APIURL, c.Mapper.TTL, c.Mapper.PublicIPProbeURL, c.Mapper.HTTPMaxIdleConns, c.Mapper.HTTPMaxIdleConnsPerHost)
	wl := whitelist.New(rdb)
	_ = wl.LoadFromRedis(ctx)
	cn := geoip.New(config.ResolveGeoIPDownloadURL(c), c.GeoIP.RefreshMin, c.GeoIP.SourceFormat)
	cn.Start(ctx)

	guard := overload.NewGuard()
	reloadGuard := func(cfg *config.Config) {
		if cfg == nil {
			return
		}
		guard.Reload(int64(cfg.Resolver.MaxInflightUpstream), cfg.Resolver.GlobalResolveQPS, cfg.Resolver.GlobalResolveBurst)
	}
	reloadGuard(c)

	pool := upstream.NewPool(c.CNDNS, c.OUTDNS, c.Resolver.QueryTimeoutMS, c.Resolver.UpstreamRetries, c, guard)
	l1 := cache.NewL1(c.Resolver.L1CacheMaxEntries, c.Resolver.L1CacheTTLCapSeconds)
	res := resolver.New(store, rc, l1, mapperSvc, wl, cn, pool, guard)

	rl := ratelimit.New(*c.RateLimit.QPSPerIP, *c.RateLimit.Burst)
	st := stats.New()
	st.Restore(ctx, rdb, c.Stats.RedisKey)

	var dnsSrv *dnsserver.Server
	var apiSrv *api.Server
	applyRuntime := func(c *config.Config) {
		reloadGuard(c)
		pool.Reload(c.CNDNS, c.OUTDNS)
		pool.ApplyRuntime(c, guard)
		if dnsSrv != nil {
			dnsSrv.ReloadSecurity(c.Security.Blacklist)
		}
		mapperSvc.Reload(c.Mapper.APIURL, c.Mapper.TTL, c.Mapper.PublicIPProbeURL, c.Mapper.HTTPMaxIdleConns, c.Mapper.HTTPMaxIdleConnsPerHost)
		rl.Reload(*c.RateLimit.QPSPerIP, *c.RateLimit.Burst)
		cn.SetSource(config.ResolveGeoIPDownloadURL(c), c.GeoIP.RefreshMin, c.GeoIP.SourceFormat)
		if apiSrv != nil {
			apiSrv.SyncSessionSecretFromConfig()
		}
	}
	apiSrv = api.New(cfgPath, store, rdb, rc, wl, cn, pool, applyRuntime, st)
	dnsSrv = dnsserver.New(store, res, rl, apiSrv.PushLog, st)

	dohS := doh.New(store, res, rl, apiSrv.PushLog, st)

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go rl.RunPruneLoop(rootCtx, time.Duration(c.RateLimit.PerIPLimiterIdleMinutes)*time.Minute)

	if c.Stats.PersistIntervalSec > 0 {
		go st.RunPersistLoop(rootCtx, rdb, c.Stats.RedisKey, time.Duration(c.Stats.PersistIntervalSec)*time.Second)
	}

	metrics.RegisterVPNDNS(st, cn)

	go warmup.Run(context.Background(), res, c.Warmup.Domains, c.Warmup.QTypes)

	if err := store.Watch(rootCtx, cfgPath, applyRuntime); err != nil {
		log.Printf("config watch: %v", err)
	}

	go func() {
		if err := dnsSrv.ServeUDP(rootCtx, c.Listen.UDP); err != nil {
			log.Printf("dns udp: %v", err)
		}
	}()
	go func() {
		if err := dnsSrv.ServeTCP(rootCtx, c.Listen.TCP); err != nil {
			log.Printf("dns tcp: %v", err)
		}
	}()

	go subscribe.RunWhitelistPull(rootCtx, rdb, c.Whitelist.SubscribeURLs, time.Duration(c.Whitelist.RefreshMin)*time.Minute)
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-t.C:
				_ = wl.LoadFromRedis(context.Background())
			}
		}
	}()

	adminMux := http.NewServeMux()
	adminMux.Handle("/metrics", promhttp.Handler())
	apiSrv.Handler(adminMux)
	sub, err := fs.Sub(webStatic, "web/static")
	if err != nil {
		log.Printf("embed static: %v", err)
		os.Exit(1)
	}
	adminMux.Handle("/", http.FileServer(http.FS(sub)))

	admin := &http.Server{
		Addr:              c.Listen.Admin,
		Handler:           adminMux,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		log.Printf("admin ui %s (metrics /metrics)", c.Listen.Admin)
		if err := admin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("admin server: %v", err)
		}
	}()

	dohMux := http.NewServeMux()
	dohMux.Handle("/dns-query", dohS.Handler())
	dohSrv := &http.Server{
		Addr:              c.Listen.DoH,
		Handler:           dohMux,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       180 * time.Second,
	}
	go func() {
		log.Printf("doh %s tls=%v", c.Listen.DoH, c.Listen.DoHTLS)
		var err error
		if !c.Listen.DoHTLS {
			err = dohSrv.ListenAndServe()
		} else {
			tcert, usePEM, e := tlscfg.Certificate(c)
			if e != nil {
				log.Printf("doh tls: inline PEM parse error: %v", e)
			}
			if usePEM && e == nil {
				// ALPN：无 NextProtos 时客户端无法协商 h2，curl --http2 会退回 HTTP/1.1
				dohSrv.TLSConfig = &tls.Config{
					Certificates: []tls.Certificate{tcert},
					MinVersion:   tls.VersionTLS12,
					NextProtos:   []string{"h2", "http/1.1"},
				}
				ln, e2 := net.Listen("tcp", c.Listen.DoH)
				if e2 != nil {
					log.Printf("doh listen: %v", e2)
					return
				}
				tlsLn := tls.NewListener(ln, dohSrv.TLSConfig)
				err = dohSrv.Serve(tlsLn)
			} else if c.Listen.TLSCert != "" && c.Listen.TLSKey != "" {
				err = dohSrv.ListenAndServeTLS(c.Listen.TLSCert, c.Listen.TLSKey)
			} else {
				log.Printf("doh_tls enabled but no certificate: falling back to plain HTTP on %s", c.Listen.DoH)
				err = dohSrv.ListenAndServe()
			}
		}
		if err != nil && err != http.ErrServerClosed {
			log.Printf("doh server: %v", err)
		}
	}()

	dnsSrv.ReloadSecurity(c.Security.Blacklist)

	<-rootCtx.Done()
	log.Println("shutting down")
	shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = admin.Shutdown(shCtx)
	_ = dohSrv.Shutdown(shCtx)
	_ = st.Persist(context.Background(), rdb, c.Stats.RedisKey)
	_ = rdb.Close()
}
