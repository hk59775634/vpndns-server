package warmup

import (
	"context"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/vpndns/cdn/internal/models"
	"github.com/vpndns/cdn/internal/resolver"
)

// Run resolves configured names once at startup to seed Redis cache.
func Run(ctx context.Context, res *resolver.Resolver, domains []string, qtypes []string) {
	if res == nil || len(domains) == 0 {
		return
	}
	if len(qtypes) == 0 {
		qtypes = []string{"A"}
	}
	for _, raw := range domains {
		d := strings.TrimSpace(strings.ToLower(raw))
		if d == "" {
			continue
		}
		name := dns.Fqdn(d)
		for _, qt := range qtypes {
			var code uint16
			switch strings.ToUpper(strings.TrimSpace(qt)) {
			case "AAAA":
				code = dns.TypeAAAA
			default:
				code = dns.TypeA
			}
			msg := new(dns.Msg)
			msg.SetQuestion(name, code)
			req := &models.DNSRequest{Msg: msg, ClientVIP: "127.0.0.1"}
			cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			_, _ = res.Resolve(cctx, req)
			cancel()
		}
	}
}
