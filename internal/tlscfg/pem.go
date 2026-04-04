package tlscfg

import (
	"crypto/tls"
	"strings"

	"github.com/vpndns/cdn/internal/config"
)

// Certificate returns TLS certificate from inline PEM or file paths.
func Certificate(c *config.Config) (cert tls.Certificate, use bool, err error) {
	if c == nil {
		return tls.Certificate{}, false, nil
	}
	ce := strings.TrimSpace(c.Listen.TLSCertPEM)
	ke := strings.TrimSpace(c.Listen.TLSKeyPEM)
	if ce != "" && ke != "" {
		cert, err = tls.X509KeyPair([]byte(ce), []byte(ke))
		return cert, true, err
	}
	return tls.Certificate{}, false, nil
}
