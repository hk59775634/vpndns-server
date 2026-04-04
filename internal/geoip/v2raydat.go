package geoip

import (
	"fmt"
	"net"
	"strings"

	"google.golang.org/protobuf/proto"
)

// SourceFormatGeoIPDat expects a V2Ray-style geoip.dat (protobuf GeoIPList), e.g. Loyalsoldier releases.
// Only country code CN is loaded into the in-memory classifier.
func parseV2RayGeoIPDat(data []byte) ([]*net.IPNet, error) {
	var list v2rayGeoIPList
	if err := proto.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("geoip.dat protobuf: %w", err)
	}
	var out []*net.IPNet
	for _, e := range list.GetEntry() {
		if !strings.EqualFold(strings.TrimSpace(e.GetCountryCode()), "cn") {
			continue
		}
		for _, c := range e.GetCidr() {
			ipb := c.GetIp()
			prefix := c.GetPrefix()
			if len(ipb) != 4 && len(ipb) != 16 {
				continue
			}
			ip := net.IP(ipb)
			if len(ipb) == 4 {
				ip = ip.To4()
			}
			if ip == nil {
				continue
			}
			_, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), prefix))
			if err != nil {
				continue
			}
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("geoip.dat: no CN CIDR entries found")
	}
	return out, nil
}
