package config

import (
	"fmt"
	"net"
	"strings"
)

// Inputs have already passed loadTrustedProxies and loadForwardedHeader. A broad
// multi-hop trust chain cannot distinguish a proxy-appended hop from client input.
func validateProxyTrust(cidrs []string, header string) error {
	if !strings.EqualFold(header, "X-Forwarded-For") && !strings.EqualFold(header, "Forwarded") {
		return nil
	}
	for _, cidr := range cidrs {
		_, network, _ := net.ParseCIDR(cidr)
		ones, bits := network.Mask.Size()
		// Go's IPNet.Contains treats IPv4-mapped networks as IPv4 too.
		if bits == 128 && network.IP.To4() != nil {
			ones, bits = ones-96, 32
		}
		floor := 7 // IPv6 ULA: fc00::/7.
		if bits == 32 {
			floor = 8 // RFC 1918's widest block: 10.0.0.0/8.
			if network.Contains(net.ParseIP("172.16.0.0")) {
				floor = 12
			}
			if network.Contains(net.ParseIP("192.168.0.0")) {
				floor = 16
			}
		}
		if ones < floor {
			return fmt.Errorf("TRUSTED_PROXY_CIDRS range %s is too broad for KYIDENTITY_FORWARDED_HEADER=%s; narrow trust to the proxy address (/32 or /128), or select a single-IP header the proxy must overwrite (Cloudflare: KYIDENTITY_FORWARDED_HEADER=CF-Connecting-IP). With broad trust, only that proxy may reach the KyIdentity port", cidr, header)
		}
	}
	return nil
}
