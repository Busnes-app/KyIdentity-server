package main

import "net"

// Inputs have already passed config.loadTrustedProxies. Warn only; the operator
// owns port isolation, and a warning cannot make catch-all X-Forwarded-For safe.
func warnWideTrustedProxies(cidrs []string, logf func(string, ...any)) {
	for _, cidr := range cidrs {
		_, network, _ := net.ParseCIDR(cidr)
		ones, bits := network.Mask.Size()
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
			logf("WARNING: TRUSTED_PROXY_CIDRS range %s is wider than a private block; list the proxy's exact address instead. Use a catch-all (0.0.0.0/0 or ::/0) only when the tunnel alone can reach the port, with KYIDENTITY_FORWARDED_HEADER=CF-Connecting-IP for Cloudflare. Catch-all trust with X-Forwarded-For still allows forged client addresses.", cidr)
		}
	}
}
