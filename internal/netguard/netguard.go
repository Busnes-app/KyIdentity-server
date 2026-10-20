// Package netguard holds the outbound HTTP policy for every request the server makes to an
// operator-supplied URL. Such a URL is attacker-influenced in practice — a stolen admin
// session is enough to choose it — so it is validated when it is supplied and enforced again
// at dial time, where the address actually being connected to is known.
package netguard

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// AllowPrivate opens private LAN ranges (RFC 1918, ULA, carrier-grade NAT) to operator-supplied
// URLs, for deployments where every service shares a container network. Loopback, link-local,
// metadata and reserved addresses stay refused regardless, and device-supplied URLs never get it.
var AllowPrivate = false

// AllowLoopback lets tests reach their own httptest servers. No configuration sets it.
var AllowLoopback = false

// ErrRedirect is returned instead of following a redirect. A redirect would let a validated
// destination bounce the payload to an internal address that failed validation.
var ErrRedirect = errors.New("redirects are not followed for server-initiated requests")

// dialer refuses to connect to loopback, private, link-local, or otherwise non-public
// addresses. This is the enforcement point that survives DNS rebinding: validation at
// configuration time proves nothing about resolution at request time. device drops
// AllowPrivate, for URLs a device chose rather than the operator.
func dialer(timeout time.Duration, device bool) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("refusing to dial unparseable address %q", address)
			}
			if refused(ip, AllowPrivate && !device) {
				return fmt.Errorf("refusing to connect to the non-public address %s", ip)
			}
			return nil
		},
	}
}

// Client returns an HTTP client for operator-supplied URLs that refuses redirects and refuses
// to dial non-public addresses.
func Client(timeout time.Duration) *http.Client { return client(timeout, false) }

// DeviceClient is Client for device-supplied URLs: private ranges are refused even when
// AllowPrivate is set.
func DeviceClient(timeout time.Duration) *http.Client { return client(timeout, true) }

func client(timeout time.Duration, device bool) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error { return ErrRedirect },
		Transport: &http.Transport{
			DialContext:         dialer(timeout, device).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}
}

// refused reports whether ip must not be dialed. allowPrivate opens only privateRanges.
func refused(ip net.IP, allowPrivate bool) bool {
	switch {
	case ip.IsLoopback():
		return !AllowLoopback
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() || inAny(ip, reservedRanges):
		return true
	case ip.IsPrivate() || inAny(ip, privateRanges):
		return !allowPrivate
	}
	return false
}

func inAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// privateRanges are the LAN ranges net.IP.IsPrivate misses: carrier-grade NAT (every
// Tailscale address) and deprecated site-local.
var privateRanges = cidrs("100.64.0.0/10", "fec0::/10")

// reservedRanges are never dialed: "this" network, IETF assignments, benchmarking, class E,
// NAT64 prefixes (which embed any IPv4, metadata included), and cloud metadata services that
// sit inside a private range (Alibaba in CGNAT, AWS IPv6 in ULA).
var reservedRanges = cidrs("0.0.0.0/8", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4",
	"64:ff9b::/96", "64:ff9b:1::/48", "100.100.100.200/32", "fd00:ec2::254/128")

func cidrs(list ...string) []*net.IPNet {
	var out []*net.IPNet
	for _, cidr := range list {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// ValidateURL rejects anything the server should not be made to send data to. field names
// the offending input so the error points the operator at the right field.
func ValidateURL(raw, field string) error { return validate(raw, field, false) }

// ValidateDeviceURL is ValidateURL for device-supplied URLs: https only, no private ranges.
func ValidateDeviceURL(raw, field string) error { return validate(raw, field, true) }

func validate(raw, field string, device bool) error {
	allowPrivate := AllowPrivate && !device
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%s is required", field)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", field, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("%s must use https", field)
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("%s must include a host", field)
	}
	if parsed.User != nil {
		return fmt.Errorf("%s must not embed credentials", field)
	}
	if parsed.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("%s must not contain a fragment", field)
	}

	// A literal internal address is rejected outright. Hostnames are not resolved here:
	// resolution now proves nothing about resolution at request time, so the real
	// enforcement lives in the dialer.
	if ip := net.ParseIP(host); ip != nil && refused(ip, allowPrivate) {
		if !device && !refused(ip, true) {
			return fmt.Errorf("%s points at the private address %s; "+
				"set KYIDENTITY_ALLOW_PRIVATE_CALLBACKS=true if that is intended", field, ip)
		}
		return fmt.Errorf("%s points at the non-public address %s", field, ip)
	}
	return nil
}
