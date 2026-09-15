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

// AllowPrivate permits outbound requests to loopback and private ranges. Deployments where
// every service shares a container network need this; it is off by default because an
// operator-supplied URL is otherwise a request forgery primitive aimed at the internal
// network, including the cloud metadata endpoint.
var AllowPrivate = false

// ErrRedirect is returned instead of following a redirect. A redirect would let a validated
// destination bounce the payload to an internal address that failed validation.
var ErrRedirect = errors.New("redirects are not followed for server-initiated requests")

// Dialer refuses to connect to loopback, private, link-local, or otherwise non-public
// addresses. This is the enforcement point that survives DNS rebinding: validation at
// configuration time proves nothing about resolution at request time.
func Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			if AllowPrivate {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("refusing to dial unparseable address %q", address)
			}
			if isNonPublic(ip) {
				return fmt.Errorf("refusing to connect to the non-public address %s", ip)
			}
			return nil
		},
	}
}

// Client returns an HTTP client that refuses redirects and refuses to dial non-public
// addresses.
func Client(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error { return ErrRedirect },
		Transport: &http.Transport{
			DialContext:         Dialer(timeout).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}
}

func isNonPublic(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast()
}

// ValidateURL rejects anything the server should not be made to send data to. field names
// the offending input so the error points the operator at the right field.
func ValidateURL(raw, field string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%s is required", field)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", field, err)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && AllowPrivate) {
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
	if AllowPrivate {
		return nil
	}

	// A literal internal address is rejected outright. Hostnames are not resolved here:
	// resolution now proves nothing about resolution at request time, so the real
	// enforcement lives in the dialer.
	if ip := net.ParseIP(host); ip != nil && isNonPublic(ip) {
		return fmt.Errorf("%s points at the non-public address %s; "+
			"set KYIDENTITY_ALLOW_PRIVATE_CALLBACKS=true if that is intended", field, ip)
	}
	return nil
}
