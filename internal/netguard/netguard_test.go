package netguard

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateURLRejectsRequestForgeryTargets(t *testing.T) {
	AllowPrivate = false
	rejected := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:5867/api/admin/users",
		"http://[::1]:8080/hook",
		"https://10.89.0.2/internal",
		"https://192.168.1.1/",
		"https://172.16.0.5/",
		"file:///etc/passwd",
		"gopher://evil.test/_x",
		"http://example.test/insecure",
		"https://user:pass@example.test/",
		"https://example.test/#frag",
		"https://",
		"not a url at all",
		"",
	}
	for _, target := range rejected {
		if err := ValidateURL(target, "url"); err == nil {
			t.Errorf("%q was accepted", target)
		}
	}

	if err := ValidateURL("https://recovery.example.test/base", "url"); err != nil {
		t.Errorf("a public https URL was rejected: %v", err)
	}
}

// Validation at configuration time proves nothing about resolution at request time, so the
// dialer is the enforcement point that has to hold.
func TestGuardedClientRefusesToDialPrivateAddresses(t *testing.T) {
	AllowPrivate = false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the guarded client reached a loopback server")
	}))
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Client(5 * time.Second).Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("the guarded client connected to loopback")
	}
	if !strings.Contains(err.Error(), "non-public") {
		t.Errorf("expected a non-public address refusal, got %v", err)
	}
}

// A redirect would let a destination that passed validation bounce the request to one that
// would not have.
func TestGuardedClientRefusesRedirects(t *testing.T) {
	AllowPrivate, AllowLoopback = true, true // let the test reach its own loopback servers
	defer func() { AllowPrivate, AllowLoopback = false, false }()

	var reached bool
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer internal.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL, http.StatusFound)
	}))
	defer redirector.Close()

	req, _ := http.NewRequest(http.MethodGet, redirector.URL, nil)
	resp, err := Client(5 * time.Second).Do(req)
	if err == nil {
		resp.Body.Close()
	}
	if reached {
		t.Error("the guarded client followed a redirect to a second host")
	}
}

// Carrier-grade NAT is every Tailscale address; NAT64 embeds any IPv4 (metadata included).
func TestReservedRangesAreNonPublic(t *testing.T) {
	for _, ip := range []string{"100.64.0.1", "100.100.100.100", "64:ff9b::a9fe:a9fe", "198.18.0.1", "0.1.2.3", "192.0.0.8", "240.0.0.1", "fec0::1"} {
		if !refused(net.ParseIP(ip), false) {
			t.Errorf("%s treated as public", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "100.128.0.1", "2606:4700::1111"} {
		if refused(net.ParseIP(ip), false) {
			t.Errorf("%s treated as non-public", ip)
		}
	}
}

// AllowPrivate opens LAN ranges only: loopback, link-local and metadata stay refused.
func TestAllowPrivateOpensOnlyLANRanges(t *testing.T) {
	AllowPrivate = true
	defer func() { AllowPrivate = false }()
	for _, raw := range []string{
		"http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/latest/meta-data/",
		"http://[fe80::1]/", "http://0.0.0.0/", "http://[::]/", "http://100.100.100.200/",
		"http://[fd00:ec2::254]/", "http://[64:ff9b::a9fe:a9fe]/", "http://224.0.0.1/",
	} {
		if err := ValidateURL(raw, "url"); err == nil {
			t.Errorf("%s accepted with AllowPrivate", raw)
		}
	}
	for _, raw := range []string{"https://10.89.0.2/", "https://192.168.1.1/", "https://172.16.0.5/", "https://100.64.0.1/", "https://[fd12::1]/"} {
		if err := ValidateURL(raw, "url"); err != nil {
			t.Errorf("%s rejected with AllowPrivate: %v", raw, err)
		}
		if err := ValidateDeviceURL(raw, "url"); err == nil {
			t.Errorf("%s accepted as a device URL", raw)
		}
	}
	AllowPrivate = false
	if err := ValidateURL("https://10.89.0.2/", "url"); err == nil {
		t.Error("10.89.0.2 accepted without AllowPrivate")
	}
}

// The dialer is the real enforcement point, so the same policy has to hold there.
func TestDialerPolicy(t *testing.T) {
	AllowPrivate = true
	defer func() { AllowPrivate = false }()
	for _, tc := range []struct {
		addr          string
		device, allow bool
	}{
		{"127.0.0.1:443", false, false},
		{"169.254.169.254:80", false, false},
		{"[fe80::1]:443", false, false},
		{"10.0.0.1:443", true, false},
		{"10.0.0.1:443", false, true},
	} {
		err := dialer(time.Second, tc.device).Control("tcp", tc.addr, nil)
		if tc.allow != (err == nil) {
			t.Errorf("%s device=%v: err = %v", tc.addr, tc.device, err)
		}
	}
	AllowPrivate = false
	if dialer(time.Second, false).Control("tcp", "10.0.0.1:443", nil) == nil {
		t.Error("10.0.0.1 allowed without AllowPrivate")
	}
}

// A device URL never reaches a private address at dial time, whatever AllowPrivate says.
func TestDeviceClientRefusesPrivateDialWithAllowPrivate(t *testing.T) {
	AllowPrivate = true
	defer func() { AllowPrivate = false }()
	resp, err := DeviceClient(2 * time.Second).Get("https://10.255.255.1/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("device client dialed a private address")
	}
	if !strings.Contains(err.Error(), "non-public") {
		t.Errorf("expected a non-public refusal, got %v", err)
	}
}

func TestPrivateCallbacksStillRequireHTTPS(t *testing.T) {
	AllowPrivate = true
	defer func() { AllowPrivate = false }()
	for _, target := range []string{"http://10.89.0.2/hook", "http://public.example/hook"} {
		if ValidateURL(target, "callback") == nil {
			t.Fatal("allowed plaintext", target)
		}
	}
	if err := ValidateURL("https://10.89.0.2/hook", "callback"); err != nil {
		t.Fatal(err)
	}
}
