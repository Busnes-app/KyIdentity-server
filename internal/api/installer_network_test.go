package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The suite status endpoint must report the existing trusted-proxy verdict, not fall through
// to the SPA, and must ignore forwarding headers from a peer outside TRUSTED_PROXY_CIDRS.
func TestInstallerNetworkReportsTrustedProxyResolution(t *testing.T) {
	base, st, syncEngine, mfaEngine, oauthEngine, cleanup := setupTestServer(t)
	defer cleanup()
	cfg := *base.cfg
	cfg.TrustedProxyCIDRs = []string{"192.0.2.7/32"}
	cfg.ForwardedHeader = "X-Forwarded-For"
	srv := NewServer(&cfg, st, base.keyManager, syncEngine, mfaEngine, oauthEngine, base.audit, nil)

	for _, trusted := range []bool{false, true} {
		r := httptest.NewRequest(http.MethodGet, "/api/installer/network", nil)
		r.RemoteAddr = "198.51.100.8:42"
		if trusted {
			r.RemoteAddr = "192.0.2.7:42"
		}
		r.Header.Set("X-Forwarded-For", "203.0.113.6")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("CF-Connecting-IP", "198.51.100.66")
		w := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(w, r)

		var report map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
			t.Fatalf("trusted=%v: not JSON (%v): %q", trusted, err, w.Body.String())
		}
		ip, scheme := "198.51.100.8", "http"
		if trusted {
			ip, scheme = "203.0.113.6", "https"
		}
		if w.Code != http.StatusOK || len(report) != 3 || report["clientIp"] != ip || report["scheme"] != scheme ||
			report["proxyHeadersTrusted"] != trusted || w.Header().Get("Cache-Control") != "no-store" ||
			w.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("trusted=%v: %d %v %s", trusted, w.Code, w.Header(), w.Body)
		}
	}
}
