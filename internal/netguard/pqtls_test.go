package netguard

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/pqtls"
)

func TestOutboundTLSNegotiatesHybridPQ(t *testing.T) {
	previous := AllowLoopback
	AllowLoopback = true
	t.Cleanup(func() { AllowLoopback = previous })

	serverStates := make(chan tls.ConnectionState, 4)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			serverStates <- *r.TLS
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	for _, tc := range []struct {
		name   string
		client func(time.Duration) *http.Client
	}{
		{name: "Client", client: Client},
		{name: "DeviceClient", client: DeviceClient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.client(5 * time.Second)
			tr := c.Transport.(*http.Transport)
			t.Cleanup(tr.CloseIdleConnections)
			if tr.TLSClientConfig != nil {
				t.Fatalf("expected default nil TLSClientConfig, got %+v", tr.TLSClientConfig)
			}
			// Trust only the loopback test server's certificate; keep Go's default TLS groups.
			tr.TLSClientConfig = &tls.Config{RootCAs: pool}

			resp, err := c.Get(srv.URL)
			if err != nil {
				t.Fatalf("GET %s: %v", srv.URL, err)
			}
			resp.Body.Close()
			if resp.TLS == nil {
				t.Fatal("missing response TLS state")
			}
			pqtls.RequireHybrid(t, *resp.TLS)
			pqtls.RequireHybrid(t, <-serverStates)
		})
	}

	t.Run("Dialer", func(t *testing.T) {
		conn, err := tls.DialWithDialer(Dialer(5*time.Second), "tcp", srv.Listener.Addr().String(), &tls.Config{
			RootCAs:    pool,
			ServerName: "127.0.0.1",
		})
		if err != nil {
			t.Fatalf("tls.DialWithDialer: %v", err)
		}
		defer conn.Close()
		pqtls.RequireHybrid(t, conn.ConnectionState())
	})
}
