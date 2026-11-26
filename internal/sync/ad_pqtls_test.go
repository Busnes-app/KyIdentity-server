package sync

import (
	"bytes"
	"crypto/tls"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/pqtls"
	"github.com/Busnes-app/kyidentity-server/internal/ldaptest"
	"github.com/Busnes-app/kyidentity-server/internal/netguard"
)

func TestADLDAPSNegotiatesHybridPQ(t *testing.T) {
	previous := netguard.AllowLoopback
	netguard.AllowLoopback = true
	t.Cleanup(func() { netguard.AllowLoopback = previous })

	t.Run("tls_config", func(t *testing.T) {
		cert, caPEM := ldaptest.Selfsigned(t)
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
		if err != nil {
			t.Fatalf("tls.Listen: %v", err)
		}
		t.Cleanup(func() { ln.Close() })

		serverStateCh := make(chan tls.ConnectionState, 1)
		serverErrCh := make(chan error, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				serverErrCh <- err
				return
			}
			defer c.Close()
			tc := c.(*tls.Conn)
			if err := tc.Handshake(); err != nil {
				serverErrCh <- err
				return
			}
			serverStateCh <- tc.ConnectionState()
		}()

		roots, err := adRoots(caPEM)
		if err != nil {
			t.Fatalf("adRoots: %v", err)
		}
		cfg := adTLSConfig(roots, "127.0.0.1")
		if len(cfg.CurvePreferences) != 0 {
			t.Fatalf("expected default nil CurvePreferences, got %v", cfg.CurvePreferences)
		}

		clientConn, err := tls.DialWithDialer(netguard.Dialer(5*time.Second), "tcp", ln.Addr().String(), cfg)
		if err != nil {
			t.Fatalf("tls.DialWithDialer: %v", err)
		}
		defer clientConn.Close()

		pqtls.RequireHybrid(t, clientConn.ConnectionState())
		select {
		case err := <-serverErrCh:
			t.Fatalf("server handshake: %v", err)
		case state := <-serverStateCh:
			pqtls.RequireHybrid(t, state)
		}
	})

	t.Run("adConn_logs_negotiated_group_without_credentials", func(t *testing.T) {
		e, _, _, dc, sys := adFixture(t)
		const secretPass = "ldaps-bind-secret-never-log"
		dc.Users[strings.ToLower(adBindDN)] = secretPass

		c, err := e.store.ADConnector(sys.ID)
		if err != nil || c == nil {
			t.Fatalf("ADConnector: %v %v", c, err)
		}

		var logs bytes.Buffer
		log.SetOutput(&logs)
		t.Cleanup(func() { log.SetOutput(os.Stderr) })

		conn, err := e.adConn(sys, c, secretPass)
		if err != nil {
			t.Fatalf("adConn: %v", err)
		}
		defer conn.Close()

		state, ok := conn.TLSConnectionState()
		if !ok {
			t.Fatal("expected TLS connection state on LDAPS conn")
		}
		pqtls.RequireHybrid(t, state)

		out := logs.String()
		if !strings.Contains(out, "tls=TLS 1.3") || !strings.Contains(out, "group=X25519MLKEM768") {
			t.Fatalf("expected negotiated TLS version and group in log, got %q", out)
		}
		if strings.Contains(out, secretPass) || strings.Contains(out, adBindDN) {
			t.Fatalf("bind credentials leaked to log: %q", out)
		}
	})
}
