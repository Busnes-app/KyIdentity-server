package main

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/pqtls"
	"github.com/Busnes-app/kyidentity-server/internal/ldaptest"
)

func TestAgentLDAPSNegotiatesHybridPQ(t *testing.T) {
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

		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(caPEM)) {
			t.Fatal("failed to parse test CA PEM")
		}
		a := &agent{roots: roots}
		cfg := a.ldapsTLSConfig("127.0.0.1")
		if len(cfg.CurvePreferences) != 0 {
			t.Fatalf("expected default nil CurvePreferences, got %v", cfg.CurvePreferences)
		}

		clientConn, err := tls.Dial("tcp", ln.Addr().String(), cfg)
		if err != nil {
			t.Fatalf("tls.Dial: %v", err)
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

	t.Run("dial_logs_negotiated_group_without_credentials", func(t *testing.T) {
		f := newFixture(t)
		conn, err := f.agent.dial()
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		state, ok := conn.TLSConnectionState()
		if !ok {
			t.Fatal("expected TLS connection state on LDAPS conn")
		}
		pqtls.RequireHybrid(t, state)

		out := f.logs.String()
		if !strings.Contains(out, "tls=TLS 1.3") || !strings.Contains(out, "group=X25519MLKEM768") {
			t.Fatalf("expected negotiated TLS version and group in log, got %q", out)
		}
		if strings.Contains(out, f.agent.password) || strings.Contains(out, testBindDN) || strings.Contains(out, f.agent.token) {
			t.Fatalf("credentials leaked to log: %q", out)
		}
	})
}
