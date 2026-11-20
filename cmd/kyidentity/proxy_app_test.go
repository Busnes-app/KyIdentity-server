package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// A rerun keeps the one app and the one secret; only --rotate-secret prints a new one, and
// another owner or an administrator's own proxy app for the host is refused.
func TestProxyApp(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KYIDENTITY_DATA_DIR", dir)
	t.Setenv("KYIDENTITY_DB_PATH", "")
	dbPath := filepath.Join(dir, "kyidentity.db")
	s, err := store.NewTest(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	run := func(args ...string) (map[string]string, error) {
		t.Helper()
		var out bytes.Buffer
		err := runProxyApp(args, &out)
		if err != nil {
			return nil, err
		}
		var res map[string]string
		if json.Unmarshal(out.Bytes(), &res) != nil || res["schema"] != "kyidentity.proxy-app/1" {
			t.Fatalf("output %q", out.String())
		}
		return res, nil
	}
	base := []string{"--owner", "inst-1", "--host", "grafana.example.test", "--name", "Grafana", "--login-header", "X-WEBAUTH-USER"}
	first, err := run(base...)
	if err != nil || first["status"] != "created" || len(first["edgeSecret"]) != 64 {
		t.Fatalf("create: %v %v", first, err)
	}
	p, err := s.ProxyAppByHost("grafana.example.test")
	if err != nil || p == nil || p.SecretHash != crypto.HashSHA256(first["edgeSecret"]) || p.LoginHeader != "X-WEBAUTH-USER" || p.SessionSeconds != store.DefaultForwardSession {
		t.Fatalf("stored app: %+v %v", p, err)
	}
	again, err := run(base...)
	if err != nil || again["status"] != "unchanged" || again["edgeSecret"] != "" || again["id"] != first["id"] {
		t.Fatalf("rerun: %v %v", again, err)
	}
	changed, err := run(append(base, "--bypass", "/api/health")...)
	if err != nil || changed["status"] != "updated" || changed["edgeSecret"] != "" {
		t.Fatalf("bypass change: %v %v", changed, err)
	}
	if p, _ = s.ProxyAppByHost("grafana.example.test"); p.SecretHash != crypto.HashSHA256(first["edgeSecret"]) || len(p.Bypass) != 1 {
		t.Fatalf("change replaced the secret or lost the bypass: %+v", p)
	}
	rotated, err := run(append(base, "--bypass", "/api/health", "--rotate-secret")...)
	if err != nil || len(rotated["edgeSecret"]) != 64 || rotated["edgeSecret"] == first["edgeSecret"] {
		t.Fatalf("rotate: %v %v", rotated, err)
	}
	apps, _ := s.ListProxyApps()
	if len(apps) != 1 {
		t.Fatalf("%d proxy apps after reruns", len(apps))
	}
	if _, err := run("--owner", "inst-2", "--host", "grafana.example.test", "--name", "G"); err == nil || !strings.Contains(err.Error(), "did not create") {
		t.Fatalf("another owner: %v", err)
	}
	// An administrator's own proxy app is never adopted.
	card := &store.Application{ID: uuid.NewString(), Name: "Admin's", URL: "https://admin.example.test/", IconName: "favicon", Enabled: true}
	if err := s.CreateProxyApp(card, &store.ProxyApp{Host: "admin.example.test", LoginHeader: "X-Ky-User", Bypass: []string{}, SessionSeconds: 3600, SecretHash: "h"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := run("--owner", "inst-1", "--host", "admin.example.test", "--name", "A"); err == nil || !strings.Contains(err.Error(), "did not create") {
		t.Fatalf("foreign app: %v", err)
	}
	for _, bad := range [][]string{
		{"--owner", "inst-1", "--host", "*.example.test", "--name", "W"},
		{"--owner", "inst-1", "--host", "x.example.test", "--name", "W", "--login-header", "Cookie"},
		{"--owner", "inst-1", "--host", "x.example.test", "--name", "W", "--bypass", "/"},
		{"--owner", "inst-1", "--host", "x.example.test", "--name", "W", "--session-hours", "0"},
		{"--owner", "", "--host", "x.example.test", "--name", "W"},
		{"--owner", "inst-1", "--host", "x.example.test"},
	} {
		if _, err := run(bad...); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	var caps bytes.Buffer
	if err := runSetup([]string{"--capabilities"}, &caps); err != nil || !strings.Contains(caps.String(), `"proxy-apps"`) {
		t.Fatalf("capabilities: %s %v", caps.String(), err)
	}
}
