package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// platform-token create prints the token once; list never shows it; revoke ends it; each
// action is a platform audit row; a single-tenant install refuses.
func TestPlatformTokenCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kyidentity.db")
	cfg := &config.Config{Tenancy: "multi", DBPath: path}
	if err := platformToken(&config.Config{Tenancy: "single", DBPath: path}, "list", "", "", 0, "", &bytes.Buffer{}); err == nil {
		t.Fatal("single-tenant install ran platform-token")
	}
	var out bytes.Buffer
	if err := platformToken(cfg, "create", "billing", "orgs:read,orgs:write", 30, "", &out); err != nil {
		t.Fatal(err)
	}
	var made struct{ ID, Token string }
	if err := json.Unmarshal(out.Bytes(), &made); err != nil || !strings.HasPrefix(made.Token, "kyp_"+made.ID+"_") {
		t.Fatalf("create: %s %v", out.String(), err)
	}
	for _, bad := range []struct {
		scopes string
		days   int
	}{{"orgs:read,members:read", 30}, {"orgs:read", 0}, {"orgs:read", 731}} {
		if err := platformToken(cfg, "create", "x", bad.scopes, bad.days, "", &bytes.Buffer{}); err == nil {
			t.Errorf("create %v accepted", bad)
		}
	}
	out.Reset()
	if err := platformToken(cfg, "list", "", "", 0, "", &out); err != nil || strings.Contains(out.String(), made.Token[20:]) || !strings.Contains(out.String(), made.ID) {
		t.Fatalf("list: %s %v", out.String(), err)
	}
	if err := platformToken(cfg, "revoke", "", "", 0, made.ID, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := platformToken(cfg, "revoke", "", "", 0, made.ID, &bytes.Buffer{}); err == nil {
		t.Fatal("revoked twice")
	}
	s, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if tok, err := s.Platform().AuthenticatePlatformToken(made.Token); tok != nil || err != nil {
		t.Fatalf("revoked token authenticates: %v %v", tok, err)
	}
	raw, err := store.OpenRawForTest(path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var n int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action IN ('platform.token_created','platform.token_listed','platform.token_revoked') AND org_id IS NULL AND details_json NOT LIKE ?`, "%"+made.Token[20:]+"%").Scan(&n); err != nil || n != 3 {
		t.Fatalf("audit rows: %d %v", n, err)
	}
}
