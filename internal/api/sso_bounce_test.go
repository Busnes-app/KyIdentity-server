package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/config"
)

// Issue #77: one sign-in must carry to a second app without a password prompt.
func TestSSOBounceToSecondApp(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	newClient(t, db, "kynotes", []string{"https://notes.example/cb"}, []string{"openid"})
	newClient(t, db, "kypost", []string{"https://mail.example/cb"}, []string{"openid"})
	sum := sha256.Sum256([]byte(strings.Repeat("v", 43)))
	authorize := func(client, cb string) url.Values {
		return url.Values{"client_id": {client}, "redirect_uri": {cb}, "response_type": {"code"}, "scope": {"openid"},
			"state": {"s"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	}
	browser := interactionBrowser(t, srv)

	r := browser("GET", "/oauth/authorize?"+authorize("kynotes", "https://notes.example/cb").Encode(), nil)
	loc, _ := url.Parse(r.Header().Get("Location"))
	raw := loc.Query().Get("interaction")
	if raw == "" {
		t.Fatalf("first app did not start login: %d %s", r.Code, r.Header().Get("Location"))
	}
	if r := browser("POST", "/api/auth/login", map[string]string{"username": u.Username, "password": "correct-horse-battery", "interaction": raw}); r.Code != 200 {
		t.Fatalf("login: %d %s", r.Code, r.Body.String())
	}
	if r := browser("GET", "/oauth/authorize?interaction="+raw, nil); !strings.HasPrefix(r.Header().Get("Location"), "https://notes.example/cb?code=") {
		t.Fatalf("first app: %s", r.Header().Get("Location"))
	}

	bounce := func() string {
		return browser("GET", "/oauth/authorize?"+authorize("kypost", "https://mail.example/cb").Encode(), nil).Header().Get("Location")
	}
	if got := bounce(); !strings.HasPrefix(got, "https://mail.example/cb?code=") {
		t.Fatalf("immediate bounce to second app asked for sign-in: %s", got)
	}

	// The user then works in KyNotes for 31 minutes; KyNotes never calls KyIdentity.
	rawDB, err := sql.Open("sqlite", srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rawDB.Close()
	idle := func(d time.Duration) {
		t.Helper()
		if _, err := rawDB.Exec(`UPDATE sessions SET last_active_at=?`, time.Now().UTC().Add(-d)); err != nil {
			t.Fatal(err)
		}
	}
	idle(31 * time.Minute)
	if got := bounce(); !strings.HasPrefix(got, "https://mail.example/cb?code=") {
		t.Fatalf("bounce after 31 minutes in another app asked for sign-in: %s", got)
	}
	// The idle limit still ends the session.
	idle(config.DefaultSessionIdleTTL + time.Minute)
	if got := bounce(); !strings.HasPrefix(got, "/login?interaction=") {
		t.Fatalf("idle-expired session signed in silently: %s", got)
	}
}
