package oauth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

type refreshFixture struct {
	t       *testing.T
	e       *Engine
	db      *store.Store
	raw     *sql.DB
	user    *store.User
	client  *store.OAuthClient
	secret  string
	session string
	appID   string
}

var refreshPolicy = store.AppAuthenticationPolicy{Mode: "reuse", Factor: "password", RefreshIdle: 3600, RefreshLifetime: 86400}

func newRefreshFixture(t *testing.T) *refreshFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := store.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	km, err := crypto.LoadOrCreateRSAKey(filepath.Join(dir, "jwt.key"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", filepath.Join(dir, "test.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	f := &refreshFixture{t: t, e: NewEngine(db, km, "http://localhost:5867"), db: db, raw: raw, secret: "client-secret-value"}
	f.user = &store.User{ID: uuid.NewString(), Username: "alice", DisplayName: "Alice", Email: "alice@example.com", PasswordHash: "x", Role: "user", Status: "active"}
	if err := db.CreateUser(f.user); err != nil {
		t.Fatal(err)
	}
	f.client = f.newClient("kynotes", "confidential")
	f.appID = f.setPolicy(f.client.ID, refreshPolicy)
	f.session = f.newSession(time.Now().UTC().Add(-10 * time.Minute))
	return f
}

func (f *refreshFixture) newClient(id, kind string) *store.OAuthClient {
	f.t.Helper()
	c := &store.OAuthClient{ID: id, ClientName: id, ClientType: kind, RedirectURIsJSON: `["https://app.example/cb"]`, AllowedScopesJSON: `["openid","profile","email"]`, Enabled: true}
	if kind == "confidential" {
		c.ClientSecretHash = crypto.HashSHA256(f.secret)
	}
	if err := f.db.CreateOAuthClient(c, nil); err != nil {
		f.t.Fatal(err)
	}
	allowTestAppAccess(f.t, f.db, id)
	return c
}

func (f *refreshFixture) app(clientID string) store.AppRecord {
	f.t.Helper()
	rows, _, err := f.db.ListAppRecords(clientID, 10, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, a := range rows {
		if a.ClientID == clientID {
			return a
		}
	}
	f.t.Fatalf("no app for %s", clientID)
	return store.AppRecord{}
}

func (f *refreshFixture) setPolicy(clientID string, p store.AppAuthenticationPolicy) string {
	f.t.Helper()
	a := f.app(clientID)
	if err := f.db.SetAppAuthenticationPolicy(a.ID, p, a.Revision, nil); err != nil {
		f.t.Fatal(err)
	}
	return a.ID
}

func (f *refreshFixture) newSession(passwordAt time.Time) string {
	f.t.Helper()
	id := uuid.NewString()
	if err := f.db.CreateSession(&store.Session{ID: id, UserID: f.user.ID, SessionTokenHash: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		AuthenticationEvidence: store.AuthenticationEvidence{PrimaryAuthenticatedAt: &passwordAt}}); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *refreshFixture) login(scope string) *TokenResponse {
	f.t.Helper()
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	code, err := f.e.CreateAuthorizationCodeWithNonce(f.client.ID, f.session, "https://app.example/cb", scope, base64.RawURLEncoding.EncodeToString(h[:]), "S256", "n-0")
	if err != nil {
		f.t.Fatal(err)
	}
	resp, err := f.e.ExchangeAuthorizationCode(code, f.client.ID, f.secret, "https://app.example/cb", verifier)
	if err != nil {
		f.t.Fatal(err)
	}
	if resp.RefreshToken == "" {
		f.t.Fatal("no refresh token for a confidential client with refresh enabled")
	}
	return resp
}

func (f *refreshFixture) refresh(token string) (*TokenResponse, error) {
	resp, _, err := f.e.ExchangeRefreshToken(token, f.client.ID, f.secret, "")
	return resp, err
}

func (f *refreshFixture) exec(query string, args ...any) {
	f.t.Helper()
	if _, err := f.raw.Exec(query, args...); err != nil {
		f.t.Fatal(err)
	}
}

func TestRefreshRotatesAndReuseRevokesFamily(t *testing.T) {
	f := newRefreshFixture(t)
	first := f.login("openid profile")
	var stored int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM refresh_tokens WHERE token_hash=?`, first.RefreshToken).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("raw refresh token stored: %d %v", stored, err)
	}
	second, err := f.refresh(first.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if second.RefreshToken == "" || second.RefreshToken == first.RefreshToken || second.AccessToken == first.AccessToken {
		t.Fatal("refresh did not rotate")
	}
	if _, err := f.e.GetUserinfo(second.AccessToken); err != nil {
		t.Fatalf("refreshed access token: %v", err)
	}
	// Replaying the spent token ends the family: the newer token and every access token too.
	if _, err := f.refresh(first.RefreshToken); !errors.Is(err, ErrRefreshReuse) {
		t.Fatalf("reuse: %v", err)
	}
	if _, err := f.refresh(second.RefreshToken); err == nil {
		t.Fatal("token from a revoked family refreshed")
	}
	for _, access := range []string{first.AccessToken, second.AccessToken} {
		if _, err := f.e.GetUserinfo(access); err == nil {
			t.Fatal("access token of a revoked family still accepted online")
		}
	}
}

func TestRefreshedIDTokenKeepsOriginalLogin(t *testing.T) {
	f := newRefreshFixture(t)
	first := f.login("openid profile")
	f.exec(`UPDATE sessions SET last_active_at=? WHERE id=?`, time.Now().UTC().Add(-time.Hour), f.session)
	second, err := f.refresh(first.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := f.e.keyManager.VerifyJWT(first.IDToken)
	b, err := f.e.keyManager.VerifyJWT(second.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	if b["auth_time"] != a["auth_time"] || b["acr"] != a["acr"] || b["sid"] != a["sid"] || b["sub"] != a["sub"] || b["aud"] != a["aud"] {
		t.Fatalf("refreshed ID token changed the login: %v vs %v", b, a)
	}
	if _, ok := b["nonce"]; ok || a["nonce"] != "n-0" {
		t.Fatalf("nonce: original %v refreshed %v", a["nonce"], b["nonce"])
	}
	var active time.Time
	if err := f.raw.QueryRow(`SELECT last_active_at FROM sessions WHERE id=?`, f.session).Scan(&active); err != nil || time.Since(active) > time.Minute {
		t.Fatalf("refresh did not count as session activity: %v %v", active, err)
	}
}

func TestRefreshScopeNarrowsOnly(t *testing.T) {
	f := newRefreshFixture(t)
	first := f.login("openid profile")
	if _, _, err := f.e.ExchangeRefreshToken(first.RefreshToken, f.client.ID, f.secret, "openid email"); err == nil {
		t.Fatal("refresh widened scope")
	}
	narrowed, _, err := f.e.ExchangeRefreshToken(first.RefreshToken, f.client.ID, f.secret, "  openid  ")
	if err != nil || narrowed.Scope != "openid" {
		t.Fatalf("narrow: %+v %v", narrowed, err)
	}
}

func TestRefreshRevokedByEveryLifecyclePath(t *testing.T) {
	for name, revoke := range map[string]func(f *refreshFixture, token string){
		"logout": func(f *refreshFixture, _ string) {
			if err := f.db.RevokeSession(f.user.ID, f.session, nil); err != nil {
				t.Fatal(err)
			}
		},
		"app access revoked": func(f *refreshFixture, _ string) {
			if err := f.db.RevokeUserClientAccess(f.user.ID, f.client.ID, nil); err != nil {
				t.Fatal(err)
			}
		},
		"user disabled": func(f *refreshFixture, _ string) {
			if _, err := f.db.EditUser(f.user.ID, nil, func(u *store.User) (bool, error) { u.Status = "disabled"; return true, nil }); err != nil {
				t.Fatal(err)
			}
		},
		"assignment removed": func(f *refreshFixture, _ string) {
			a := f.app(f.client.ID)
			if err := f.db.SetAppPolicy(a.ID, "assigned_only", true, a.Revision, nil); err != nil {
				t.Fatal(err)
			}
		},
		"policy changed": func(f *refreshFixture, _ string) {
			p := refreshPolicy
			p.RefreshIdle = 600
			f.setPolicy(f.client.ID, p)
		},
		"client secret rotated": func(f *refreshFixture, _ string) {
			if err := f.db.UpdateOAuthClientWithAudit(f.client, true, nil); err != nil {
				t.Fatal(err)
			}
		},
		"RFC 7009 revoke": func(f *refreshFixture, token string) {
			if err := f.e.RevokeToken(token, f.client.ID, f.secret); err != nil {
				t.Fatal(err)
			}
		},
		"SCIM deprovisioned": func(f *refreshFixture, _ string) {
			c, err := f.db.CreateSCIMConnector("Upstream", nil)
			if err != nil {
				t.Fatal(err)
			}
			f.exec(`UPDATE users SET source_connector_id=?, external_id='ext-1', source_active=1 WHERE id=?`, c.ID, f.user.ID)
			if _, err := f.db.UpdateUpstreamUser(c.ID, f.user.ID, nil, func(u *store.User) error { u.SourceActive = false; return nil }); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRefreshFixture(t)
			live, err := f.refresh(f.login("openid").RefreshToken)
			if err != nil {
				t.Fatal(err)
			}
			revoke(f, live.RefreshToken)
			if _, err := f.refresh(live.RefreshToken); err == nil {
				t.Fatal("refresh survived revocation")
			}
		})
	}
}

func TestRefreshExpiry(t *testing.T) {
	past := time.Now().UTC().Add(-time.Second)
	for name, expire := range map[string]func(f *refreshFixture){
		"refresh idle": func(f *refreshFixture) { f.exec(`UPDATE refresh_tokens SET expires_at=?`, past) },
		"refresh lifetime": func(f *refreshFixture) {
			f.exec(`UPDATE issued_tokens SET expires_at=? WHERE jti IN (SELECT jti FROM refresh_families)`, past)
		},
		"session idle": func(f *refreshFixture) {
			f.exec(`UPDATE sessions SET last_active_at=?`, time.Now().UTC().Add(-f.db.SessionLimits().IdleTTL()-time.Minute))
		},
		"session absolute": func(f *refreshFixture) { f.exec(`UPDATE sessions SET expires_at=?`, past) },
		"session limit shortened": func(f *refreshFixture) {
			if err := f.db.SetSessionLimits(store.SessionLimits{Absolute: 3600, Idle: 600}, nil); err != nil {
				f.t.Fatal(err)
			}
			f.exec(`UPDATE sessions SET created_at=?`, time.Now().UTC().Add(-2*time.Hour))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRefreshFixture(t)
			live, err := f.refresh(f.login("openid").RefreshToken)
			if err != nil {
				t.Fatal(err)
			}
			expire(f)
			if _, err := f.refresh(live.RefreshToken); err == nil || errors.Is(err, ErrRefreshReuse) {
				t.Fatalf("expired refresh token: %v", err)
			}
		})
	}
}

// The app's re-auth deadline caps the family: refresh never outlives max_age.
func TestRefreshFamilyEndsAtReauthDeadline(t *testing.T) {
	f := newRefreshFixture(t)
	p := refreshPolicy
	p.Mode, p.PrimaryMaxAge = "max_age", 3600
	f.setPolicy(f.client.ID, p)
	passwordAt := time.Now().UTC().Add(-50 * time.Minute)
	f.session = f.newSession(passwordAt)
	f.login("openid")
	var end time.Time
	if err := f.raw.QueryRow(`SELECT t.expires_at FROM issued_tokens t JOIN refresh_families r ON r.jti=t.jti`).Scan(&end); err != nil {
		t.Fatal(err)
	}
	if want := passwordAt.Add(time.Hour); end.After(want.Add(time.Second)) {
		t.Fatalf("family ends %v, after the re-auth deadline %v", end, want)
	}
}

func TestRefreshBoundToClient(t *testing.T) {
	f := newRefreshFixture(t)
	first := f.login("openid")
	if _, _, err := f.e.ExchangeRefreshToken(first.RefreshToken, f.client.ID, "wrong", ""); err == nil {
		t.Fatal("wrong client secret refreshed")
	}
	if _, err := f.refresh(first.RefreshToken); err != nil {
		t.Fatalf("a failed client authentication must not spend the token: %v", err)
	}
	f2 := newRefreshFixture(t)
	stolen := f2.login("openid")
	other := f2.newClient("kypost", "confidential")
	if _, _, err := f2.e.ExchangeRefreshToken(stolen.RefreshToken, other.ID, f2.secret, ""); !errors.Is(err, ErrRefreshReuse) {
		t.Fatalf("another client's refresh token: %v", err)
	}
	if _, err := f2.refresh(stolen.RefreshToken); err == nil {
		t.Fatal("family survived presentation by another client")
	}
}

func TestPublicClientsGetNoRefreshTokens(t *testing.T) {
	f := newRefreshFixture(t)
	public := f.newClient("spa", "public")
	a := f.app(public.ID)
	if err := f.db.SetAppAuthenticationPolicy(a.ID, refreshPolicy, a.Revision, nil); !errors.Is(err, store.ErrRefreshNeedsConfidential) {
		t.Fatalf("refresh enabled for a public client: %v", err)
	}
}

func TestConcurrentRefreshSpendsOnce(t *testing.T) {
	f := newRefreshFixture(t)
	first := f.login("openid")
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.refresh(first.RefreshToken); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("%d concurrent refreshes succeeded", successes)
	}
}

func TestRefreshPolicyBounds(t *testing.T) {
	for _, p := range []store.AppAuthenticationPolicy{
		{Mode: "reuse", Factor: "password", RefreshIdle: 60, RefreshLifetime: 3600},
		{Mode: "reuse", Factor: "password", RefreshIdle: 3600, RefreshLifetime: 30 * 86400},
		{Mode: "reuse", Factor: "password", RefreshIdle: 7200, RefreshLifetime: 3600},
		{Mode: "reuse", Factor: "password", RefreshIdle: 0, RefreshLifetime: 3600},
		{Mode: "reuse", Factor: "password", RefreshIdle: 3600, RefreshLifetime: 0},
	} {
		if p.Valid() {
			t.Fatalf("absurd refresh timers accepted: %+v", p)
		}
	}
	if !refreshPolicy.Valid() {
		t.Fatal("default refresh timers refused")
	}
}
