package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// An app's step-up for a sensitive action is plain OIDC: acr_values for MFA plus max_age
// means "MFA within N seconds", and the ID token says when and how the user proved it.
func TestAppStepUpWithMaxAgeAndACR(t *testing.T) {
	srv, db, _, _, engine, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(24*time.Hour))
	newClient(t, db, "kypasswords", []string{"https://vault.example/cb"}, []string{"openid"})
	raw, err := sql.Open("sqlite", srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	login := func(passwordAgo, factorAgo time.Duration, method string) time.Time {
		t.Helper()
		at := time.Now().UTC().Add(-passwordAgo)
		var factorAt any
		if method != "" {
			factorAt = time.Now().UTC().Add(-factorAgo)
		}
		if _, err := raw.Exec(`UPDATE sessions SET primary_authenticated_at=?, factor_authenticated_at=?, factor_method=?`, at, factorAt, method); err != nil {
			t.Fatal(err)
		}
		return at
	}
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	authorize := func(extra url.Values) *url.URL {
		t.Helper()
		q := url.Values{"client_id": {"kypasswords"}, "redirect_uri": {"https://vault.example/cb"}, "response_type": {"code"}, "scope": {"openid"},
			"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
			"acr_values": {"urn:kysignon:acr:mfa"}, "max_age": {"600"}}
		for k, v := range extra {
			q[k] = v
		}
		req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
		req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
		r := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(r, req)
		loc, _ := url.Parse(r.Header().Get("Location"))
		return loc
	}

	at := login(5*time.Minute, 5*time.Minute, "totp")
	loc := authorize(nil)
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("MFA 5 minutes ago did not satisfy max_age=600: %s", loc)
	}
	resp, err := engine.ExchangeAuthorizationCode(code, "kypasswords", "", "https://vault.example/cb", verifier)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := srv.keyManager.VerifyJWT(resp.IDToken, srv.cfg.IssuerURL, "id_token")
	if err != nil {
		t.Fatal(err)
	}
	amr, _ := claims["amr"].([]any)
	if claims["auth_time"] != float64(at.Unix()) || claims["acr"] != "urn:kysignon:acr:mfa" || len(amr) == 0 || amr[len(amr)-1] != "mfa" {
		t.Fatalf("ID token step-up claims: %v", claims)
	}

	for name, c := range map[string]struct {
		password, factor time.Duration
		method           string
	}{
		"MFA 20 minutes ago":      {20 * time.Minute, 20 * time.Minute, "totp"},
		"password only, just now": {time.Minute, 0, ""},
		"recovery code, just now": {time.Minute, time.Minute, "recovery"},
	} {
		login(c.password, c.factor, c.method)
		if loc := authorize(nil); !strings.HasPrefix(loc.String(), "/login?interaction=") {
			t.Fatalf("%s satisfied MFA within 10 minutes: %s", name, loc)
		}
		if loc := authorize(url.Values{"prompt": {"none"}}); loc.Query().Get("error") != "login_required" {
			t.Fatalf("%s with prompt=none: %s", name, loc)
		}
	}
}
