package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/netguard"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/tenancy-golden from this build")

// Values that differ on every run: when a token was signed and its IDs, the login's sid,
// the test key's kid, and the device assertion's iat (its auth_time).
var goldenVolatile = regexp.MustCompile(`"(jti|iat|exp|sid|kid|auth_time)":("[^"]*"|[0-9]+)`)

// goldenJWT is a token's header and payload as signed, with the volatile values masked.
func goldenJWT(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	var out []string
	for _, p := range parts[:2] {
		raw, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, goldenVolatile.ReplaceAllString(string(raw), `"$1":"*"`))
	}
	return strings.Join(out, "\n") + "\n"
}

// tenancyTokens issues every token kind KyIdentity signs for one user of org: the code
// flow's access and ID tokens and UserInfo, the device sign-on's access and ID tokens,
// and a back-channel logout token through the delivery worker.
func tenancyTokens(t *testing.T, e *Engine, db *store.Store, org *store.OrgStore) map[string]string {
	t.Helper()
	netguard.AllowPrivate, netguard.AllowLoopback = true, true
	t.Cleanup(func() { netguard.AllowPrivate, netguard.AllowLoopback = false, false })
	user := &store.User{ID: "golden-user", Username: "golden", DisplayName: "Golden", Email: "golden@example.com", PasswordHash: "x", Role: "user", Status: "active"}
	if err := org.CreateUser(user); err != nil {
		t.Fatal(err)
	}
	client := testClient(t, db, "golden-app", "public", []string{"https://golden.example/cb"}, []string{"openid", "profile", "email"})
	if org.ID().String() != store.DefaultOrgID {
		apps, _, err := db.ListAppRecords(client.ID, 1, 0)
		if err != nil || len(apps) != 1 {
			t.Fatal(apps, err)
		}
		if err := store.EnableOrgAppForTest(db, org.ID(), apps[0].ID, "{}"); err != nil {
			t.Fatal(err)
		}
	}
	out := map[string]string{}

	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	sess := &store.Session{ID: uuid.NewString(), UserID: user.ID, SessionTokenHash: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour),
		AuthenticationEvidence: store.AuthenticationEvidence{PrimaryAuthenticatedAt: &at}}
	if err := db.CreateSession(sess); err != nil {
		t.Fatal(err)
	}
	verifier, challenge := pkcePair()
	code, err := e.CreateAuthorizationCode(client.ID, sess.ID, "https://golden.example/cb", "openid profile email", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.ExchangeAuthorizationCode(code, client.ID, "", "https://golden.example/cb", verifier)
	if err != nil {
		t.Fatal(err)
	}
	out["code_access"], out["code_id"] = goldenJWT(t, resp.AccessToken), goldenJWT(t, resp.IDToken)
	info, err := e.GetUserinfo(resp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(info)
	out["userinfo"] = string(raw) + "\n"

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err := db.UpsertNativeDevice(&store.NativeDevice{ID: "golden-dev", UserID: user.ID, DeviceName: "phone", DeviceIdentifier: "golden-ident",
		PublicKey: base64.StdEncoding.EncodeToString(spki), IsMFAApprover: true, CanSignOn: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	assertion := signDeviceAssertionForTest(t, priv, testHeader("golden-dev"), map[string]any{
		"iss": "device:golden-dev", "sub": user.ID, "aud": e.issuerURL + "/oauth/token", "client_id": client.ID,
		"origin": "https://golden.example", "iat": now, "exp": now + 120, "jti": uuid.NewString()})
	dresp, _, err := e.ExchangeDeviceAssertion(assertion, client.ID, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	out["device_access"], out["device_id"] = goldenJWT(t, dresp.AccessToken), goldenJWT(t, dresp.IDToken)

	tokens := make(chan string, 1)
	rcv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		tokens <- r.PostForm.Get("logout_token")
	}))
	defer rcv.Close()
	client.BackchannelLogoutURI = rcv.URL + "/logout"
	if err := db.UpdateOAuthClient(client); err != nil {
		t.Fatal(err)
	}
	if err := org.RevokeSession(user.ID, sess.ID, nil); err != nil {
		t.Fatal(err)
	}
	if did, err := e.DeliverPendingLogout(context.Background()); err != nil || !did {
		t.Fatalf("deliver: %v %v", did, err)
	}
	out["logout"] = goldenJWT(t, <-tokens)
	return out
}

// A single-tenant install signs exactly what it signed before tenancy: every token,
// UserInfo and the logout token match master's, apart from the volatile values.
func TestSingleTenantTokensAreUnchanged(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	got := tenancyTokens(t, e, db, db.DefaultOrg())
	discovery, _ := json.Marshal(e.GetOIDCConfiguration())
	got["discovery"] = string(discovery) + "\n"
	for name, text := range got {
		path := filepath.Join("testdata", "tenancy-golden", name+".txt")
		if *updateGolden {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if text != string(want) {
			t.Errorf("%s changed:\n got %s\nwant %s", name, text, want)
		}
	}
}

var orgClaim = regexp.MustCompile(`"org_id":"([^"]*)",`)

// In multi-tenant mode every token, UserInfo and the logout token carry the user's org as
// org_id, read from the user row, and nothing else changes; discovery lists the claim.
func TestMultiTenantTokensCarryTheOrg(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	e.SetMultiTenant(true)
	org, err := store.CreateOrgForTest(db, "household")
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range tenancyTokens(t, e, db, db.Org(org)) {
		found := orgClaim.FindAllStringSubmatch(text, -1)
		if len(found) != 1 || found[0][1] != org.String() {
			t.Errorf("%s: org_id %v, want once %s: %s", name, found, org, text)
		}
		want, err := os.ReadFile(filepath.Join("testdata", "tenancy-golden", name+".txt"))
		if err != nil {
			t.Fatal(err)
		}
		if got := orgClaim.ReplaceAllString(text, ""); got != string(want) {
			t.Errorf("%s: more than org_id changed:\n got %s\nwant %s", name, got, want)
		}
	}
	if supported := e.GetOIDCConfiguration().ClaimsSupported; !slices.Contains(supported, "org_id") {
		t.Fatalf("claims_supported %v", supported)
	}
}

var exportClaim = regexp.MustCompile(`"export_only":true,`)

// An export-only session (a member after the holder's Delete everything) signs tokens with
// export_only and nothing else changed, its scope is cut to openid email profile, and the
// member's device sign-on is refused; the claim is listed in discovery.
func TestExportOnlyTokensCarryTheClaim(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	e.SetMultiTenant(true)
	orgID, err := store.CreateOrgForTest(db, "household")
	if err != nil {
		t.Fatal(err)
	}
	org := db.Org(orgID)
	holder := &store.User{ID: "golden-holder", Username: "holder", DisplayName: "Holder", Email: "holder@example.com", PasswordHash: "x", Role: "user", Status: "active"}
	user := &store.User{ID: "golden-user", Username: "golden", DisplayName: "Golden", Email: "golden@example.com", PasswordHash: "x", Role: "user", Status: "active"}
	for _, u := range []*store.User{holder, user} {
		if err := org.CreateUser(u); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetAccountHolderForTest(db, orgID, holder.ID); err != nil {
		t.Fatal(err)
	}
	client := testClient(t, db, "golden-app", "public", []string{"https://golden.example/cb"}, []string{"openid", "profile", "email", "offline_access"})
	apps, _, err := db.ListAppRecords(client.ID, 1, 0)
	if err != nil || len(apps) != 1 {
		t.Fatal(apps, err)
	}
	if err := store.EnableOrgAppForTest(db, orgID, apps[0].ID, "{}"); err != nil {
		t.Fatal(err)
	}
	// A device paired before the request.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err := db.UpsertNativeDevice(&store.NativeDevice{ID: "golden-dev", UserID: user.ID, DeviceName: "phone", DeviceIdentifier: "golden-ident",
		PublicKey: base64.StdEncoding.EncodeToString(spki), IsMFAApprover: true, CanSignOn: true}); err != nil {
		t.Fatal(err)
	}
	hs := &store.Session{ID: uuid.NewString(), UserID: holder.ID, SessionTokenHash: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if err := db.CreateSession(hs); err != nil {
		t.Fatal(err)
	}
	grant := uuid.NewString()
	if err := db.CreateStepUpToken(&store.StepUpToken{ID: uuid.NewString(), UserID: holder.ID, SessionID: hs.ID, TokenHash: grant,
		Operation: "POST /api/user/erase", FactorMethod: "totp", ExpiresAt: time.Now().UTC().Add(time.Minute)}, nil); err != nil {
		t.Fatal(err)
	}
	if out, err := org.Erase(holder.ID, hs.ID, grant, "POST /api/user/erase", nil); err != nil || out.Deleted {
		t.Fatalf("erase: %+v %v", out, err)
	}

	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	sess := &store.Session{ID: uuid.NewString(), UserID: user.ID, SessionTokenHash: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour),
		AuthenticationEvidence: store.AuthenticationEvidence{PrimaryAuthenticatedAt: &at}}
	if err := db.CreateSession(sess); err != nil {
		t.Fatal(err)
	}
	verifier, challenge := pkcePair()
	code, err := e.CreateAuthorizationCode(client.ID, sess.ID, "https://golden.example/cb", "openid profile email offline_access", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.ExchangeAuthorizationCode(code, client.ID, "", "https://golden.example/cb", verifier)
	if err != nil {
		t.Fatal(err)
	}
	if resp.RefreshToken != "" || resp.Scope != "openid profile email" {
		t.Fatalf("export-only grant: refresh %q, scope %q", resp.RefreshToken, resp.Scope)
	}
	info, err := e.GetUserinfo(resp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(info)
	for name, text := range map[string]string{"code_access": goldenJWT(t, resp.AccessToken), "code_id": goldenJWT(t, resp.IDToken), "userinfo": string(raw) + "\n"} {
		if n := len(exportClaim.FindAllString(text, -1)); n != 1 {
			t.Errorf("%s: export_only %d times: %s", name, n, text)
		}
		want, err := os.ReadFile(filepath.Join("testdata", "tenancy-golden", name+".txt"))
		if err != nil {
			t.Fatal(err)
		}
		got := orgClaim.ReplaceAllString(exportClaim.ReplaceAllString(text, ""), "")
		if got != string(want) {
			t.Errorf("%s: more than org_id and export_only changed:\n got %s\nwant %s", name, got, want)
		}
	}
	now := time.Now().Unix()
	assertion := signDeviceAssertionForTest(t, priv, testHeader("golden-dev"), map[string]any{
		"iss": "device:golden-dev", "sub": user.ID, "aud": e.issuerURL + "/oauth/token", "client_id": client.ID,
		"origin": "https://golden.example", "iat": now, "exp": now + 120, "jti": uuid.NewString()})
	if _, _, err := e.ExchangeDeviceAssertion(assertion, client.ID, "127.0.0.1", "test"); err == nil {
		t.Fatal("device sign-on in an org being deleted was accepted")
	}
	if supported := e.GetOIDCConfiguration().ClaimsSupported; !slices.Contains(supported, "export_only") {
		t.Fatalf("claims_supported %v", supported)
	}
}
