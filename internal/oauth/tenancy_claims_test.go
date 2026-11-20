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
