package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func loginEvidence(t *testing.T, db *store.Store, rec *httptest.ResponseRecorder) *store.Session {
	t.Helper()
	cookie := sessionCookie(rec)
	if cookie == nil {
		t.Fatalf("no session: %d %s", rec.Code, rec.Body.String())
	}
	sess, err := db.GetSessionByTokenHash(crypto.HashSHA256(cookie.Value), time.Hour)
	if err != nil || sess == nil {
		t.Fatalf("session lookup: %v", err)
	}
	if sess.PrimaryAuthenticatedAt == nil {
		t.Fatal("password verification time missing")
	}
	if sess.PrimaryAuthenticatedAt.After(sess.CreatedAt) {
		t.Fatal("password verified after session created")
	}
	return sess
}

func assertFactorEvidence(t *testing.T, db *store.Store, rec *httptest.ResponseRecorder, method string) *store.Session {
	t.Helper()
	sess := loginEvidence(t, db, rec)
	if sess.FactorMethod != method || sess.FactorAuthenticatedAt == nil {
		t.Fatalf("missing factor evidence: %+v", sess.AuthenticationEvidence)
	}
	if sess.FactorAuthenticatedAt.Before(*sess.PrimaryAuthenticatedAt) || sess.FactorAuthenticatedAt.After(sess.CreatedAt) {
		t.Fatal("factor time outside authentication interval")
	}
	return sess
}

func TestPasswordLoginEvidenceReachesOIDCToken(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	user := newUser(t, db, "user")
	// Client-supplied evidence is not an input to authentication.
	rec := anonPost(t, srv, "/api/auth/login", map[string]any{"username": user.Username, "password": "correct-horse-battery", "factorMethod": "webauthn", "auth_time": 9999999999})
	sess := loginEvidence(t, db, rec)
	if sess.FactorMethod != "" || sess.FactorAuthenticatedAt != nil {
		t.Fatal("password login invented a second factor")
	}
	newClient(t, db, "app", []string{"https://app.test/cb"}, []string{"openid"})
	q := url.Values{"client_id": {"app"}, "redirect_uri": {"https://app.test/cb"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	req.AddCookie(sessionCookie(rec))
	authRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(authRec, req)
	if authRec.Code != http.StatusFound {
		t.Fatalf("authorize: %d %s", authRec.Code, authRec.Body.String())
	}
	location, err := url.Parse(authRec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code, err := db.GetValidAuthorizationCode(crypto.HashSHA256(location.Query().Get("code")))
	if err != nil || code == nil || code.SessionID != sess.ID || !code.PrimaryAuthenticatedAt.Equal(*sess.PrimaryAuthenticatedAt) {
		t.Fatalf("authorization lost evidence: %v", err)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"app"}, "redirect_uri": {"https://app.test/cb"}, "code": {location.Query().Get("code")}, "code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
	tokenReq := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("token: %d %s", tokenRec.Code, tokenRec.Body.String())
	}
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	claims, err := srv.keyManager.VerifyJWT(tokens.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims["auth_time"] != float64(sess.PrimaryAuthenticatedAt.Unix()) || claims["acr"] != "urn:kysignon:acr:password" {
		t.Fatalf("incorrect HTTP token claims: %v", claims)
	}
}

func TestTOTPAndRecoveryLoginEvidence(t *testing.T) {
	for _, method := range []string{"totp", "recovery"} {
		t.Run(method, func(t *testing.T) {
			f, cleanup := newStepUpFixture(t)
			defer cleanup()
			secret, _, err := f.srv.mfaEngine.GenerateTOTPSecret(f.user.Username, "test")
			if err != nil {
				t.Fatal(err)
			}
			if err := f.srv.mfaEngine.SaveUserTOTP(f.user.ID, secret, nil); err != nil {
				t.Fatal(err)
			}
			var proof string
			if method == "recovery" {
				codes, err := f.srv.mfaEngine.GenerateRecoveryCodes(f.user.ID, nil)
				if err != nil {
					t.Fatal(err)
				}
				proof = codes[0]
			} else {
				proof = testTOTPCode(t, secret)
			}
			raw := passwordLogin(t, f.srv, f.user.Username, f.pass)
			token, err := f.srv.mfaEngine.ValidateMFAToken(raw)
			if err != nil {
				t.Fatal(err)
			}
			rec := anonPost(t, f.srv, "/api/auth/mfa/"+method+"/verify", map[string]string{"mfaToken": raw, "code": proof})
			sess := assertFactorEvidence(t, f.store, rec, method)
			if !sess.PrimaryAuthenticatedAt.Equal(*token.PrimaryAuthenticatedAt) {
				t.Fatal("MFA completion reset the password time")
			}
		})
	}
}

func testTOTPCode(t *testing.T, secret string) string {
	t.Helper()
	// Generate an independent RFC 6238 authenticator response for the HTTP flow.
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1000000)
}
