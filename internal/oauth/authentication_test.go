package oauth

import (
	"reflect"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func TestAuthorizationPreservesAuthenticationEvidence(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	user := testUser(t, db)
	client := testClient(t, db, "app", "public", []string{"https://app.test/cb"}, []string{"openid"})
	verifier, challenge := pkcePair()
	primary := time.Now().UTC().Add(-4 * time.Hour).Truncate(time.Second)
	factor := primary.Add(time.Minute)
	for _, tc := range []struct {
		method string
		amr    []any
		acr    string
	}{
		{"", []any{"pwd"}, "password"},
		{"totp", []any{"pwd", "otp", "mfa"}, "mfa"},
		{"push", []any{"pwd", "urn:kysignon:amr:push", "mfa"}, "mfa"},
		{"webauthn", []any{"pwd", "urn:kysignon:amr:webauthn", "mfa"}, "mfa"},
		{"recovery", []any{"pwd", "urn:kysignon:amr:recovery"}, "recovery"},
		{"legacy", nil, ""},
	} {
		t.Run(tc.method, func(t *testing.T) {
			sess := &store.Session{ID: uuid.NewString(), UserID: user.ID, SessionTokenHash: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)}
			if tc.method != "legacy" {
				sess.PrimaryAuthenticatedAt = &primary
			}
			if tc.method != "" && tc.method != "legacy" {
				sess.FactorAuthenticatedAt = &factor
				sess.FactorMethod = tc.method
			}
			if err := db.CreateSession(sess); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := db.TouchSession(sess.ID); err != nil {
					t.Fatal(err)
				}
				code, err := e.CreateAuthorizationCodeWithNonce(client.ID, sess.ID, "https://app.test/cb", "openid", challenge, "S256", "nonce")
				if err != nil {
					t.Fatal(err)
				}
				stored, err := db.GetValidAuthorizationCode(crypto.HashSHA256(code))
				if err != nil {
					t.Fatal(err)
				}
				if stored.SessionID != sess.ID || !reflect.DeepEqual(stored.AuthenticationEvidence, sess.AuthenticationEvidence) {
					t.Fatalf("evidence changed: %+v", stored)
				}
				tokens, err := e.ExchangeAuthorizationCode(code, client.ID, "", "https://app.test/cb", verifier)
				if err != nil {
					t.Fatal(err)
				}
				claims, err := e.keyManager.VerifyJWT(tokens.IDToken)
				if err != nil {
					t.Fatal(err)
				}
				if tc.method == "legacy" {
					for _, name := range []string{"auth_time", "amr", "acr"} {
						if _, ok := claims[name]; ok {
							t.Fatalf("invented legacy %s: %v", name, claims[name])
						}
					}
				} else if claims["auth_time"] != float64(primary.Unix()) || !reflect.DeepEqual(claims["amr"], tc.amr) || claims["acr"] != "urn:kysignon:acr:"+tc.acr {
					t.Fatalf("incorrect claims: %v", claims)
				}
				if claims["nonce"] != "nonce" {
					t.Fatal("nonce lost")
				}
				if sid, _ := claims["sid"].(string); sid == "" || sid == sess.ID {
					t.Fatalf("sid must be present and opaque, got %q for session %s", sid, sess.ID)
				}
			}
		})
	}
}

func TestSessionRemovalBlocksCodeExchangeAndIssuedToken(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	user := testUser(t, db)
	client := testClient(t, db, "app", "public", []string{"https://app.test/cb"}, []string{"openid"})
	verifier, challenge := pkcePair()
	sessionID := oauthSession(t, db, user.ID)
	code, err := e.CreateAuthorizationCode(client.ID, sessionID, "https://app.test/cb", "openid", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := e.ExchangeAuthorizationCode(code, client.ID, "", "https://app.test/cb", verifier)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := e.CreateAuthorizationCode(client.ID, sessionID, "https://app.test/cb", "openid", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteSession(sessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ExchangeAuthorizationCode(pending, client.ID, "", "https://app.test/cb", verifier); err == nil {
		t.Fatal("revoked session exchanged a code")
	}
	if _, err := e.GetUserinfo(tokens.AccessToken); err == nil {
		t.Fatal("token outlived originating session revocation")
	}
	if _, err := e.CreateAuthorizationCode(client.ID, sessionID, "https://app.test/cb", "openid", challenge, "S256"); err == nil {
		t.Fatal("removed session minted a code")
	}
}
