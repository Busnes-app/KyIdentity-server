package oauth

import (
	"testing"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/store"
)

// A token issued on bounded access ends with the access: the access token, the ID token
// and expires_in all stop at the grant's instant rather than the default lifetime.
func TestTokensEndWithTheAccessTheyCarry(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	user := testUser(t, db)
	testClient(t, db, "bounded", "public", []string{"https://app/cb"}, []string{"openid"})
	app := appFor(t, db, "bounded")
	if err := db.SetAppPolicy(app.ID, "assigned_only", true, app.Revision, nil); err != nil {
		t.Fatal(err)
	}
	until := time.Now().UTC().Add(5 * time.Minute).Truncate(time.Second)
	if err := db.SetAppAssignmentUntil(app.ID, "users", user.ID, &until, nil); err != nil {
		t.Fatal(err)
	}
	verifier, challenge := pkcePair()
	code, err := e.CreateAuthorizationCode("bounded", oauthSession(t, db, user.ID), "https://app/cb", "openid", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.ExchangeAuthorizationCode(code, "bounded", "", "https://app/cb", verifier)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ExpiresIn <= 0 || resp.ExpiresIn > 300 {
		t.Fatalf("expires_in = %d, want at most the grant's 300s", resp.ExpiresIn)
	}
	claims, err := e.keyManager.VerifyJWT(resp.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	if exp, _ := claims["exp"].(float64); int64(exp) != until.Unix() {
		t.Fatalf("id token exp = %v, want %d", claims["exp"], until.Unix())
	}
	// An unbounded grant keeps the default lifetime.
	if err := db.SetAppAssignment(app.ID, "users", user.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	verifier, challenge = pkcePair()
	code, err = e.CreateAuthorizationCode("bounded", oauthSession(t, db, user.ID), "https://app/cb", "openid", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	if resp, err = e.ExchangeAuthorizationCode(code, "bounded", "", "https://app/cb", verifier); err != nil || resp.ExpiresIn != int(AccessTokenTTL.Seconds()) {
		t.Fatalf("unbounded expires_in = %d %v", resp.ExpiresIn, err)
	}
	_ = store.ErrExpiryInPast
}
