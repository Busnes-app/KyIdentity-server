package oauth

import (
	"errors"
	"strings"
	"testing"

	"github.com/Busness-app/kyidentity-server/internal/store"
)

func appFor(t *testing.T, db *store.Store, clientID string) store.AppRecord {
	t.Helper()
	rows, _, err := db.ListAppRecords(clientID, 25, 0)
	if err != nil || len(rows) != 1 {
		t.Fatalf("app record for %s: %v", clientID, err)
	}
	return rows[0]
}

func exchangeFor(t *testing.T, e *Engine, db *store.Store, user *store.User, clientID, scope string) (map[string]any, string) {
	t.Helper()
	verifier, challenge := pkcePair()
	code, err := e.CreateAuthorizationCode(clientID, oauthSession(t, db, user.ID), "https://app/cb", scope, challenge, "S256")
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	resp, err := e.ExchangeAuthorizationCode(code, clientID, "", "https://app/cb", verifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	claims, err := e.keyManager.VerifyJWT(resp.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	return claims, resp.AccessToken
}

// stringList reads a claim list whether it came back through JSON ([]any) or straight
// from the engine ([]string).
func stringList(v any) []string {
	if direct, ok := v.([]string); ok {
		return direct
	}
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, item.(string))
	}
	return out
}

// An ID token carries exactly the roles of its own app under the fixed `roles` claim,
// the global role only while the app keeps its legacy claim, and profile and email
// claims only for the scopes granted. UserInfo says the same.
func TestIDTokenCarriesOnlyThisAppsRoles(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	user := testUser(t, db)
	testClient(t, db, "billing", "public", []string{"https://app/cb"}, []string{"openid", "profile", "email"})
	testClient(t, db, "hr", "public", []string{"https://app/cb"}, []string{"openid", "profile"})
	billing := appFor(t, db, "billing")
	if err := db.CreateGroup(&store.Group{ID: "finance", Name: "Finance"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.SetGroupMembership("finance", user.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	role, err := db.CreateAppRole(billing.ID, "billing.admin", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetAppRoleAssignment(billing.ID, role.ID, "groups", "finance", true, nil); err != nil {
		t.Fatal(err)
	}

	claims, access := exchangeFor(t, e, db, user, "billing", "openid profile email")
	if got := stringList(claims["roles"]); len(got) != 1 || got[0] != "billing.admin" {
		t.Fatalf("billing roles: %v", claims["roles"])
	}
	if _, legacy := claims["role"]; legacy {
		t.Fatalf("new app carries the legacy role claim: %+v", claims)
	}
	if claims["email"] != user.Email || claims["preferred_username"] != user.Username {
		t.Fatalf("profile/email claims missing: %+v", claims)
	}
	if _, groups := claims["groups"]; groups {
		t.Fatal("groups claim emitted without being enabled")
	}
	info, err := e.GetUserinfo(access)
	if err != nil || len(stringList(info["roles"])) != 1 || info["email"] != user.Email {
		t.Fatalf("userinfo: %+v %v", info, err)
	}

	// The other app sees no billing role, and no email without the email scope.
	claims, access = exchangeFor(t, e, db, user, "hr", "openid profile")
	if got := stringList(claims["roles"]); len(got) != 0 {
		t.Fatalf("billing role leaked into hr: %v", got)
	}
	if _, has := claims["email"]; has {
		t.Fatalf("email emitted without the email scope: %+v", claims)
	}
	if claims["name"] != user.DisplayName {
		t.Fatalf("profile claim missing: %+v", claims)
	}
	info, _ = e.GetUserinfo(access)
	if _, has := info["email"]; has || len(stringList(info["roles"])) != 0 {
		t.Fatalf("userinfo widened the grant: %+v", info)
	}

	// Legacy role and groups claims are per-app switches.
	billing, _ = db.GetAppRecord(billing.ID)
	if err := db.SetAppClaimSettings(billing.ID, true, true, billing.Revision, nil); err != nil {
		t.Fatal(err)
	}
	claims, _ = exchangeFor(t, e, db, user, "billing", "openid")
	if claims["role"] != "user" || len(stringList(claims["groups"])) != 1 || stringList(claims["groups"])[0] != "Finance" {
		t.Fatalf("legacy role and groups: %+v", claims)
	}
	if _, has := claims["preferred_username"]; has {
		t.Fatalf("profile claim without the profile scope: %+v", claims)
	}
}

// A code issued before a role change is refused at exchange, and an unbounded mapping
// set fails with an actionable error rather than a silently trimmed token.
func TestRoleChangesBlockExchangeAndOversizedClaimsAreRefused(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	user := testUser(t, db)
	testClient(t, db, "billing", "public", []string{"https://app/cb"}, []string{"openid"})
	billing := appFor(t, db, "billing")
	role, _ := db.CreateAppRole(billing.ID, "reader", "", nil)
	verifier, challenge := pkcePair()
	code, err := e.CreateAuthorizationCode("billing", oauthSession(t, db, user.ID), "https://app/cb", "openid", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	other := testUser(t, db)
	if err := db.SetAppRoleAssignment(billing.ID, role.ID, "users", other.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ExchangeAuthorizationCode(code, "billing", "", "https://app/cb", verifier); err == nil {
		t.Fatal("code issued before a role change was exchanged")
	}

	for i := 0; i < 120; i++ {
		r, err := db.CreateAppRole(billing.ID, "role-"+strings.Repeat("x", 40)+"-"+string(rune('a'+i%26))+string(rune('a'+i/26)), "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.SetAppRoleAssignment(billing.ID, r.ID, "users", user.ID, true, nil); err != nil {
			t.Fatal(err)
		}
	}
	code, err = e.CreateAuthorizationCode("billing", oauthSession(t, db, user.ID), "https://app/cb", "openid", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.ExchangeAuthorizationCode(code, "billing", "", "https://app/cb", verifier)
	if !errors.Is(err, ErrClaimsTooLarge) {
		t.Fatalf("oversized claims: %v", err)
	}
}
