package oauth

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func TestInstallerAssignmentsIssueOnlyDeclaredAppRoles(t *testing.T) {
	engine, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	secret := strings.Repeat("q", 48)
	setup := store.InstallerSetup{ID: uuid.NewString(),
		Admin:    store.InstallerUser{Username: "installer-admin", Email: "admin@example.test", Role: "admin", PasswordHash: "fixture-hash"},
		Everyday: store.InstallerUser{Username: "installer-owner", Email: "owner@example.test", Role: "user", PasswordHash: "fixture-hash"}}
	for _, entry := range []struct{ client, admin, daily string }{{"wiki", "admin", "editor"}, {"manage", "kyyard.admin", ""}, {"ordinary", "", ""}} {
		setup.Clients = append(setup.Clients, store.InstallerClient{ID: entry.client, Name: entry.client, SecretHash: crypto.HashSHA256(secret),
			RedirectURIs: []string{"https://app/cb"}, PostLogoutURIs: []string{}, AdministratorRole: entry.admin, EverydayRole: entry.daily})
	}
	if _, err := db.ApplyInstallerSetup(setup, false); err != nil {
		t.Fatal(err)
	}
	admin, err := db.GetUserByUsername(setup.Admin.Username)
	if err != nil {
		t.Fatal(err)
	}
	daily, err := db.GetUserByUsername(setup.Everyday.Username)
	if err != nil {
		t.Fatal(err)
	}
	unassigned := testUser(t, db)
	for _, row := range []struct {
		user    *store.User
		client  string
		roles   []string
		allowed bool
	}{
		{admin, "wiki", []string{"admin"}, true}, {daily, "wiki", []string{"editor"}, true},
		{admin, "manage", []string{"kyyard.admin"}, true}, {daily, "manage", nil, false},
		{admin, "ordinary", nil, false}, {daily, "ordinary", nil, true},
		{unassigned, "wiki", nil, false}, {unassigned, "manage", nil, false}, {unassigned, "ordinary", nil, false},
	} {
		verifier, challenge := pkcePair()
		code, err := engine.CreateAuthorizationCode(row.client, oauthSession(t, db, row.user.ID), "https://app/cb", "openid profile email", challenge, "S256")
		if !row.allowed {
			if !errors.Is(err, store.ErrAppAccessDenied) {
				t.Fatalf("unexpected issuance result for %s: %v", row.client, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		token, err := engine.ExchangeAuthorizationCode(code, row.client, secret, "https://app/cb", verifier)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := engine.keyManager.VerifyJWT(token.IDToken, engine.issuerURL, "id_token")
		if err != nil {
			t.Fatal(err)
		}
		if claims["sub"] != row.user.ID || !slices.Equal(stringList(claims["roles"]), row.roles) {
			t.Fatalf("wrong native token binding/roles: %+v", claims)
		}
		if _, ok := claims["role"]; ok {
			t.Fatal("global directory administrator role leaked to app")
		}
		info, err := engine.GetUserinfo(token.AccessToken)
		if err != nil || info["sub"] != row.user.ID || !slices.Equal(stringList(info["roles"]), row.roles) {
			t.Fatalf("wrong UserInfo roles: %+v error %v", info, err)
		}
	}
}
