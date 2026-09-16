package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// issueToken puts a token on the revocation registry the way the token endpoint does.
func issueToken(t *testing.T, db *store.Store, userID, clientID string) string {
	t.Helper()
	if c, err := db.GetOAuthClientByID(clientID); err != nil {
		t.Fatal(err)
	} else if c == nil {
		newClient(t, db, clientID, []string{"https://example.com/cb"}, []string{"openid"})
	}
	allowTestAppAccess(t, db, clientID)
	jti := uuid.New().String()
	if err := db.RecordIssuedToken(&store.IssuedToken{
		JTI: jti, UserID: userID, ClientID: clientID, SessionID: oauthSession(t, db, userID),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("RecordIssuedToken: %v", err)
	}
	return jti
}

func assertRevoked(t *testing.T, db *store.Store, jti string, want bool, what string) {
	t.Helper()
	got, err := db.IsTokenRevoked(jti)
	if err != nil {
		t.Fatalf("IsTokenRevoked: %v", err)
	}
	if got != want {
		t.Fatalf("%s: revoked = %v, want %v", what, got, want)
	}
}

// Demotion is a revocation. An ID token carries "role":"admin" as a signed claim, so a
// relying party keeps honouring it for the token's full lifetime unless it is revoked.
func TestDemotingAnAdministratorRevokesItsTokens(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	actor := newUser(t, db, "admin")
	target := newUser(t, db, "admin")
	cookie := newSession(t, db, actor, time.Now().UTC().Add(time.Hour))

	jti := issueToken(t, db, target.ID, "some-client")
	targetSession := newSession(t, db, target, time.Now().UTC().Add(time.Hour))

	rr := adminRequest(t, srv, "PUT", "/api/admin/users/"+target.ID, cookie, `{"role":"user"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("demotion failed: %d %s", rr.Code, rr.Body.String())
	}

	assertRevoked(t, db, jti, true, "a demoted administrator's access token")

	sess, err := db.GetSessionByTokenHash(crypto.HashSHA256(targetSession), time.Hour)
	if err != nil {
		t.Fatalf("GetSessionByTokenHash: %v", err)
	}
	if sess != nil {
		t.Fatal("a demoted administrator kept a live browser session")
	}
}

// A rename must not revoke. Revocation that fires on every edit trains admins to ignore it.
func TestEditingAUserWithoutPrivilegeChangeKeepsItsTokens(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	actor := newUser(t, db, "admin")
	target := newUser(t, db, "user")
	cookie := newSession(t, db, actor, time.Now().UTC().Add(time.Hour))
	jti := issueToken(t, db, target.ID, "some-client")

	rr := adminRequest(t, srv, "PUT", "/api/admin/users/"+target.ID, cookie, `{"displayName":"Renamed"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("rename failed: %d %s", rr.Code, rr.Body.String())
	}
	assertRevoked(t, db, jti, false, "a renamed user's access token")
}

// A deleted client's bearer tokens must stop working. Otherwise deleting a compromised
// integration is cosmetic until every outstanding token expires on its own.
func TestDeletingAnOAuthClientRevokesItsTokens(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	newClient(t, db, "doomed", []string{"https://app.test/cb"}, []string{"openid"})

	mine := issueToken(t, db, admin.ID, "doomed")
	theirs := issueToken(t, db, admin.ID, "unrelated")

	rr := adminRequest(t, srv, "DELETE", "/api/admin/clients/doomed", cookie, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("client deletion failed: %d %s", rr.Code, rr.Body.String())
	}
	assertRevoked(t, db, mine, true, "a deleted client's access token")
	assertRevoked(t, db, theirs, false, "an unrelated client's access token")
}

// Deleting something that is not there is not a success. Reporting one lets an admin walk
// away believing a compromised client is gone while it is still registered and serving.
func TestDeletingAMissingClientIsNotReportedAsSuccess(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	if rr := adminRequest(t, srv, "DELETE", "/api/admin/clients/never-existed", cookie, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("deleting a missing client returned %d %s, want 404", rr.Code, rr.Body.String())
	}
	if rr := adminRequest(t, srv, "DELETE", "/api/admin/applications/"+uuid.New().String(), cookie, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("deleting a missing application returned %d %s, want 404", rr.Code, rr.Body.String())
	}
}

// Disabling a client, downgrading it to public, and rotating its secret each withdraw the
// authority its outstanding tokens were issued under.
func TestOAuthClientLifecycleChangesRevokeTokens(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		clientType string
		revokes    bool
	}{
		{"disable", `{"enabled":false}`, "confidential", true},
		{"downgrade to public", `{"clientType":"public"}`, "confidential", true},
		{"rotate secret", `{"rotateSecret":true}`, "confidential", true},
		{"rename", `{"clientName":"Renamed"}`, "confidential", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, db, _, _, _, cleanup := setupTestServer(t)
			defer cleanup()

			admin := newUser(t, db, "admin")
			cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
			id := "client-" + uuid.New().String()[:8]
			newClient(t, db, id, []string{"https://app.test/cb"}, []string{"openid"})
			// newClient registers a public client; promote it first so every case starts
			// from a confidential client with a secret.
			if rr := adminRequest(t, srv, "PUT", "/api/admin/clients/"+id, cookie, `{"clientType":"confidential"}`); rr.Code != http.StatusOK {
				t.Fatalf("promotion failed: %d %s", rr.Code, rr.Body.String())
			}

			jti := issueToken(t, db, admin.ID, id)
			rr := adminRequest(t, srv, "PUT", "/api/admin/clients/"+id, cookie, tc.body)
			if rr.Code != http.StatusOK {
				t.Fatalf("update failed: %d %s", rr.Code, rr.Body.String())
			}
			assertRevoked(t, db, jti, tc.revokes, tc.name)
		})
	}
}

// The audit row and the mutation are one commit. If the audit write cannot happen, the
// mutation must not happen either — the alternative is an unattributed security change.
func TestUserMutationsAndTheirAuditRowsCommitTogether(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	body := fmt.Sprintf(`{"username":"audited-%s","password":"correct-horse-battery","displayName":"A","email":"a-%s@x.test"}`,
		uuid.New().String()[:8], uuid.New().String()[:8])
	rr := adminRequest(t, srv, "POST", "/api/admin/users", cookie, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("user creation failed: %d %s", rr.Code, rr.Body.String())
	}
	var created struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	for _, action := range []string{"admin.user_created", "admin.user_updated", "admin.user_deleted"} {
		switch action {
		case "admin.user_updated":
			if got := adminRequest(t, srv, "PUT", "/api/admin/users/"+created.User.ID, cookie, `{"displayName":"B"}`); got.Code != http.StatusOK {
				t.Fatalf("update failed: %d %s", got.Code, got.Body.String())
			}
		case "admin.user_deleted":
			if got := adminRequest(t, srv, "DELETE", "/api/admin/users/"+created.User.ID, cookie, ""); got.Code != http.StatusOK {
				t.Fatalf("delete failed: %d %s", got.Code, got.Body.String())
			}
		}
		if !auditRecorded(t, db, action, created.User.ID) {
			t.Fatalf("%s committed without a durable audit row", action)
		}
	}
}

func auditRecorded(t *testing.T, db *store.Store, action, targetID string) bool {
	t.Helper()
	events, _, err := db.ListAuditEvents(500, 0)
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	for _, e := range events {
		if e.Action == action && e.TargetID == targetID {
			return true
		}
	}
	return false
}

// The web UI validates `role` and `status` against exact unions and refuses anything else,
// rather than folding an unknown value into a safe-looking default. That makes these two
// fields part of the wire contract: dropping either from an auth response does not degrade
// the UI, it breaks sign-in outright. Nothing else ties the Go handler to the TypeScript
// parser, so this test does.
func TestAuthResponsesCarryTheUnionFieldsTheUIValidates(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	user := newUser(t, db, "admin")
	cookie := newSession(t, db, user, time.Now().UTC().Add(time.Hour))

	req := httptest.NewRequest("GET", "/api/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/api/auth/me failed: %d %s", rr.Code, rr.Body.String())
	}
	assertUnionFields(t, rr.Body.Bytes(), "/api/auth/me")

	login := httptest.NewRequest("POST", "/api/auth/login",
		strings.NewReader(`{"username":"`+user.Username+`","password":"correct-horse-battery"}`))
	login.Header.Set("Content-Type", "application/json")
	csrf := srv.middleware.IssueCSRFToken("")
	login.Header.Set("X-CSRF-Token", csrf)
	login.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: csrf})
	loginRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(loginRR, login)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", loginRR.Code, loginRR.Body.String())
	}
	var body struct {
		User json.RawMessage `json:"user"`
	}
	if err := json.Unmarshal(loginRR.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.User) == 0 {
		t.Fatal("the login response carried no user object")
	}
	assertUnionFields(t, body.User, "/api/auth/login")
}

func assertUnionFields(t *testing.T, payload []byte, what string) {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	for field, allowed := range map[string][]string{
		"role":   {"admin", "user"},
		"status": {"active", "disabled"},
	} {
		v, ok := got[field].(string)
		if !ok {
			t.Fatalf("%s omitted %q, which the UI parser requires", what, field)
		}
		if !slices.Contains(allowed, v) {
			t.Fatalf("%s sent %s=%q, which the UI parser rejects (want one of %v)", what, field, v, allowed)
		}
	}
}
