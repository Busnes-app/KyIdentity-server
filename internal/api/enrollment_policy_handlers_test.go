package api

import (
	"database/sql"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func enrollmentAPIAdmin(t *testing.T, srv *Server, db *store.Store) string {
	t.Helper()
	u := newUser(t, db, "admin")
	if err := srv.mfaEngine.SaveUserTOTP(u.ID, "JBSWY3DPEHPK3PXP", nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cookie := "enrollment-admin-cookie"
	if err := db.CreateSession(&store.Session{ID: "enrollment-admin", UserID: u.ID, SessionTokenHash: crypto.HashSHA256(cookie), ExpiresAt: now.Add(time.Hour), AuthenticationEvidence: store.AuthenticationEvidence{PrimaryAuthenticatedAt: &now, FactorAuthenticatedAt: &now, FactorMethod: "totp"}}); err != nil {
		t.Fatal(err)
	}
	return cookie
}
func policyJSON(t *testing.T, p store.EnrollmentPolicy) string {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func TestEnrollmentPolicyAdminBoundaries(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := enrollmentAPIAdmin(t, srv, db)
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	path := "/api/admin/enrollment-policies"
	body := policyJSON(t, store.EnrollmentPolicy{Scope: "organization", Required: true, AllowedMethods: []string{"totp", "webauthn"}, GraceSeconds: 3600, Revision: 1})
	for _, route := range []struct{ method, path string }{{"GET", path}, {"POST", path + "/preview"}, {"PUT", path}} {
		if r := adminRequestNoStepUp(t, srv, route.method, route.path, cookie, body); r.Code != 403 {
			t.Fatal("non-admin", r.Code)
		}
	}
	if r := adminRequestNoStepUp(t, srv, "PUT", path, admin, body); r.Code != 403 {
		t.Fatal("missing step-up", r.Code)
	}
	if r := adminRequestNoStepUp(t, srv, "POST", path+"/preview", admin, body); r.Code != 200 || !strings.Contains(r.Body.String(), `"canActivate":true`) {
		t.Fatal("preview", r.Body.String())
	}
	policies, _ := db.ListEnrollmentPolicies()
	for _, p := range policies {
		if p.Required {
			t.Fatal("preview changed policy")
		}
	}
	for _, raw := range []string{`{}`, `{"scope":"group","required":true,"allowedMethods":["totp"],"graceSeconds":0,"revision":1}`, `{"scope":"organization","required":true,"allowedMethods":["recovery"],"graceSeconds":0,"revision":1}`, `{"scope":"organization","required":true,"allowedMethods":["totp"],"graceSeconds":-1,"revision":1}`, body + `{}`} {
		if r := adminRequestNoStepUp(t, srv, "POST", path+"/preview", admin, raw); r.Code != 400 {
			t.Fatal("invalid policy accepted", raw, r.Code)
		}
	}
	wrong := mintStepUp(t, srv, admin, "PUT /api/admin/other")
	if r := adminRequestWithStepUp(t, srv, "PUT", path, admin, body, wrong); r.Code != 403 {
		t.Fatal("wrong-operation grant", r.Code)
	}
	if r := adminRequest(t, srv, "PUT", path, admin, body); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if r := adminRequest(t, srv, "PUT", path, admin, body); r.Code != 409 {
		t.Fatal("stale policy overwrite", r.Code)
	}
	events, _, err := db.ListAuditEvents(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	var preview, denied bool
	for _, event := range events {
		if event.Action == "admin.mfa_enrollment_policy_previewed" && event.Outcome == "success" {
			preview = true
		}
		if event.Action == "admin.mfa_enrollment_policy_changed" && event.Outcome == "denied" && strings.Contains(event.DetailsJSON, "revision_conflict") {
			denied = true
		}
	}
	if !preview || !denied {
		t.Fatalf("missing audit records: preview=%v stale-denial=%v", preview, denied)
	}

}

func TestEnrollmentRestrictedHTTPAndTOTPCompletion(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := enrollmentAPIAdmin(t, srv, db)
	u := newUser(t, db, "user")
	newClient(t, db, "app", []string{"https://app.example/cb"}, []string{"openid"})
	body := policyJSON(t, store.EnrollmentPolicy{Scope: "organization", Required: true, AllowedMethods: []string{"totp"}, GraceSeconds: 0, Revision: 1})
	if r := adminRequest(t, srv, "PUT", "/api/admin/enrollment-policies", admin, body); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	browser := interactionBrowser(t, srv)
	r := browser("POST", "/api/auth/login", map[string]string{"username": u.Username, "password": "correct-horse-battery"})
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	cookie := sessionCookie(r)
	if cookie == nil {
		t.Fatal("missing enrollment session")
	}
	if !strings.Contains(r.Body.String(), `"restricted":true`) {
		t.Fatal("login did not expose restriction", r.Body.String())
	}
	for _, route := range []struct{ method, path string }{{"GET", "/api/admin/users"}, {"GET", "/api/user/applications"}, {"POST", "/api/user/recovery-codes"}, {"DELETE", "/api/user/passkeys/any"}, {"PUT", "/api/notifications/native/devices/any/mfa"}} {
		if r := browser(route.method, route.path, nil); r.Code != 403 || !strings.Contains(r.Body.String(), "enrollment_required") {
			t.Fatal("restricted route escaped", route, r.Code, r.Body.String())
		}
	}
	q := appAuthQuery("app")
	q.Set("prompt", "none")
	r = browser("GET", "/oauth/authorize?"+q.Encode(), nil)
	target, _ := url.Parse(r.Header().Get("Location"))
	if target.Query().Get("error") != "interaction_required" || target.Query().Get("state") != "original" {
		t.Fatal("restricted OAuth escaped", target)
	}
	// Even a valid password cannot get an unrelated grant from an enrollment session.
	r = browser("POST", "/api/auth/step-up", map[string]string{"password": "correct-horse-battery", "operation": "PUT /api/admin/enrollment-policies"})
	if r.Code != 403 {
		t.Fatal("restricted grant", r.Code, r.Body.String())
	}
	// Use the real password-only enrollment step-up and actual TOTP enrollment route.
	r = browser("POST", "/api/auth/step-up", map[string]string{"password": "correct-horse-battery", "operation": "POST /api/user/mfa/totp/enable"})
	if r.Code != 200 {
		t.Fatal("enrollment step-up denied", r.Code, r.Body.String())
	}
	var grant struct {
		StepUpToken string `json:"stepUpToken"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	// The existing step-up response uses stepUpToken.
	token := grant.StepUpToken
	if token == "" {
		t.Fatal("missing grant", r.Body.String())
	}
	secret := "JBSWY3DPEHPK3PXP"
	proof := testTOTPCode(t, secret)
	enrollmentBody, _ := json.Marshal(map[string]string{"secret": secret, "code": proof})
	r = adminRequestWithStepUp(t, srv, "POST", "/api/user/mfa/totp/enable", cookie.Value, string(enrollmentBody), token)
	if r.Code != 200 {
		t.Fatal("enrollment failed", r.Code, r.Body.String())
	}
	if r := browser("GET", "/api/auth/me", nil); r.Code != 200 || !strings.Contains(r.Body.String(), `"restricted":true`) || !strings.Contains(r.Body.String(), `"enrolled":true`) {
		t.Fatal("enrollment upgraded session", r.Body.String())
	}
	// A new password-plus-TOTP login exits the restricted session.
	r = browser("POST", "/api/auth/login", map[string]string{"username": u.Username, "password": "correct-horse-battery"})
	var step LoginResponse
	if err := json.Unmarshal(r.Body.Bytes(), &step); err != nil || !step.MFARequired {
		t.Fatal(r.Body.String())
	}
	r = browser("POST", "/api/auth/mfa/totp/verify", map[string]string{"mfaToken": step.MFAToken, "code": proof})
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"restricted":false`) {
		t.Fatal("compliant sign-in failed", r.Code, r.Body.String())
	}
	if r := browser("GET", "/api/user/applications", nil); r.Code != 200 {
		t.Fatal("fresh compliant login denied", r.Code)
	}
}

func TestEnrollmentPolicyDenialAuditAndPreviewFailure(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "admin")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	path := "/api/admin/enrollment-policies"
	body := policyJSON(t, store.EnrollmentPolicy{Scope: "organization", Required: true, AllowedMethods: []string{"totp"}, GraceSeconds: 3600, Revision: 1})
	for _, tc := range []struct {
		body, reason string
		code         int
	}{
		{body, "compliant_admin_required", 409}, {`{}`, "invalid_policy", 400},
	} {
		r := adminRequest(t, srv, "PUT", path, cookie, tc.body)
		if r.Code != tc.code {
			t.Fatal(r.Code, r.Body.String())
		}
		events, _, err := db.ListAuditEvents(100, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, e := range events {
			if e.Action == "admin.mfa_enrollment_policy_changed" && e.Outcome == "denied" && e.ActorID == u.ID && strings.Contains(e.DetailsJSON, tc.reason) {
				found = true
			}
		}
		if !found {
			t.Fatal("missing denial audit", tc.reason)
		}
	}
	raw, err := sql.Open("sqlite", srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`CREATE TRIGGER reject_preview_audit BEFORE INSERT ON audit_events WHEN NEW.action='admin.mfa_enrollment_policy_previewed' BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	r := adminRequestNoStepUp(t, srv, "POST", path+"/preview", cookie, body)
	if r.Code != 500 || strings.Contains(r.Body.String(), "missingFactor") {
		t.Fatal("unaudited preview disclosed", r.Code, r.Body.String())
	}
}

func TestEnrollmentInteractionCannotSkipExistingFactor(t *testing.T) {
	for _, allowed := range []string{"push", "webauthn"} {
		t.Run(allowed, func(t *testing.T) {
			srv, db, _, _, _, cleanup := setupTestServer(t)
			defer cleanup()
			admin := newUser(t, db, "admin")
			if allowed == "webauthn" {
				enrolPasskey(t, db, admin.ID, newTestAuthenticator(t, "admin-key"))
			} else {
				if err := db.UpsertNativeDevice(&store.NativeDevice{ID: "admin-phone", UserID: admin.ID, DeviceIdentifier: "phone", PublicKey: "test", IsMFAApprover: true}); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now().UTC()
			if err := db.CreateSession(&store.Session{ID: "policy-admin", UserID: admin.ID, SessionTokenHash: "policy-admin", ExpiresAt: now.Add(time.Hour), AuthenticationEvidence: store.AuthenticationEvidence{PrimaryAuthenticatedAt: &now, FactorAuthenticatedAt: &now, FactorMethod: allowed}}); err != nil {
				t.Fatal(err)
			}
			u := newUser(t, db, "user")
			if err := srv.mfaEngine.SaveUserTOTP(u.ID, "JBSWY3DPEHPK3PXP", nil); err != nil {
				t.Fatal(err)
			}
			if err := db.SetEnrollmentPolicy(store.EnrollmentPolicy{Scope: "organization", Required: true, AllowedMethods: []string{allowed}, Revision: 1}, "policy-admin", nil); err != nil {
				t.Fatal(err)
			}
			newClient(t, db, "app", []string{"https://app.example/cb"}, []string{"openid"})
			setTestAuthenticationPolicy(t, db, "app", store.AppAuthenticationPolicy{Mode: "reuse", Factor: "passkey"})
			browser := interactionBrowser(t, srv)
			r := browser("GET", "/oauth/authorize?"+appAuthQuery("app").Encode(), nil)
			location, _ := url.Parse(r.Header().Get("Location"))
			interaction := location.Query().Get("interaction")
			if interaction == "" {
				t.Fatal("missing interaction")
			}
			r = browser("POST", "/api/auth/login", map[string]string{"username": u.Username, "password": "correct-horse-battery", "interaction": interaction})
			if r.Code != 403 {
				t.Fatalf("existing TOTP bypassed: status=%d body=%s", r.Code, r.Body.String())
			}
			for _, c := range r.Result().Cookies() {
				if c.Name == "kyidentity_session" && c.Value != "" {
					t.Fatal("password-only session issued")
				}
			}
			if r := browser("POST", "/api/user/devices/pairing-token", nil); r.Code != 401 {
				t.Fatal("unauthenticated pairing", r.Code)
			}

			// Normal sign-in still requires the existing factor before enrollment access.
			r = browser("POST", "/api/auth/login", map[string]string{"username": u.Username, "password": "correct-horse-battery"})
			var step LoginResponse
			if err := json.Unmarshal(r.Body.Bytes(), &step); err != nil || !step.MFARequired {
				t.Fatal("existing factor not required", r.Body.String())
			}
			r = browser("POST", "/api/auth/mfa/totp/verify", map[string]string{"mfaToken": step.MFAToken, "code": testTOTPCode(t, "JBSWY3DPEHPK3PXP")})
			if r.Code != 200 || !strings.Contains(r.Body.String(), `"restricted":true`) {
				t.Fatal("verified factor enrollment access", r.Code, r.Body.String())
			}
			if r := browser("POST", "/api/user/devices/pairing-token", nil); r.Code != 403 {
				t.Fatal("pairing without step-up", r.Code)
			}
			r = browser("POST", "/api/auth/step-up", map[string]string{"password": "correct-horse-battery", "operation": "POST /api/user/devices/pairing-token"})
			if r.Code == 200 {
				t.Fatal("password alone obtained enrollment grant", r.Body.String())
			}
			// A genuinely never-enrolled account can still enter restricted enrollment.
			fresh := newUser(t, db, "user")
			freshBrowser := interactionBrowser(t, srv)
			r = freshBrowser("GET", "/oauth/authorize?"+appAuthQuery("app").Encode(), nil)
			location, _ = url.Parse(r.Header().Get("Location"))
			r = freshBrowser("POST", "/api/auth/login", map[string]string{"username": fresh.Username, "password": "correct-horse-battery", "interaction": location.Query().Get("interaction")})
			if r.Code != 200 || sessionCookie(r) == nil || !strings.Contains(r.Body.String(), `"restricted":true`) {
				t.Fatal("never-enrolled fallback broken", r.Code, r.Body.String())
			}
		})
	}
}

func TestPairingTokenRequiresBoundSingleUseStepUp(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := enrollmentAPIAdmin(t, srv, db)
	u := newUser(t, db, "user")
	body := policyJSON(t, store.EnrollmentPolicy{Scope: "organization", Required: true, AllowedMethods: []string{"totp", "push"}, Revision: 1})
	if r := adminRequest(t, srv, "PUT", "/api/admin/enrollment-policies", admin, body); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	path := "/api/user/devices/pairing-token"
	if r := adminRequestNoStepUp(t, srv, "POST", path, cookie, `{}`); r.Code != 403 {
		t.Fatalf("pairing without proof: %d", r.Code)
	}
	wrong := mintStepUp(t, srv, cookie, "POST /api/user/mfa/totp/enable")
	if r := adminRequestWithStepUp(t, srv, "POST", path, cookie, `{}`, wrong); r.Code != 403 {
		t.Fatal("wrong operation accepted", r.Code)
	}
	grant := mintStepUp(t, srv, cookie, "POST "+path)
	if r := adminRequestWithStepUp(t, srv, "POST", path, cookie, `{}`, grant); r.Code != 200 {
		t.Fatal("authorized enrollment denied", r.Code, r.Body.String())
	}
	if r := adminRequestWithStepUp(t, srv, "POST", path, cookie, `{}`, grant); r.Code != 403 {
		t.Fatal("grant replay", r.Code)
	}
}
