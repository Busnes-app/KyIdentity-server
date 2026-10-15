package sync_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/api"
	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/netguard"
	"github.com/Busnes-app/kyidentity-server/internal/oauth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	identitysync "github.com/Busnes-app/kyidentity-server/internal/sync"
	"github.com/google/uuid"
)

// Run by KyNotes' TestKyIdentityNativeDirectoryDelivery using a precompiled test
// binary. Only disposable accounts, native scope hooks and the actual worker are
// used; no desired-state rows, event bodies or signatures are manufactured here.
func TestKyNotesNativeDirectorySender(t *testing.T) {
	dir := os.Getenv("KYIDENTITY_TEST_NOTES_FIXTURE")
	if dir == "" {
		t.Skip("real KyNotes receiver not requested")
	}
	var receiver struct{ URL, Certificate string }
	body, err := os.ReadFile(filepath.Join(dir, "receiver.json"))
	if err != nil || json.Unmarshal(body, &receiver) != nil {
		t.Fatal("invalid receiver fixture")
	}
	u, err := url.Parse(receiver.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.User != nil || u.Path != "/api/v1/sync/events" {
		t.Fatal("receiver must be the owned loopback TLS fixture")
	}
	// This separately executed test binary trusts only the owned receiver CA.
	// Keep the actual outbound transport, TLS checks and redirect refusal intact.
	ca := filepath.Join(t.TempDir(), "receiver.pem")
	if err := os.WriteFile(ca, []byte(receiver.Certificate), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", ca)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	previous, previousLoopback := netguard.AllowPrivate, netguard.AllowLoopback
	netguard.AllowPrivate, netguard.AllowLoopback = true, true
	t.Cleanup(func() { netguard.AllowPrivate, netguard.AllowLoopback = previous, previousLoopback })
	s, err := store.New(filepath.Join(t.TempDir(), "identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	passwordHash, err := auth.HashPassword("native-fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	foreign := &store.User{ID: uuid.NewString(), Username: "foreign-admin", Email: "foreign@example.test", PasswordHash: passwordHash, Role: "admin", Status: "active"}
	if err := s.CreateUser(foreign); err != nil {
		t.Fatal(err)
	}
	e := identitysync.NewEngine(s, key)
	clientSecret, err := crypto.GenerateRandomHex(32)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := crypto.GenerateRandomHex(32)
	if err != nil {
		t.Fatal(err)
	}
	p := store.InstallerSetup{ID: uuid.NewString(), EncryptionKey: key,
		Admin:    store.InstallerUser{Username: "owner-admin", Email: "owner-admin@example.test", Role: "admin", PasswordHash: passwordHash},
		Everyday: store.InstallerUser{Username: "owner", Email: "owner@example.test", Role: "user", PasswordHash: passwordHash},
		Clients:  []store.InstallerClient{{ID: "kynotes", Name: "KyNotes", SecretHash: crypto.HashSHA256(clientSecret), RedirectURIs: []string{"https://notes.example.test/api/v1/auth/oidc/callback"}, PostLogoutURIs: []string{}, AdministratorRole: "kynotes.admin", EverydayRole: "kynotes.user", SuiteWebhook: &store.InstallerSuiteWebhook{URL: receiver.URL, SigningSecret: secret}}}}
	report, err := s.ApplyInstallerSetup(p, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, inspect := range []bool{true, false} {
		checked, err := s.ApplyInstallerSetup(p, inspect)
		if err != nil || len(checked.Created) != 0 {
			t.Fatal("owned suite connector check/resume failed", err)
		}
	}
	owner, err := s.GetUserByUsername("owner-admin")
	if err != nil {
		t.Fatal(err)
	}
	day, err := s.GetUserByUsername("owner")
	if err != nil {
		t.Fatal(err)
	}
	var systemID string
	for _, object := range report.Created {
		if object.Kind == "connector" {
			systemID = object.ID
		}
	}
	system, err := s.GetPairedSystemByID(systemID)
	if err != nil {
		t.Fatal(err)
	}
	apps, _, err := s.ListAppRecords("", 1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	var app store.AppRecord
	for _, candidate := range apps {
		if candidate.SystemID == system.ID {
			app = candidate
		}
	}
	if app.ClientID != "kynotes" || system.SystemType != "suite_webhook" {
		t.Fatal("owned suite connector is detached from its OIDC app")
	}
	if stored, err := e.SigningSecret(system); err != nil || stored != secret {
		t.Fatal("owned signing secret does not match native worker readback", err)
	}
	// Use production login, authorization, token, discovery and JWKS handlers.
	// The fixture has no enrolled MFA; it does not relax enrollment or assurance.
	mux := http.NewServeMux()
	issuer := httptest.NewUnstartedServer(mux)
	issuerURL := "https://" + issuer.Listener.Addr().String()
	km, err := crypto.LoadOrCreateRSAKey(filepath.Join(t.TempDir(), "issuer.key"))
	if err != nil {
		t.Fatal(err)
	}
	mm := api.NewMiddlewareManager(s, nil, "", key)
	logger := audit.NewLogger(s)
	oh := api.NewOAuthHandler(s, oauth.NewEngine(s, km, issuerURL), logger, mm)
	ah := api.NewAuthHandler(s, mfa.NewEngine(s, key), logger, mm, true)
	mux.HandleFunc("GET /.well-known/openid-configuration", oh.OIDCConfiguration)
	mux.HandleFunc("GET /.well-known/jwks.json", oh.JWKS)
	mux.Handle("GET /oauth/authorize", mm.OptionalAuth(http.HandlerFunc(oh.Authorize)))
	mux.HandleFunc("POST /oauth/token", oh.Token)
	mux.HandleFunc("GET /api/auth/csrf", ah.GetCSRFToken)
	mux.HandleFunc("POST /api/auth/login", ah.Login)
	issuer.Config.Handler = mm.SecurityHeaders(mm.CSRFValidate(mux))
	issuer.StartTLS()
	defer issuer.Close()
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate().Raw}))
	pairing, err := json.Marshal(struct{ Secret, Owner, Everyday, Foreign, Issuer, Certificate, ClientSecret string }{secret, owner.ID, day.ID, foreign.ID, issuerURL, certificate, clientSecret})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pairing.tmp"), pairing, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "pairing.tmp"), filepath.Join(dir, "pairing.json")); err != nil {
		t.Fatal(err)
	}
	waitNotesNativeFile(t, dir, "ready")
	phase := func(name string) {
		t.Helper()
		for i := 0; i < 5; i++ {
			if err := e.DispatchPendingEvents(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		pending, err := s.GetPendingSyncEvents(100)
		if err != nil || len(pending) != 0 {
			t.Fatal("native delivery not acknowledged", name, err, len(pending))
		}
		current, err := s.GetPairedSystemByID(system.ID)
		if err != nil || current.Status != "active" {
			t.Fatal("native connector not healthy", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
		waitNotesNativeFile(t, dir, name+"-checked")
	}
	phase("created")
	if err := s.SetAppAssignment(app.ID, "users", day.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	phase("unassigned")
	if err := s.SetAppAssignment(app.ID, "users", day.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	phase("reassigned")
	if _, err := s.EditUser(day.ID, nil, func(u *store.User) (bool, error) { u.Status = "disabled"; return true, nil }); err != nil {
		t.Fatal(err)
	}
	phase("disabled")
	if _, err := s.EditUser(day.ID, nil, func(u *store.User) (bool, error) { u.Status = "active"; return false, nil }); err != nil {
		t.Fatal(err)
	}
	phase("reactivated")
	if err := s.DeleteUserWithSyncEvents(day.ID, nil); err != nil {
		t.Fatal(err)
	}
	phase("deleted")
	if err := s.SetAppAssignment(app.ID, "users", owner.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	phase("owner-unassigned")
	if err := s.SetAppAssignment(app.ID, "users", owner.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	// A recreated worker must consume the committed scope intent and signing key.
	e = identitysync.NewEngine(s, key)
	phase("owner-reassigned")
	roles, err := s.ListAppRoles(app.ID)
	if err != nil {
		t.Fatal(err)
	}
	var adminRole string
	for _, role := range roles {
		if role.Name == "kynotes.admin" {
			adminRole = role.ID
		}
	}
	if adminRole == "" {
		t.Fatal("native administrator role missing")
	}
	if err := s.SetAppRoleAssignment(app.ID, adminRole, "users", owner.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	// Before dispatch, the receiver still has its local admin grant. Only the
	// actual fresh upstream token ceiling can deny administration at this point.
	if err := os.WriteFile(filepath.Join(dir, "owner-role-limited"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	waitNotesNativeFile(t, dir, "owner-role-limited-checked")
	phase("owner-role-revoked")
	if err := s.SetAppRoleAssignment(app.ID, adminRole, "users", owner.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	phase("owner-role-restored")
}

func waitNotesNativeFile(t *testing.T, dir, name string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("KyNotes fixture timed out waiting for", name)
}
