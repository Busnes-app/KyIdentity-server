package sync

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/adpass"
	"github.com/Busnes-app/kyidentity-server/internal/ldaptest"
	"github.com/Busnes-app/kyidentity-server/internal/netguard"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

const (
	adOU     = "OU=KyIdentity,DC=kyws,DC=test"
	adBindDN = "CN=kyidentity-sync,CN=Users,DC=kyws,DC=test"
)

func adFixture(t *testing.T) (*Engine, *store.Store, *store.User, *ldaptest.Server, *store.PairedSystem) {
	t.Helper()
	netguard.AllowLoopback = true
	t.Cleanup(func() { netguard.AllowLoopback = false })
	e, s, u, cleanup := setupTestSyncEngine(t)
	t.Cleanup(cleanup)
	dc := ldaptest.Start(t)
	dc.Users[strings.ToLower(adBindDN)] = "bind-secret"
	dc.Put(adOU, map[string][]string{"objectClass": {"organizationalUnit"}})
	dc.Put("CN=outsider,OU=Outside,DC=kyws,DC=test", map[string][]string{"sAMAccountName": {"outsider"}, "userAccountControl": {"512"}})
	dc.Put("CN=squatter,"+adOU, map[string][]string{"sAMAccountName": {"squatter"}, "userAccountControl": {"512"}})
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "dc", SystemType: "active_directory", CallbackURL: dc.URL, BearerToken: "bind-secret",
		ActiveDirectory: &ADSettings{BindDN: adBindDN, BaseDN: adOU, CAPEM: dc.CAPEM}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e, s, u, dc, sys
}

func adUser(t *testing.T, dc *ldaptest.Server, systemID, userID string) *ldaptest.Entry {
	t.Helper()
	found := dc.Find("adminDescription", adpass.Marker(systemID, "user", userID))
	if len(found) != 1 {
		t.Fatalf("want one directory account for %s, have %d", userID, len(found))
	}
	return found[0]
}

func first(e *ldaptest.Entry, attr string) string {
	if v := e.Attrs[attr]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func TestADConnectorFollowsAssignments(t *testing.T) {
	e, s, _, dc, sys := adFixture(t)
	u := &store.User{ID: uuid.NewString(), Username: "alice", DisplayName: "Alice", Email: "alice@example.com", PasswordHash: "x", Role: "user", Status: "active"}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := e.TestSystem(context.Background(), sys); err != nil {
		t.Fatal("connection test:", err)
	}
	outsiderBefore := dc.Get("CN=outsider,OU=Outside,DC=kyws,DC=test")
	app := appRecordFor(t, s, sys.ID)
	group := &store.Group{ID: uuid.NewString(), Name: "pc-users"}
	if err := s.CreateGroup(group, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership(group.ID, u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(app.ID, "groups", group.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	acct := adUser(t, dc, sys.ID, u.ID)
	if acct.DN != "CN=alice,"+adOU || first(acct, "sAMAccountName") != "alice" || first(acct, "userPrincipalName") != "alice@kyws.test" ||
		first(acct, "userAccountControl") != "512" || first(acct, "mail") != u.Email || first(acct, "unicodePwd") == "" {
		t.Fatalf("account written as %+v", acct.Attrs)
	}
	grp := dc.Find("adminDescription", adpass.Marker(sys.ID, "group", group.ID))
	if len(grp) != 1 || len(grp[0].Attrs["member"]) != 1 || grp[0].Attrs["member"][0] != acct.DN {
		t.Fatalf("group written as %+v", grp)
	}

	// Disabling locally disables in AD; nothing is deleted.
	if _, err := s.EditUser(u.ID, nil, func(x *store.User) (bool, error) { x.Status = "disabled"; return true, nil }); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if got := adUser(t, dc, sys.ID, u.ID); first(got, "userAccountControl") != "514" {
		t.Fatal("disabled user still enabled in AD", got.Attrs)
	}
	if _, err := s.EditUser(u.ID, nil, func(x *store.User) (bool, error) { x.Status = "active"; return false, nil }); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if got := adUser(t, dc, sys.ID, u.ID); first(got, "userAccountControl") != "512" {
		t.Fatal("re-enabled user still disabled", got.Attrs)
	}
	// Losing the group empties it and disables the account; both are kept.
	if err := s.SetAppAssignment(app.ID, "groups", group.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if got := adUser(t, dc, sys.ID, u.ID); first(got, "userAccountControl") != "514" {
		t.Fatal("unassigned user still enabled", got.Attrs)
	}
	if grp := dc.Find("adminDescription", adpass.Marker(sys.ID, "group", group.ID)); len(grp) != 1 || len(grp[0].Attrs["member"]) != 0 {
		t.Fatalf("unassigned group not emptied: %+v", grp)
	}
	if after := dc.Get("CN=outsider,OU=Outside,DC=kyws,DC=test"); len(after.Attrs) != len(outsiderBefore.Attrs) || first(after, "userAccountControl") != "512" {
		t.Fatal("object outside the OU changed", after.Attrs)
	}
}

func TestADConnectorLeavesForeignObjectsAlone(t *testing.T) {
	e, s, _, dc, sys := adFixture(t)
	squatter := &store.User{ID: uuid.NewString(), Username: "squatter", DisplayName: "S", Email: "s@example.com", PasswordHash: "x", Role: "user", Status: "active"}
	if err := s.CreateUser(squatter); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(appRecordFor(t, s, sys.ID).ID, "users", squatter.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	foreign := dc.Get("CN=squatter," + adOU)
	if len(foreign.Attrs["adminDescription"]) != 0 || len(foreign.Attrs) != 2 {
		t.Fatal("foreign object was changed", foreign.Attrs)
	}
	failing, err := s.GetPendingSyncEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	reported := false
	for _, f := range failing {
		reported = reported || f.LastError == errADConflict.Error()
	}
	if !reported {
		t.Fatalf("conflict not reported to the admin: %+v", failing)
	}
	// A disable of an account the directory never had creates nothing.
	if err := s.SetAppAssignment(appRecordFor(t, s, sys.ID).ID, "users", squatter.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if dc.Get("CN=squatter," + adOU).Attrs["userAccountControl"][0] != "512" {
		t.Fatal("removal reached a foreign object")
	}
}

func TestADConnectorPinsTheDirectoryCertificate(t *testing.T) {
	e, s, _, dc, sys := adFixture(t)
	_, otherCA := ldaptest.Selfsigned(t)
	settings := &ADSettings{BindDN: adBindDN, BaseDN: adOU, CAPEM: otherCA}
	if err := e.ConfigureAD(sys, dc.URL, "", settings, nil); err != nil {
		t.Fatal(err)
	}
	sys, _ = s.GetPairedSystemByID(sys.ID)
	if err := e.TestSystem(context.Background(), sys); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatal("connection succeeded against a certificate the pin does not name:", err)
	}
	if msg := deliveryError(e.TestSystem(context.Background(), sys)); strings.Contains(msg, "bind-secret") || !strings.Contains(msg, "TLS") {
		t.Fatal("delivery error text:", msg)
	}
	settings.CAPEM = dc.CAPEM
	if err := e.ConfigureAD(sys, dc.URL, "wrong-password", settings, nil); err != nil {
		t.Fatal(err)
	}
	sys, _ = s.GetPairedSystemByID(sys.ID)
	if err := e.TestSystem(context.Background(), sys); err == nil {
		t.Fatal("bind with a wrong password succeeded")
	}
	if err := e.ConfigureAD(sys, dc.URL, "bind-secret", settings, nil); err != nil {
		t.Fatal(err)
	}
	sys, _ = s.GetPairedSystemByID(sys.ID)
	if err := e.TestSystem(context.Background(), sys); err != nil {
		t.Fatal("replaced bind password not used:", err)
	}
}

func TestADSettingsValidation(t *testing.T) {
	e, _, _, dc, _ := adFixture(t)
	good := func() *CreateSystemRequest {
		return &CreateSystemRequest{SystemType: "active_directory", CallbackURL: dc.URL, BearerToken: "pw",
			ActiveDirectory: &ADSettings{BindDN: adBindDN, BaseDN: adOU, CAPEM: dc.CAPEM}}
	}
	for name, mutate := range map[string]func(*CreateSystemRequest){
		"plain ldap":       func(r *CreateSystemRequest) { r.CallbackURL = strings.Replace(dc.URL, "ldaps://", "ldap://", 1) },
		"path":             func(r *CreateSystemRequest) { r.CallbackURL = dc.URL + "/x" },
		"no CA":            func(r *CreateSystemRequest) { r.ActiveDirectory.CAPEM = "" },
		"OU without DC":    func(r *CreateSystemRequest) { r.ActiveDirectory.BaseDN = "OU=KyIdentity" },
		"bad bind DN":      func(r *CreateSystemRequest) { r.ActiveDirectory.BindDN = "not a dn" },
		"no bind password": func(r *CreateSystemRequest) { r.BearerToken = "" },
		"bad agent key":    func(r *CreateSystemRequest) { r.ActiveDirectory.AgentPublicKey = "x25519:AAAA" },
		"long lifetime":    func(r *CreateSystemRequest) { r.ActiveDirectory.PasswordTTLMinutes = 1441 },
		"short lifetime":   func(r *CreateSystemRequest) { r.ActiveDirectory.PasswordTTLMinutes = 9 },
		"no settings":      func(r *CreateSystemRequest) { r.ActiveDirectory = nil },
	} {
		req := good()
		mutate(req)
		if _, _, err := e.CreateSystem(req, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	netguard.AllowLoopback = false
	if _, _, err := e.CreateSystem(good(), nil); err == nil {
		t.Error("loopback directory accepted without the test override")
	}
	for _, bad := range []string{"", "a/b", "x@y", "with space ", "twentyonecharacters12"} {
		if validSAM(bad, 20) {
			t.Errorf("validSAM(%q)", bad)
		}
	}
	if adDomain("OU=a,OU=b,DC=Example,DC=org") != "Example.org" {
		t.Error("domain from OU")
	}
}

// A password reset while the account is disabled must reach the directory before the
// account is enabled again, or the replaced password signs in on re-enable.
func TestADEnableWaitsForAResetMadeWhileDisabled(t *testing.T) {
	netguard.AllowLoopback = true
	t.Cleanup(func() { netguard.AllowLoopback = false })
	e, s, _, cleanup := setupTestSyncEngine(t)
	t.Cleanup(cleanup)
	dc := ldaptest.Start(t)
	dc.Users[strings.ToLower(adBindDN)] = "bind-secret"
	dc.Put(adOU, map[string][]string{"objectClass": {"organizationalUnit"}})
	agentKey, _ := adpass.GenerateKey()
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "dc", SystemType: "active_directory", CallbackURL: dc.URL, BearerToken: "bind-secret",
		ActiveDirectory: &ADSettings{BindDN: adBindDN, BaseDN: adOU, CAPEM: dc.CAPEM, AgentPublicKey: adpass.EncodePublicKey(agentKey.PublicKey()), PasswordTTLMinutes: 60}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{ID: uuid.NewString(), Username: "bob", DisplayName: "Bob", Email: "bob@example.com", PasswordHash: "first-hash", Role: "user", Status: "active"}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(appRecordFor(t, s, sys.ID).ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	apply := func() {
		t.Helper()
		pending, err := s.PendingADPasswords(sys.ID, time.Now(), 10)
		if err != nil || len(pending) != 1 {
			t.Fatal(pending, err)
		}
		if err := s.FinishADPassword(sys.ID, u.ID, pending[0].Seq, "applied", ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.QueueDirectoryPassword(e.DirectoryKeys(), u.ID, "first-hash", []byte("First-Pass-1"), nil); err != nil {
		t.Fatal(err)
	}
	apply()
	edit := func(f func(*store.User)) {
		t.Helper()
		if _, err := s.EditUser(u.ID, nil, func(x *store.User) (bool, error) { f(x); return true, nil }); err != nil {
			t.Fatal(err)
		}
	}
	edit(func(x *store.User) { x.Status = "disabled" })
	drain(t, e)
	edit(func(x *store.User) { x.PasswordHash = "reset-hash" })
	if n, err := s.QueueDirectoryPassword(e.DirectoryKeys(), u.ID, "reset-hash", []byte("Reset-Pass-2"), nil); err != nil || n != 1 {
		t.Fatal("reset not queued for the disabled account", n, err)
	}
	edit(func(x *store.User) { x.Status = "active" })
	drain(t, e)
	if got := adUser(t, dc, sys.ID, u.ID); first(got, "userAccountControl") != "514" {
		t.Fatal("enabled while the directory still holds the replaced password", got.Attrs)
	}
	waiting := false
	left, _ := s.GetPendingSyncEvents(20)
	for _, ev := range left {
		waiting = waiting || ev.LastError == store.ADEnableWaitsForPassword
	}
	if !waiting {
		t.Fatal("the held enable does not say why", left)
	}
	apply()
	drain(t, e)
	if got := adUser(t, dc, sys.ID, u.ID); first(got, "userAccountControl") != "512" {
		t.Fatal("not enabled once the reset was applied", got.Attrs)
	}
}
