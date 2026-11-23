package store

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// One customer kind for every paid plan (tenancy design, "Plans and orgs" P1).
func TestCustomerKind(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	insert := func(id, kind string) string {
		return `INSERT INTO orgs(id,name,kind,status,home_region,created_at,updated_at) VALUES('` + id + `','n','` + kind + `','active','local',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`
	}
	for _, kind := range []string{"person", "household", "business", "enterprise", "Customer", ""} {
		refused(t, s, "kind", insert("org-"+kind, kind))
	}
	tenancyExec(t, s, insert("org-customer", customerKind), insert("org-staff", "staff"))
}

// An install from before customer_kind, built by the real migrations 1..15 as they
// shipped (TestShippedMigrationsUnchanged holds them), with a household org. Version 16
// moves every row and object to customer and leaves a fresh install's schema.
func TestUpgradeToCustomerKind(t *testing.T) {
	saved := migrations
	t.Cleanup(func() { migrations = saved })
	migrations = saved[:slices.IndexFunc(saved, func(m migration) bool { return m.name == "customer_kind" })]
	path := filepath.Join(t.TempDir(), "previous.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	tenancyExec(t, s, `INSERT INTO orgs(id,name,kind,status,home_region,created_at,updated_at) VALUES('org-old','Old','household','active','local',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	migrations = saved
	if s, err = New(path); err != nil {
		t.Fatal("upgrade:", err)
	}
	defer s.Close()
	var kind string
	if err := s.db.QueryRow(`SELECT kind FROM orgs WHERE id='org-old'`).Scan(&kind); err != nil || kind != customerKind {
		t.Errorf("old household org is %q %v", kind, err)
	}
	refused(t, s, "kind", `INSERT INTO orgs(id,name,kind,status,home_region,created_at,updated_at) VALUES('org-h','n','household','active','local',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`)
	fresh, cleanup := setupTestStore(t)
	defer cleanup()
	if a, b := schemaText(t, s), schemaText(t, fresh); a != b || strings.Contains(a, "household") {
		t.Errorf("upgraded schema:\n%s\nfresh:\n%s", a, b)
	}
	if _, _, err := s.SetSuiteEmailDomains([]string{"example.com"}, nil); err != nil {
		t.Fatal(err)
	}
	org := testOrg(t, s, customerKind)
	u := testOrgUser(t, org, "user")
	// The mailbox triggers take a customer account.
	if _, _, err := org.SetMailboxAddress(u.ID, "kim@example.com", true, nil); err != nil {
		t.Fatal("mailbox address after the upgrade:", err)
	}
	// So does org_erasures_holder: the holder of a customer org alone asks, immediate.
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE orgs SET account_holder_user_id=? WHERE id=?`, u.ID, org.org); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO org_erasures(org_id,holder_user_id,immediate,requested_at) VALUES(?,?,TRUE,?)`, org.org, u.ID, time.Now().UTC()); err != nil {
		t.Fatal("erasure request after the upgrade:", err)
	}
}
