package store

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeMailboxAddress(t *testing.T) {
	for in, want := range map[string]string{
		" Alice.Smith@Example.COM ":            "alice.smith@example.com",
		"bob@Bücher.example":                   "bob@xn--bcher-kva.example",
		"bob@xn--bcher-kva.example":            "bob@xn--bcher-kva.example",
		"a_b-c@mail.example.com":               "a_b-c@mail.example.com",
		strings.Repeat("a", 64) + "@x.example": strings.Repeat("a", 64) + "@x.example",
	} {
		if got, err := NormalizeMailboxAddress(in); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "alice", "@example.com", "alice@", "alice+tag@example.com", ".alice@example.com",
		"alice.@example.com", "al..ice@example.com", "a@b@example.com", "élise@example.com",
		"alice smith@example.com", "alice@localhost", "alice@example.com:25", "alice@*.example.com",
		strings.Repeat("a", 65) + "@example.com", "a@" + strings.Repeat("b", 600) + ".com",
	} {
		if got, err := NormalizeMailboxAddress(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		} else if strings.Contains(err.Error(), in) && in != "" {
			t.Errorf("%q: the refusal repeats the address: %v", in, err)
		}
	}
}

// mailboxFixture: a store with suite domains, a household org and a member in it.
func mailboxFixture(t *testing.T, domains ...string) (*Store, *OrgStore, *User) {
	t.Helper()
	s, cleanup := setupTestStore(t)
	t.Cleanup(cleanup)
	if len(domains) > 0 {
		if _, _, err := s.SetSuiteEmailDomains(domains, nil); err != nil {
			t.Fatal(err)
		}
	}
	org := testOrg(t, s, "household")
	return s, org, testOrgUser(t, org, "user")
}

func mailboxOf(t *testing.T, s *Store, id string) string {
	t.Helper()
	var v *string
	if err := s.db.QueryRow(`SELECT mailbox_address FROM users WHERE id=?`, id).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v == nil {
		return "<null>"
	}
	return *v
}

func TestMailboxAddressIsWriteOnceUnlessOverwritten(t *testing.T) {
	s, org, u := mailboxFixture(t, "example.com", "other.example")
	audit := &AuditEvent{ID: uuid.NewString(), Action: "admin.user_mailbox_address_changed", Outcome: "success", TargetID: u.ID, TargetType: "user"}
	got, changed, err := org.SetMailboxAddress(u.ID, "Alice@Example.com", false, audit)
	if err != nil || !changed || got.MailboxAddress != "alice@example.com" {
		t.Fatalf("first set: %+v %v %v", got, changed, err)
	}
	if audit.DetailsJSON != `{"domain":"example.com","oldDomain":""}` {
		t.Errorf("audit details %s", audit.DetailsJSON)
	}
	// A retry with the same value (any case) changes nothing and writes no audit row.
	if _, changed, err := org.SetMailboxAddress(u.ID, "ALICE@example.com", false, &AuditEvent{ID: uuid.NewString(), Action: "retry", Outcome: "success"}); err != nil || changed {
		t.Errorf("same value again: %v %v", changed, err)
	}
	if _, _, err := org.SetMailboxAddress(u.ID, "alice@other.example", false, nil); !errors.Is(err, ErrMailboxAddressSet) {
		t.Errorf("a second value without overwrite: %v", err)
	}
	if v := mailboxOf(t, s, u.ID); v != "alice@example.com" {
		t.Errorf("stored %q after the refused change", v)
	}
	staff := &AuditEvent{ID: uuid.NewString(), Action: "admin.user_mailbox_address_changed", Outcome: "success", TargetID: u.ID, TargetType: "user"}
	if _, changed, err := org.SetMailboxAddress(u.ID, "alice@other.example", true, staff); err != nil || !changed {
		t.Fatalf("staff change: %v %v", changed, err)
	}
	if staff.DetailsJSON != `{"domain":"other.example","oldDomain":"example.com"}` {
		t.Errorf("staff audit details %s", staff.DetailsJSON)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action IN ('admin.user_mailbox_address_changed','retry')`).Scan(&n); err != nil || n != 2 {
		t.Errorf("%d audit rows, want the set and the staff change: %v", n, err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE details_json LIKE '%alice%'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d audit rows name the local part: %v", n, err)
	}
	if got, err := org.GetUserByID(u.ID); err != nil || got.MailboxAddress != "alice@other.example" || got.Email != u.Email {
		t.Errorf("read back %+v %v: the sign-in email must not move", got, err)
	}
	// An empty value is refused, so staff cannot clear it.
	if _, _, err := org.SetMailboxAddress(u.ID, "", true, nil); err == nil {
		t.Error("cleared")
	}
}

func TestMailboxAddressMustBeOnASuiteDomain(t *testing.T) {
	s, org, u := mailboxFixture(t)
	if _, _, err := org.SetMailboxAddress(u.ID, "alice@example.com", true, nil); !errors.Is(err, ErrMailboxDomain) {
		t.Errorf("no suite domains: %v", err)
	}
	if _, _, err := s.SetSuiteEmailDomains([]string{"example.com"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"alice@example.org", "alice@sub.example.com", "alice@example.com.evil.example"} {
		if _, _, err := org.SetMailboxAddress(u.ID, addr, true, nil); !errors.Is(err, ErrMailboxDomain) {
			t.Errorf("%s: %v", addr, err)
		}
	}
	if v := mailboxOf(t, s, u.ID); v != "<null>" {
		t.Errorf("stored %q", v)
	}
}

func TestMailboxAddressIsUniqueAcrossTheInstall(t *testing.T) {
	s, a, alice := mailboxFixture(t, "bücher.example", "example.com")
	b := testOrg(t, s, "person")
	bob := testOrgUser(t, b, "user")
	if _, _, err := a.SetMailboxAddress(alice.ID, "post@Bücher.example", false, nil); err != nil {
		t.Fatal(err)
	}
	// Case and the Unicode form of the domain are the same address.
	for _, addr := range []string{"POST@xn--bcher-kva.example", "post@BÜCHER.example"} {
		if _, _, err := b.SetMailboxAddress(bob.ID, addr, false, nil); !errors.Is(err, ErrMailboxAddressTaken) {
			t.Errorf("%s in another org: %v", addr, err)
		}
	}
	// Another account's sign-in email is taken too, in either direction.
	carol := testOrgUser(t, b, "user")
	if _, err := b.EditUser(carol.ID, nil, func(u *User) (bool, error) { u.Email = "Carol@Example.com"; return false, nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.SetMailboxAddress(bob.ID, "carol@example.com", false, nil); !errors.Is(err, ErrMailboxAddressTaken) {
		t.Errorf("a mailbox address equal to another account's sign-in email: %v", err)
	}
	if _, _, err := b.SetMailboxAddress(bob.ID, "bob@example.com", false, nil); err != nil {
		t.Fatal(err)
	}
	dup := &User{ID: uuid.NewString(), Username: "squatter", DisplayName: "s", Email: "Bob@Example.com", Role: "user", Status: "active"}
	if err := a.CreateUserWithSyncEvents(dup, nil); !errors.Is(err, ErrUserConflict) {
		t.Errorf("a new sign-in email equal to a mailbox address: %v", err)
	}
	if err := a.CreateUser(dup); err == nil {
		t.Error("CreateUser with a sign-in email equal to a mailbox address")
	}
	if _, err := a.EditUser(alice.ID, nil, func(u *User) (bool, error) { u.Email = "bob@example.com"; return false, nil }); err == nil {
		t.Error("a sign-in email changed to another account's mailbox address")
	}
	// One's own sign-in email may also be one's mailbox address.
	dave := testOrgUser(t, b, "user")
	if _, err := b.EditUser(dave.ID, nil, func(u *User) (bool, error) { u.Email = "dave@example.com"; return false, nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.SetMailboxAddress(dave.ID, "dave@example.com", false, nil); err != nil {
		t.Errorf("own sign-in email as mailbox: %v", err)
	}
}

// Writers race for one address; exactly one wins on either backend.
func TestMailboxAddressRace(t *testing.T) {
	s, org, first := mailboxFixture(t, "example.com")
	users := []*User{first}
	for range 7 {
		users = append(users, testOrgUser(t, org, "user"))
	}
	var wg sync.WaitGroup
	errs := make([]error, len(users))
	for i, u := range users {
		wg.Go(func() { _, _, errs[i] = org.SetMailboxAddress(u.ID, "shared@example.com", false, nil) })
	}
	// A new account claiming the same sign-in email races them too.
	var createErr error
	wg.Go(func() {
		createErr = org.CreateUserWithSyncEvents(&User{ID: uuid.NewString(), Username: "racer", DisplayName: "r", Email: "shared@example.com", Role: "user", Status: "active"}, nil)
	})
	wg.Wait()
	won := 0
	for _, err := range append(errs, createErr) {
		switch {
		case err == nil:
			won++
		case errors.Is(err, ErrMailboxAddressTaken), errors.Is(err, ErrUserConflict):
		default:
			t.Errorf("unexpected: %v", err)
		}
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE mailbox_address='shared@example.com' OR email='shared@example.com'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if won != 1 || n != 1 {
		t.Errorf("%d writers won and %d accounts hold the address, want one", won, n)
	}
}

func TestMailboxAddressRefusesAnotherOrgsUser(t *testing.T) {
	s, a, _ := mailboxFixture(t, "example.com")
	b := testOrg(t, s, "household")
	victim := testOrgUser(t, b, "user")
	_, _, cross := a.SetMailboxAddress(victim.ID, "x@example.com", true, nil)
	_, _, missing := a.SetMailboxAddress(uuid.NewString(), "x@example.com", true, nil)
	if !errors.Is(cross, ErrNotFound) || !errors.Is(missing, ErrNotFound) {
		t.Errorf("another org's user %v, a missing one %v: want the same ErrNotFound", cross, missing)
	}
	if v := mailboxOf(t, s, victim.ID); v != "<null>" {
		t.Errorf("victim's mailbox is %q", v)
	}
}

// Only person and household accounts hold one, on every write path: a single-tenant
// install (the default org) and staff never can.
func TestMailboxAddressIsForCustomerAccountsOnly(t *testing.T) {
	s, member, u := mailboxFixture(t, "example.com")
	for name, o := range map[string]*OrgStore{"default": s.DefaultOrg(), "staff": testOrg(t, s, "staff")} {
		x := testOrgUser(t, o, "user")
		if _, _, err := o.SetMailboxAddress(x.ID, "x-"+name+"@example.com", true, nil); !errors.Is(err, ErrMailboxCustomerOnly) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := s.db.Exec(`UPDATE users SET mailbox_address='raw-`+name+`@example.com' WHERE id=?`, x.ID); err == nil || !strings.Contains(err.Error(), msgMailboxCustomerOnly) {
			t.Errorf("%s raw update: %v", name, err)
		}
		if ok, err := o.MailboxEligible(); err != nil || ok {
			t.Errorf("%s eligible: %v %v", name, ok, err)
		}
	}
	if ok, err := member.MailboxEligible(); err != nil || !ok {
		t.Errorf("household eligible: %v %v", ok, err)
	}
	if _, err := s.db.Exec(`INSERT INTO users(org_id,id,username,display_name,email,password_hash,role,status,mailbox_address) VALUES(?,'raw','raw','raw','raw@test.invalid','','user','active','raw@example.com')`, DefaultOrgID); err == nil {
		t.Error("raw insert of a default-org account with a mailbox address")
	}
	// Stored lowercase on every path.
	if _, err := s.db.Exec(`UPDATE users SET mailbox_address='Upper@example.com' WHERE id=?`, u.ID); err == nil {
		t.Error("raw update with an uppercase address")
	}
}

func TestRemovingAUsedSuiteDomainIsRefused(t *testing.T) {
	s, org, u := mailboxFixture(t, "example.com", "other.example", "spare.example")
	if _, _, err := org.SetMailboxAddress(u.ID, "alice@example.com", false, nil); err != nil {
		t.Fatal(err)
	}
	var inUse *DomainInUseError
	_, _, err := s.SetSuiteEmailDomains([]string{"other.example"}, &AuditEvent{ID: uuid.NewString(), Action: "admin.suite_email_domains_changed", Outcome: "success"})
	if !errors.As(err, &inUse) || inUse.Domain != "example.com" || inUse.Count != 1 {
		t.Fatalf("removing a used domain: %v", err)
	}
	if got, _ := s.SuiteEmailDomains(); len(got) != 3 {
		t.Errorf("list changed to %v", got)
	}
	// An unused domain still goes.
	if _, changed, err := s.SetSuiteEmailDomains([]string{"example.com", "other.example"}, nil); err != nil || !changed {
		t.Errorf("removing an unused domain: %v %v", changed, err)
	}
	// Once staff move the address, its old domain can go.
	if _, _, err := org.SetMailboxAddress(u.ID, "alice@other.example", true, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetSuiteEmailDomains([]string{"other.example"}, nil); err != nil {
		t.Errorf("after the move: %v", err)
	}
}

func TestMailboxAddressPayloadEntry(t *testing.T) {
	u := &User{ID: "u1", Username: "a@gmail.example", Email: "a@gmail.example", Role: "user", Status: "active"}
	plain, err := scimUserPayload(u, true)
	if err != nil || strings.Contains(string(plain), MailboxEmailType) {
		t.Fatalf("no mailbox address: %s %v", plain, err)
	}
	u.MailboxAddress = "a@example.com"
	b, err := scimUserPayload(u, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := `"emails":[{"value":"a@gmail.example","type":"work","primary":true},{"value":"a@example.com","type":"mailbox"}]`; !strings.Contains(string(b), want) {
		t.Errorf("payload %s, want %s", b, want)
	}
}
