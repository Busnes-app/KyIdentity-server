package store

import (
	"errors"
	"testing"
)

// Guards inbound SCIM authentication: a disabled connector's tokens stop working at once
// and work again on re-enable; an empty bearer is ErrNotFound; issuing for an unknown
// connector or a bad scope is refused, and an audit failure keeps the connector active.
func TestSCIMConnectorDisableBlocksTokens(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	c, err := s.CreateSCIMConnector("  HR  ", nil)
	if err != nil || c.Name != "HR" {
		t.Fatal(c, err)
	}
	if _, err := s.CreateSCIMConnector("   ", nil); err == nil {
		t.Fatal("blank connector name accepted")
	}
	raw, _, err := s.IssueSCIMToken(c.ID, "write", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.IssueSCIMToken(c.ID, "admin", nil); err == nil {
		t.Fatal("unknown scope issued")
	}
	if _, _, err := s.IssueSCIMToken("missing", "read", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("token issued for unknown connector", err)
	}
	if _, _, err := s.AuthenticateSCIMToken("scim_"); !errors.Is(err, ErrNotFound) {
		t.Fatal("empty bearer", err)
	}
	if err := s.UpdateSCIMConnector(c.ID, "HR", "paused", nil); err == nil {
		t.Fatal("unknown status accepted")
	}
	if err := s.UpdateSCIMConnector(c.ID, " ", "disabled", nil); err == nil {
		t.Fatal("blank name accepted")
	}
	if err := s.UpdateSCIMConnector("missing", "HR", "disabled", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown connector updated", err)
	}
	if err := s.UpdateSCIMConnector(c.ID, "HR", "disabled", poisonedAudit(t, s, "admin.scim_connector_updated", c.ID)); err == nil {
		t.Fatal("update ignored audit failure")
	}
	if _, _, err := s.AuthenticateSCIMToken(raw); err != nil {
		t.Fatal("failed disable blocked the token", err)
	}
	if err := s.UpdateSCIMConnector(c.ID, "HR", "disabled", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthenticateSCIMToken(raw); !errors.Is(err, ErrNotFound) {
		t.Fatal("disabled connector authenticated", err)
	}
	if err := s.UpdateSCIMConnector(c.ID, "HR", "active", nil); err != nil {
		t.Fatal(err)
	}
	if got, scope, err := s.AuthenticateSCIMToken(raw); err != nil || got.ID != c.ID || scope != "write" {
		t.Fatal("re-enabled connector refused", err)
	}
	if err := s.RevokeSCIMToken(c.ID, "missing", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown token revoked", err)
	}
}

// Guards the SCIM user listing filters: each attribute is an exact (case-insensitive for
// names and email) match scoped to the connector; unknown attributes are refused and
// paging is clamped.
func TestListUpstreamUsersFiltersAndPaging(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	a, _ := s.CreateSCIMConnector("A", nil)
	b, _ := s.CreateSCIMConnector("B", nil)
	alice := upstream(t, s, a.ID, "ext-a", "alice")
	upstream(t, s, a.ID, "ext-b", "bob")
	other := upstream(t, s, b.ID, "ext-o", "other")
	createTestUserNamed(t, s, "local")
	for _, f := range []struct{ attr, value string }{{"userName", "ALICE"}, {"externalId", "ext-a"}, {"emails.value", "Alice@UP.test"}, {"emails", "alice@up.test"}, {"id", alice.ID}} {
		got, total, err := s.ListUpstreamUsers(a.ID, f.attr, f.value, 1, 10)
		if err != nil || total != 1 || len(got) != 1 || got[0].ID != alice.ID {
			t.Fatalf("%s=%s: %+v %d %v", f.attr, f.value, got, total, err)
		}
	}
	if got, total, _ := s.ListUpstreamUsers(a.ID, "id", other.ID, 1, 10); total != 0 || len(got) != 0 {
		t.Fatal("listing crossed connectors", got)
	}
	if _, _, err := s.ListUpstreamUsers(a.ID, "password", "x", 1, 10); err == nil {
		t.Fatal("unsupported filter accepted")
	}
	if got, total, _ := s.ListUpstreamUsers(a.ID, "", "", 0, 1000); total != 2 || len(got) != 2 {
		t.Fatalf("unfiltered = %d of %d", len(got), total)
	}
	if got, total, _ := s.ListUpstreamUsers(a.ID, "", "", 2, 10); total != 2 || len(got) != 1 {
		t.Fatalf("second page = %d of %d", len(got), total)
	}
	if got, total, _ := s.ListUpstreamUsers(a.ID, "", "", 1, -5); total != 2 || len(got) != 0 {
		t.Fatalf("negative count = %d of %d", len(got), total)
	}
}
