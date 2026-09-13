package store

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func upstream(t *testing.T, s *Store, connectorID, external, username string) *User {
	t.Helper()
	u := &User{Username: username, DisplayName: strings.ToUpper(username), Email: username + "@up.test", SourceConnectorID: connectorID, ExternalID: external, SourceActive: true}
	if err := s.CreateUpstreamUser(u, nil); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSCIMConnectorTokensAreHashedScopedAndRevocable(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	c, err := s.CreateSCIMConnector("Upstream", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, tok, err := s.IssueSCIMToken(c.ID, "write", nil)
	if err != nil || !strings.HasPrefix(raw, "scim_") || tok.ID == "" {
		t.Fatalf("issue: %q %+v %v", raw, tok, err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM scim_connector_tokens WHERE token_hash=? OR token_hash=?`, raw, strings.TrimPrefix(raw, "scim_")); n != 0 {
		t.Fatal("raw token stored")
	}
	got, scope, err := s.AuthenticateSCIMToken(raw)
	if err != nil || got.ID != c.ID || scope != "write" {
		t.Fatalf("authenticate: %+v %q %v", got, scope, err)
	}
	if list, _ := s.ListSCIMConnectorTokens(c.ID); len(list) != 1 || list[0].LastUsedAt == nil || list[0].RevokedAt != nil {
		t.Fatalf("tokens after use: %+v", list)
	}
	if _, _, err := s.AuthenticateSCIMToken("scim_nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown token: %v", err)
	}
	readRaw, _, err := s.IssueSCIMToken(c.ID, "read", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSCIMToken(c.ID, tok.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthenticateSCIMToken(raw); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked token still works: %v", err)
	}
	if err := s.RevokeSCIMToken(c.ID, tok.ID, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double revoke: %v", err)
	}
	if _, scope, err := s.AuthenticateSCIMToken(readRaw); err != nil || scope != "read" {
		t.Fatalf("read token: %q %v", scope, err)
	}
	if err := s.UpdateSCIMConnector(c.ID, "Upstream", "disabled", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthenticateSCIMToken(readRaw); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token of a disabled connector still works: %v", err)
	}
	if _, _, err := s.IssueSCIMToken("missing", "read", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token for a missing connector: %v", err)
	}
	if _, _, err := s.IssueSCIMToken(c.ID, "admin", nil); err == nil {
		t.Fatal("unknown scope accepted")
	}
}

func TestIssuingATokenRollsBackWithoutItsAuditRow(t *testing.T) {
	s, _ := newStoreWithUser(t, "admin")
	c, _ := s.CreateSCIMConnector("Upstream", nil)
	if _, _, err := s.IssueSCIMToken(c.ID, "write", poisonedAudit(t, s, "admin.scim_token_issued", c.ID)); err == nil {
		t.Fatal("token issued without its audit row")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM scim_connector_tokens`); n != 0 {
		t.Fatal("token row survived the rollback")
	}
}

// An upstream account is keyed by connector and external id, never takes over a local
// account, and is invisible to other connectors.
func TestUpstreamUsersAreKeyedByConnectorAndExternalID(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	a, _ := s.CreateSCIMConnector("A", nil)
	b, _ := s.CreateSCIMConnector("B", nil)
	local := createTestUser(t, s)
	u := upstream(t, s, a.ID, "ext-1", "alice")
	stored, _ := s.GetUserByID(u.ID)
	if !stored.Pending || stored.Status != "active" && stored.Status != "disabled" || stored.Status != "disabled" || stored.PasswordHash != "" || stored.Role != "user" {
		t.Fatalf("upstream account: %+v", stored)
	}
	for _, dup := range []*User{
		{Username: "other", Email: "other@up.test", SourceConnectorID: a.ID, ExternalID: "ext-1", SourceActive: true},
		{Username: "alice", Email: "x@up.test", SourceConnectorID: b.ID, ExternalID: "ext-9", SourceActive: true},
		{Username: "fresh", Email: local.Email, SourceConnectorID: a.ID, ExternalID: "ext-2", SourceActive: true},
		{Username: local.Username, Email: "fresh@up.test", SourceConnectorID: a.ID, ExternalID: "ext-3", SourceActive: true},
	} {
		if err := s.CreateUpstreamUser(dup, nil); !errors.Is(err, ErrUserConflict) {
			t.Fatalf("conflict not reported for %+v: %v", dup, err)
		}
	}
	if err := s.CreateUpstreamUser(&User{Username: "nobody", Email: "n@up.test", SourceConnectorID: a.ID}, nil); err == nil {
		t.Fatal("upstream account without external id accepted")
	}
	if got, _ := s.GetUpstreamUser(b.ID, u.ID); got != nil {
		t.Fatal("another connector could read the account")
	}
	if got, _ := s.GetUpstreamUser(a.ID, local.ID); got != nil {
		t.Fatal("a connector could read a local account")
	}
	upstream(t, s, a.ID, "ext-2", "bob")
	list, total, err := s.ListUpstreamUsers(a.ID, "externalId", "ext-2", 1, 100)
	if err != nil || total != 1 || len(list) != 1 || list[0].Username != "bob" {
		t.Fatalf("filter: %+v %d %v", list, total, err)
	}
	list, total, _ = s.ListUpstreamUsers(a.ID, "", "", 2, 1)
	if total != 2 || len(list) != 1 || list[0].Username != "bob" {
		t.Fatalf("page: %+v %d", list, total)
	}
	if _, _, err := s.ListUpstreamUsers(a.ID, "displayName", "x", 1, 10); err == nil {
		t.Fatal("unsupported attribute accepted")
	}
	if _, total, _ := s.ListUpstreamUsers(a.ID, "userName", local.Username, 1, 10); total != 0 {
		t.Fatal("local account listed for a connector")
	}
}

// The upstream's active flag drives status only within what the local administrator
// allows: a local disable holds until a local administrator lifts it.
func TestUpstreamActiveFlagRespectsTheLocalOverride(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	c, _ := s.CreateSCIMConnector("A", nil)
	u := upstream(t, s, c.ID, "ext-1", "alice")
	raw, _ := s.IssueAccountToken(u.ID, "activation", "manual", time.Hour, nil)
	if _, err := s.RedeemAccountToken(raw, "activation", "hash", nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	seedSession(t, s, u.ID, now.Add(time.Hour), now)
	stored, _ := s.GetUserByID(u.ID)
	if stored.Status != "active" {
		t.Fatalf("after activation: %+v", stored)
	}

	stored.SourceActive = false
	if err := s.UpdateUpstreamUser(stored, nil); err != nil {
		t.Fatal(err)
	}
	stored, _ = s.GetUserByID(u.ID)
	if stored.Status != "active" && stored.Status != "disabled" || stored.Status != "disabled" {
		t.Fatalf("upstream deactivation: %+v", stored)
	}
	if left, _ := s.ListUserSessions(u.ID, time.Hour); len(left) != 0 {
		t.Fatal("session survived upstream deactivation")
	}
	stored.SourceActive = true
	if err := s.UpdateUpstreamUser(stored, nil); err != nil {
		t.Fatal(err)
	}
	if stored, _ = s.GetUserByID(u.ID); stored.Status != "active" {
		t.Fatalf("upstream reactivation: %+v", stored)
	}

	// A local disable is an override the upstream cannot lift.
	stored.LocallyDisabled = true
	stored.ApplySourceState()
	if err := s.UpdateUserWithSyncEvents(stored, true, nil); err != nil {
		t.Fatal(err)
	}
	stored, _ = s.GetUserByID(u.ID)
	stored.SourceActive = true
	stored.DisplayName = "Alice Renamed"
	if err := s.UpdateUpstreamUser(stored, nil); err != nil {
		t.Fatal(err)
	}
	stored, _ = s.GetUserByID(u.ID)
	if stored.Status != "disabled" || !stored.LocallyDisabled || stored.DisplayName != "Alice Renamed" {
		t.Fatalf("upstream undid a local override or lost the profile edit: %+v", stored)
	}
	stored.LocallyDisabled = false
	stored.ApplySourceState()
	if err := s.UpdateUserWithSyncEvents(stored, false, nil); err != nil {
		t.Fatal(err)
	}
	if stored, _ = s.GetUserByID(u.ID); stored.Status != "active" {
		t.Fatalf("lifting the override: %+v", stored)
	}

	// The external id is immutable and local role decisions are not the upstream's.
	stored.ExternalID = "ext-2"
	if err := s.UpdateUpstreamUser(stored, nil); err == nil {
		t.Fatal("external id changed")
	}
	stored, _ = s.GetUserByID(u.ID)
	stored.Role = "admin"
	if err := s.UpdateUpstreamUser(stored, nil); err != nil {
		t.Fatal(err)
	}
	if stored, _ = s.GetUserByID(u.ID); stored.Role != "user" {
		t.Fatal("upstream granted a local role")
	}
}

func TestDeletingAConnectorTransfersOrDisablesItsUsers(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	keep, _ := s.CreateSCIMConnector("Keep", nil)
	drop, _ := s.CreateSCIMConnector("Drop", nil)
	k := upstream(t, s, keep.ID, "k-1", "kept")
	d := upstream(t, s, drop.ID, "d-1", "dropped")
	for _, u := range []*User{k, d} {
		raw, _ := s.IssueAccountToken(u.ID, "activation", "manual", time.Hour, nil)
		if _, err := s.RedeemAccountToken(raw, "activation", "hash", nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.IssueSCIMToken(keep.ID, "write", nil); err != nil {
		t.Fatal(err)
	}

	n, err := s.DeleteSCIMConnector(keep.ID, false, nil)
	if err != nil || n != 1 {
		t.Fatalf("transfer: %d %v", n, err)
	}
	after, _ := s.GetUserByID(k.ID)
	if after.SourceConnectorID != "" || after.ExternalID != "" || after.Status != "active" {
		t.Fatalf("transferred account: %+v", after)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM scim_connector_tokens`); n != 0 {
		t.Fatal("tokens outlived the connector")
	}

	n, err = s.DeleteSCIMConnector(drop.ID, true, nil)
	if err != nil || n != 1 {
		t.Fatalf("deactivate: %d %v", n, err)
	}
	after, _ = s.GetUserByID(d.ID)
	if after.SourceConnectorID != "" || after.Status != "disabled" {
		t.Fatalf("deactivated account: %+v", after)
	}
	if _, err := s.DeleteSCIMConnector(drop.ID, true, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete: %v", err)
	}
}
