package store

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func seedClient(t *testing.T, s *Store, id string) *OAuthClient {
	t.Helper()
	c := &OAuthClient{ID: id, ClientName: id, ClientType: "public", RedirectURIsJSON: `["https://app/cb"]`, AllowedScopesJSON: `["openid"]`, PostLogoutRedirectURIsJSON: `["https://app/bye"]`, Enabled: true}
	if err := s.CreateOAuthClient(c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOAuthClientPersistsPostLogoutRedirectURIs(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	seedClient(t, s, "app")

	got, err := s.GetOAuthClientByID("app")
	if err != nil || got == nil || got.PostLogoutRedirectURIsJSON != `["https://app/bye"]` {
		t.Fatalf("get: %+v %v", got, err)
	}
	got.PostLogoutRedirectURIsJSON = `["https://app/gone"]`
	if err := s.UpdateOAuthClient(got); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListOAuthClients()
	if err != nil || len(list) != 1 || list[0].PostLogoutRedirectURIsJSON != `["https://app/gone"]` {
		t.Fatalf("list: %+v %v", list, err)
	}
}

func TestClientSessionSIDIsStablePerClientAndSession(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	sid1 := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	seedClient(t, s, "app-a")
	seedClient(t, s, "app-b")

	a, err := s.EnsureClientSession("app-a", sid1, u.ID)
	if err != nil || len(a) < 32 {
		t.Fatalf("EnsureClientSession: %q %v", a, err)
	}
	again, err := s.EnsureClientSession("app-a", sid1, u.ID)
	if err != nil || again != a {
		t.Fatalf("same client and session must reuse the sid: %q vs %q (%v)", again, a, err)
	}
	b, err := s.EnsureClientSession("app-b", sid1, u.ID)
	if err != nil || b == a {
		t.Fatalf("another client must not share the sid: %q (%v)", b, err)
	}

	cs, err := s.GetClientSession(a)
	if err != nil || cs == nil || cs.ClientID != "app-a" || cs.SessionID != sid1 || cs.UserID != u.ID {
		t.Fatalf("GetClientSession: %+v %v", cs, err)
	}
	if cs, err := s.GetClientSession(uuid.NewString()); err != nil || cs != nil {
		t.Fatalf("unknown sid: %+v %v", cs, err)
	}

	if err := s.RevokeSession(u.ID, sid1, nil); err != nil {
		t.Fatal(err)
	}
	if cs, err := s.GetClientSession(a); err != nil || cs != nil {
		t.Fatalf("sid must not outlive its session: %+v %v", cs, err)
	}
}

func TestClientSessionRequiresALiveSession(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	seedClient(t, s, "app")
	if sid, err := s.EnsureClientSession("app", uuid.NewString(), u.ID); err == nil {
		t.Fatalf("minted sid %q for a session that does not exist", sid)
	}
}
