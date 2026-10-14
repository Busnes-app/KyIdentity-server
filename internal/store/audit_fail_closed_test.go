package store

import (
	"errors"
	"testing"
	"time"
)

// Each mutation that takes an audit row must leave nothing behind when that row cannot be
// written: the change and the record of who made it commit together or not at all.
func TestMutationsRollBackWhenTheirAuditCannotBeWritten(t *testing.T) {
	cases := map[string]struct {
		mutate func(s *Store, u *User, audit *AuditEvent) error
		intact func(s *Store, u *User) bool
	}{
		"oauth client": {
			func(s *Store, _ *User, a *AuditEvent) error {
				return s.CreateOAuthClient(&OAuthClient{ID: "c", ClientName: "C", ClientType: "public", RedirectURIsJSON: "[]", AllowedScopesJSON: "[]"}, a)
			},
			func(s *Store, _ *User) bool { c, err := s.GetOAuthClientByID("c"); return err == nil && c == nil },
		},
		"paired system": {
			func(s *Store, _ *User, a *AuditEvent) error {
				return s.CreatePairedSystem(&PairedSystem{ID: "p", Name: "P", SystemType: "scim", Status: "active"}, a)
			},
			func(s *Store, _ *User) bool { p, err := s.GetPairedSystemByID("p"); return err == nil && p == nil },
		},
		"launcher application": {
			func(s *Store, _ *User, a *AuditEvent) error {
				return s.CreateApplication(&Application{ID: "a", Name: "A", URL: "https://a.test", IconName: "globe"}, a)
			},
			func(s *Store, _ *User) bool { app, err := s.GetApplicationByID("a"); return err == nil && app == nil },
		},
		"session revocation": {
			func(s *Store, u *User, a *AuditEvent) error { return s.RevokeUserAccess(u.ID, a) },
			func(s *Store, u *User) bool {
				live, err := s.ListUserSessions(u.ID, time.Hour)
				return err == nil && len(live) == 1
			},
		},
		"recovery code": {
			func(s *Store, u *User, a *AuditEvent) error {
				_, err := s.ConsumeRecoveryCode(u.ID, "hmac:code", "legacy", a)
				return err
			},
			func(s *Store, u *User) bool {
				codes, err := s.GetValidRecoveryCodes(u.ID)
				return err == nil && len(codes) == 1
			},
		},
		"settings": {
			func(s *Store, _ *User, a *AuditEvent) error {
				return s.EditSettings(a, func(st Settings) error { return st.SetSetting("k", "v") })
			},
			func(s *Store, _ *User) bool { _, err := s.GetSetting("k"); return errors.Is(err, ErrNotFound) },
		},
		"device pairing token": {
			func(s *Store, u *User, a *AuditEvent) error {
				return s.CreateDevicePairingToken(&DevicePairingToken{ID: "t", UserID: u.ID, TokenHash: "th", PINHash: "ph", ExpiresAt: time.Now().UTC().Add(time.Minute)}, a)
			},
			func(s *Store, _ *User) bool {
				tok, err := s.GetValidDevicePairingToken("th")
				return err == nil && tok == nil
			},
		},
	}
	fixture := func(t *testing.T) (*Store, *User) {
		s, u := newStoreWithUser(t, "user")
		if err := s.CreateSession(&Session{ID: "live", UserID: u.ID, SessionTokenHash: "live", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := s.ReplaceRecoveryCodes(u.ID, []RecoveryCode{{ID: "rc", UserID: u.ID, CodeHash: "hmac:code"}}, nil); err != nil {
			t.Fatal(err)
		}
		return s, u
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			// Control: with no audit obligation the mutation lands, so intact can see it.
			s, u := fixture(t)
			if err := c.mutate(s, u, nil); err != nil || c.intact(s, u) {
				t.Fatalf("control mutation did not land: %v", err)
			}
			s, u = fixture(t)
			if err := c.mutate(s, u, poisonedAudit(t, s, "test", u.ID)); err == nil {
				t.Fatal("an unauditable mutation reported success")
			}
			if !c.intact(s, u) {
				t.Fatal("the mutation survived its failed audit write")
			}
		})
	}
}

// Only a real uniqueness clash is a conflict; the handler answers 409 on this and nothing else.
func TestCreateUserClashIsUserConflict(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	dup := &User{ID: "u2", Username: u.Username, Email: "other@example.test", PasswordHash: "x", Role: "user", Status: "active"}
	if err := s.CreateUserWithSyncEvents(dup, nil); !errors.Is(err, ErrUserConflict) {
		t.Fatalf("duplicate username: %v", err)
	}
}
