package store

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// refreshFixture issues a refresh family "fam" (first token "rt1") from a spent code for
// an assigned user of appAccessFixture's client.
func refreshFixture(t *testing.T, idle, life time.Duration) (*Store, *User, *RefreshFamily) {
	t.Helper()
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	accessCode(t, s, u, "code")
	if ok, err := s.ConsumeAuthorizationCode("code"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	_, binding, err := s.ClientAuthenticationPolicyBinding("client")
	if err != nil {
		t.Fatal(err)
	}
	f := &RefreshFamily{JTI: "fam", UserID: u.ID, ClientID: "client", SessionID: "session", Scope: "openid offline_access", Policy: binding, Idle: idle, ExpiresAt: time.Now().UTC().Add(life)}
	if err := s.CreateRefreshFamily(f, "code", "rt1"); err != nil {
		t.Fatal(err)
	}
	return s, u, f
}

func refreshAccess(id string) *IssuedToken {
	return &IssuedToken{JTI: id, ExpiresAt: time.Now().UTC().Add(time.Hour)}
}

func assertRevoked(t *testing.T, s *Store, jti string, want bool) {
	t.Helper()
	if got, err := s.IsTokenRevoked(jti); err != nil || got != want {
		t.Fatalf("token %s revoked=%v err=%v, want %v", jti, got, err, want)
	}
}

// Guards the happy rotation: the old token is spent, the new token and access token are
// bound to the family and inherit its user, session and policy, and the first token's
// idle window is capped at the family's absolute end.
func TestRotateRefreshTokenSpendsAndChains(t *testing.T) {
	s, u, f := refreshFixture(t, time.Hour, 30*time.Minute)
	if n := count(t, s, `SELECT COUNT(*) FROM refresh_tokens WHERE token_hash='rt1' AND expires_at=(SELECT expires_at FROM issued_tokens WHERE jti='fam')`); n != 1 {
		t.Fatal("first token outlived its family")
	}
	looked, err := s.LookupRefreshFamily("rt1")
	if err != nil || looked.JTI != "fam" || looked.UserID != u.ID || looked.Idle != time.Hour || looked.Scope != f.Scope || looked.Policy != f.Policy {
		t.Fatalf("lookup = %+v, %v", looked, err)
	}
	access := refreshAccess("at1")
	got, err := s.RotateRefreshToken("rt1", "client", "rt2", access)
	if err != nil || got.JTI != "fam" {
		t.Fatalf("rotate = %+v, %v", got, err)
	}
	if access.UserID != u.ID || access.SessionID != "session" || access.FamilyJTI != "fam" || access.ExpiresAt.After(f.ExpiresAt) {
		t.Fatalf("access token not bound to family: %+v", access)
	}
	if count(t, s, `SELECT COUNT(*) FROM refresh_tokens WHERE token_hash='rt1' AND used_at IS NOT NULL`) != 1 {
		t.Fatal("old token not spent")
	}
	if count(t, s, `SELECT COUNT(*) FROM refresh_tokens WHERE token_hash='rt2' AND used_at IS NULL AND family_jti='fam'`) != 1 {
		t.Fatal("next token not stored")
	}
	if count(t, s, `SELECT COUNT(*) FROM issued_tokens WHERE jti='at1' AND family_jti='fam'`) != 1 {
		t.Fatal("access token not registered in family")
	}
	assertRevoked(t, s, "at1", false)
	if _, err := s.RotateRefreshToken("rt2", "client", "rt3", refreshAccess("at2")); err != nil {
		t.Fatal("second rotation failed", err)
	}
}

// Guards reuse detection: replaying a spent token revokes the whole family, every access
// token it minted and the successor token, and reports ErrRefreshReuse.
func TestRotateRefreshTokenReuseRevokesFamily(t *testing.T) {
	s, _, _ := refreshFixture(t, time.Hour, 24*time.Hour)
	if _, err := s.RotateRefreshToken("rt1", "client", "rt2", refreshAccess("at1")); err != nil {
		t.Fatal(err)
	}
	f, err := s.RotateRefreshToken("rt1", "client", "attacker", refreshAccess("at-evil"))
	if !errors.Is(err, ErrRefreshReuse) || f == nil || f.JTI != "fam" {
		t.Fatalf("replay = %+v, %v; want ErrRefreshReuse", f, err)
	}
	assertRevoked(t, s, "fam", true)
	assertRevoked(t, s, "at1", true)
	if count(t, s, `SELECT COUNT(*) FROM issued_tokens WHERE jti='at-evil'`)+count(t, s, `SELECT COUNT(*) FROM refresh_tokens WHERE token_hash='attacker'`) != 0 {
		t.Fatal("replay minted tokens")
	}
	// The legitimate successor is dead too: the family is revoked.
	if _, err := s.RotateRefreshToken("rt2", "client", "rt3", refreshAccess("at2")); !errors.Is(err, ErrRefreshInvalid) {
		t.Fatal("successor survived reuse", err)
	}
}

// Guards client binding: a token presented by another client is treated as theft and
// revokes the family rather than minting tokens for that client.
func TestRotateRefreshTokenOtherClientRevokes(t *testing.T) {
	s, _, _ := refreshFixture(t, time.Hour, 24*time.Hour)
	if _, err := s.RotateRefreshToken("rt1", "other-client", "rt2", refreshAccess("at1")); !errors.Is(err, ErrRefreshReuse) {
		t.Fatal("cross-client refresh not refused", err)
	}
	assertRevoked(t, s, "fam", true)
	if count(t, s, `SELECT COUNT(*) FROM issued_tokens WHERE jti='at1'`) != 0 {
		t.Fatal("cross-client refresh minted access token")
	}
	if _, err := s.RotateRefreshToken("unknown", "client", "x", refreshAccess("x")); !errors.Is(err, ErrRefreshInvalid) {
		t.Fatal("unknown token", err)
	}
	if _, err := s.LookupRefreshFamily("unknown"); !errors.Is(err, ErrRefreshInvalid) {
		t.Fatal("unknown lookup", err)
	}
}

// Guards expiry and liveness refusals: expired tokens or families, ended sessions and a
// changed app policy refuse with ErrRefreshInvalid and leave the presented token unspent
// and the family unrevoked (the failure rolls back).
func TestRotateRefreshTokenRefusalsRollBack(t *testing.T) {
	past := time.Now().UTC().Add(-time.Minute)
	for name, breakIt := range map[string]func(*testing.T, *Store){
		"token expired": func(t *testing.T, s *Store) {
			mustExec(t, s, `UPDATE refresh_tokens SET expires_at=? WHERE token_hash='rt1'`, past)
		},
		"family expired": func(t *testing.T, s *Store) {
			mustExec(t, s, `UPDATE issued_tokens SET expires_at=? WHERE jti='fam'`, past)
		},
		"session idle": func(t *testing.T, s *Store) {
			mustExec(t, s, `UPDATE sessions SET last_active_at=? WHERE id='session'`, past.Add(-48*time.Hour))
		},
		"session too old": func(t *testing.T, s *Store) {
			mustExec(t, s, `UPDATE sessions SET created_at=? WHERE id='session'`, past.Add(-90*24*time.Hour))
		},
		"policy changed": func(t *testing.T, s *Store) {
			mustExec(t, s, `UPDATE app_registry SET auth_revision=auth_revision+1 WHERE client_id='client'`)
		},
		"user disabled": func(t *testing.T, s *Store) { mustExec(t, s, `UPDATE users SET status='disabled'`) },
	} {
		t.Run(name, func(t *testing.T) {
			s, _, _ := refreshFixture(t, time.Hour, 24*time.Hour)
			breakIt(t, s)
			if _, err := s.RotateRefreshToken("rt1", "client", "rt2", refreshAccess("at1")); !errors.Is(err, ErrRefreshInvalid) {
				t.Fatalf("got %v, want ErrRefreshInvalid", err)
			}
			if count(t, s, `SELECT COUNT(*) FROM refresh_tokens WHERE token_hash='rt1' AND used_at IS NULL`) != 1 {
				t.Fatal("refused rotation spent the token")
			}
			if count(t, s, `SELECT COUNT(*) FROM refresh_tokens WHERE token_hash='rt2'`)+count(t, s, `SELECT COUNT(*) FROM issued_tokens WHERE jti='at1'`) != 0 {
				t.Fatal("refused rotation minted tokens")
			}
			if count(t, s, `SELECT COUNT(*) FROM issued_tokens WHERE jti='fam' AND revoked_at IS NOT NULL`) != 0 {
				t.Fatal("refusal revoked the family")
			}
		})
	}
}

// Guards that a revoked family (e.g. by session or user revocation) cannot be rotated.
func TestRotateRefreshTokenRevokedFamily(t *testing.T) {
	s, u, _ := refreshFixture(t, time.Hour, 24*time.Hour)
	if err := s.RevokeUserTokens(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateRefreshToken("rt1", "client", "rt2", refreshAccess("at1")); !errors.Is(err, ErrRefreshInvalid) {
		t.Fatal("revoked family rotated", err)
	}
}

// Guards that the minted access token never outlives the family's absolute end.
func TestRotateRefreshTokenClampsAccessExpiry(t *testing.T) {
	s, _, f := refreshFixture(t, time.Hour, 10*time.Minute)
	access := &IssuedToken{JTI: "at1", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	got, err := s.RotateRefreshToken("rt1", "client", "rt2", access)
	if err != nil {
		t.Fatal(err)
	}
	if access.ExpiresAt.After(f.ExpiresAt) || !access.ExpiresAt.Equal(got.ExpiresAt) {
		t.Fatalf("access expiry %v beyond family end %v", access.ExpiresAt, f.ExpiresAt)
	}
}

// Guards CreateRefreshFamily's issuance guard: a family cannot be created from an unspent
// code, and the refusal leaves no family or token rows behind.
func TestCreateRefreshFamilyRequiresSpentCode(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	accessCode(t, s, u, "unspent")
	f := &RefreshFamily{JTI: "fam", UserID: u.ID, ClientID: "client", SessionID: "session", Scope: "openid", Idle: time.Hour, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if err := s.CreateRefreshFamily(f, "unspent", "rt1"); !errors.Is(err, ErrAppAccessDenied) {
		t.Fatal("family created from unspent code", err)
	}
	if count(t, s, `SELECT COUNT(*) FROM refresh_families`)+count(t, s, `SELECT COUNT(*) FROM refresh_tokens`)+count(t, s, `SELECT COUNT(*) FROM issued_tokens`) != 0 {
		t.Fatal("refused family left rows")
	}
	// A zero idle window violates the CHECK and rolls back the issued token too.
	if ok, err := s.ConsumeAuthorizationCode("unspent"); err != nil || !ok {
		t.Fatal(err)
	}
	f.Idle = 0
	if err := s.CreateRefreshFamily(f, "unspent", "rt1"); err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Fatalf("zero idle not refused by the CHECK constraint: %v", err)
	}
	if count(t, s, `SELECT COUNT(*) FROM issued_tokens`) != 0 {
		t.Fatal("failed family left its issued token")
	}
}

// Guards RFC 7009 revocation: unknown tokens and other clients' tokens are silently
// ignored (no oracle, no cross-client revocation); the owner's call revokes the family
// and the access tokens it minted.
func TestRevokeRefreshFamily(t *testing.T) {
	s, _, _ := refreshFixture(t, time.Hour, 24*time.Hour)
	if _, err := s.RotateRefreshToken("rt1", "client", "rt2", refreshAccess("at1")); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeRefreshFamily("rt2", "other-client"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeRefreshFamily("unknown", "client"); err != nil {
		t.Fatal(err)
	}
	assertRevoked(t, s, "fam", false)
	assertRevoked(t, s, "at1", false)
	if err := s.RevokeRefreshFamily("rt2", "client"); err != nil {
		t.Fatal(err)
	}
	assertRevoked(t, s, "fam", true)
	assertRevoked(t, s, "at1", true)
	if _, err := s.RotateRefreshToken("rt2", "client", "rt3", refreshAccess("at2")); !errors.Is(err, ErrRefreshInvalid) {
		t.Fatal("revoked family rotated", err)
	}
}
