package store

import (
	"database/sql"
	"errors"
	"time"
)

// A refresh family is an issued_tokens row (its jti, expiry = absolute end) so every
// existing user, client and session revocation reaches it. Its rotating tokens are
// stored only as hashes and cascade with it.

var (
	ErrRefreshInvalid = errors.New("refresh token is invalid, expired or revoked")
	// ErrRefreshReuse means a spent token was presented again; the family is revoked.
	ErrRefreshReuse = errors.New("refresh token reused; family revoked")
)

type RefreshFamily struct {
	JTI       string
	UserID    string
	ClientID  string
	SessionID string
	Scope     string
	AuthenticationEvidence
	Policy AppPolicyBinding
	// Idle is how long each rotated token stays usable; ExpiresAt is the family's end.
	Idle      time.Duration
	ExpiresAt time.Time
}

func (s *Store) migrateRefreshTokens() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, spec := range []struct{ table, column, ddl string }{
		{"issued_tokens", "family_jti", `ALTER TABLE issued_tokens ADD COLUMN family_jti TEXT`},
	} {
		var exists int
		if err = tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`, spec.table, spec.column).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			if _, err = tx.Exec(spec.ddl); err != nil {
				return err
			}
		}
	}
	if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_issued_tokens_family ON issued_tokens(family_jti);
CREATE TABLE IF NOT EXISTS refresh_families (
	jti TEXT PRIMARY KEY REFERENCES issued_tokens(jti) ON DELETE CASCADE,
	scope TEXT NOT NULL,
	primary_authenticated_at DATETIME,
	factor_authenticated_at DATETIME,
	factor_method TEXT NOT NULL DEFAULT '',
	auth_app_id TEXT NOT NULL,
	auth_revision INTEGER NOT NULL,
	role_revision INTEGER NOT NULL,
	idle_seconds INTEGER NOT NULL CHECK(idle_seconds > 0)
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
	token_hash TEXT PRIMARY KEY,
	family_jti TEXT NOT NULL REFERENCES refresh_families(jti) ON DELETE CASCADE,
	expires_at DATETIME NOT NULL,
	used_at DATETIME,
	created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_jti);`); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateRefreshFamily registers a family for a just-spent authorization code through the
// same guard as its access token, plus its first token, in one transaction.
func (s *Store) CreateRefreshFamily(f *RefreshFamily, authorizationCodeID, tokenHash string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = recordIssuedTokenTx(tx, &IssuedToken{AuthorizationCodeID: authorizationCodeID, JTI: f.JTI, UserID: f.UserID, ClientID: f.ClientID, SessionID: f.SessionID, ExpiresAt: f.ExpiresAt}); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO refresh_families(jti,scope,primary_authenticated_at,factor_authenticated_at,factor_method,auth_app_id,auth_revision,role_revision,idle_seconds) VALUES(?,?,?,?,?,?,?,?,?)`,
		f.JTI, f.Scope, f.PrimaryAuthenticatedAt, f.FactorAuthenticatedAt, f.FactorMethod, f.Policy.AppID, f.Policy.AuthRevision, f.Policy.RoleRevision, int64(f.Idle/time.Second)); err != nil {
		return err
	}
	if err = insertRefreshTokenTx(tx, f, tokenHash, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func insertRefreshTokenTx(tx *sql.Tx, f *RefreshFamily, tokenHash string, now time.Time) error {
	expires := now.Add(f.Idle)
	if f.ExpiresAt.Before(expires) {
		expires = f.ExpiresAt
	}
	_, err := tx.Exec(`INSERT INTO refresh_tokens(token_hash,family_jti,expires_at,created_at) VALUES(?,?,?,?)`, tokenHash, f.JTI, expires, now)
	return err
}

const (
	refreshFamilyColumns = `SELECT f.jti,t.user_id,t.client_id,COALESCE(t.session_id,''),t.expires_at,f.scope,f.primary_authenticated_at,f.factor_authenticated_at,f.factor_method,f.auth_app_id,f.auth_revision,f.role_revision,f.idle_seconds`
	refreshFamilyFrom    = ` FROM refresh_tokens r JOIN refresh_families f ON f.jti=r.family_jti JOIN issued_tokens t ON t.jti=f.jti WHERE r.token_hash=?`
)

func scanRefreshFamily(row *sql.Row, extra ...any) (*RefreshFamily, error) {
	f := &RefreshFamily{}
	var idle int64
	dest := append([]any{&f.JTI, &f.UserID, &f.ClientID, &f.SessionID, &f.ExpiresAt, &f.Scope, &f.PrimaryAuthenticatedAt, &f.FactorAuthenticatedAt, &f.FactorMethod, &f.Policy.AppID, &f.Policy.AuthRevision, &f.Policy.RoleRevision, &idle}, extra...)
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRefreshInvalid
		}
		return nil, err
	}
	f.Idle = time.Duration(idle) * time.Second
	return f, nil
}

// LookupRefreshFamily names the family a token belongs to without spending or trusting
// it; RotateRefreshToken repeats every check.
func (s *Store) LookupRefreshFamily(tokenHash string) (*RefreshFamily, error) {
	return scanRefreshFamily(s.db.QueryRow(refreshFamilyColumns+refreshFamilyFrom, tokenHash))
}

// RotateRefreshToken spends one token and, in the same transaction, registers the new
// access token through the issuance guard, stores the next token and counts the refresh
// as session activity. A spent token, or one presented by another client, revokes the
// family and every access token it minted and returns ErrRefreshReuse.
func (s *Store) RotateRefreshToken(oldHash, clientID, newHash string, access *IssuedToken, sessionIdle time.Duration) (*RefreshFamily, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	var usedAt sql.NullTime
	var tokenExpires time.Time
	var revoked bool
	f, err := scanRefreshFamily(tx.QueryRow(refreshFamilyColumns+`,r.used_at,r.expires_at,t.revoked_at IS NOT NULL`+refreshFamilyFrom, oldHash), &usedAt, &tokenExpires, &revoked)
	if err != nil {
		return nil, err
	}
	if usedAt.Valid || f.ClientID != clientID {
		if err = revokeRefreshFamilyTx(tx, f.JTI, now); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return f, ErrRefreshReuse
	}
	if revoked || !tokenExpires.After(now) || !f.ExpiresAt.After(now) {
		return nil, ErrRefreshInvalid
	}
	// The session's own idle limit applies; a refresh then counts as activity.
	res, err := tx.Exec(`UPDATE sessions SET last_active_at=? WHERE id=? AND last_active_at>?`, now, f.SessionID, now.Add(-sessionIdle))
	if err != nil {
		return nil, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return nil, ErrRefreshInvalid
	}
	if _, err = tx.Exec(`UPDATE refresh_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL`, now, oldHash); err != nil {
		return nil, err
	}
	access.UserID, access.ClientID, access.SessionID, access.FamilyJTI, access.Policy = f.UserID, f.ClientID, f.SessionID, f.JTI, f.Policy
	if f.ExpiresAt.Before(access.ExpiresAt) {
		access.ExpiresAt = f.ExpiresAt
	}
	if err = recordIssuedTokenTx(tx, access); err != nil {
		if errors.Is(err, ErrAppAccessDenied) {
			return nil, ErrRefreshInvalid
		}
		return nil, err
	}
	if err = insertRefreshTokenTx(tx, f, newHash, now); err != nil {
		return nil, err
	}
	return f, tx.Commit()
}

// RevokeRefreshFamily ends the family of a token presented by its own client (RFC 7009).
// Unknown tokens and other clients' tokens are ignored, so the call is not an oracle.
func (s *Store) RevokeRefreshFamily(tokenHash, clientID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var jti string
	err = tx.QueryRow(`SELECT t.jti FROM refresh_tokens r JOIN issued_tokens t ON t.jti=r.family_jti WHERE r.token_hash=? AND t.client_id=?`, tokenHash, clientID).Scan(&jti)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = revokeRefreshFamilyTx(tx, jti, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func revokeRefreshFamilyTx(tx *sql.Tx, jti string, now time.Time) error {
	_, err := tx.Exec(`UPDATE issued_tokens SET revoked_at=? WHERE (jti=? OR family_jti=?) AND revoked_at IS NULL`, now, jti, jti)
	return err
}
