package store

import (
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
)

// Platform provisioning API tokens (tenancy design, "Platform provisioning API",
// build plan PR 4). A token is kyp_<id>_<secret> with a 256-bit secret; only its SHA-256 is
// stored. Billing holds orgs:* scopes, the customer portal members:*, never both.

const (
	ScopeOrgsRead     = "orgs:read"
	ScopeOrgsWrite    = "orgs:write"
	ScopeOrgsDelete   = "orgs:delete"
	ScopeMembersRead  = "members:read"
	ScopeMembersWrite = "members:write"
	// MaxPlatformTokenTTL bounds a token's life; the CLI default is a year.
	MaxPlatformTokenTTL = 2 * 365 * 24 * time.Hour
)

var ErrInvalidScopes = errors.New("scopes must be orgs:read|write|delete or members:read|write, not both kinds")

// PlatformToken is a token's row, never its secret.
type PlatformToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

// Has reports whether the token holds scope.
func (t *PlatformToken) Has(scope string) bool { return slices.Contains(t.Scopes, scope) }

// validScopes: at least one scope, all known, all of one kind, no repeats.
func validScopes(scopes []string) bool {
	kind := ""
	for i, sc := range scopes {
		k, _, _ := strings.Cut(sc, ":")
		switch sc {
		case ScopeOrgsRead, ScopeOrgsWrite, ScopeOrgsDelete, ScopeMembersRead, ScopeMembersWrite:
		default:
			return false
		}
		if kind != "" && k != kind || slices.Contains(scopes[:i], sc) {
			return false
		}
		kind = k
	}
	return kind != ""
}

// CreatePlatformToken mints a token and returns it once with its row; the audit row is a
// platform row written in the same transaction.
func (p *PlatformStore) CreatePlatformToken(name string, scopes []string, ttl time.Duration, audit *AuditEvent) (string, *PlatformToken, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 || ttl <= 0 || ttl > MaxPlatformTokenTTL {
		return "", nil, errors.New("a token needs a name of 1-100 characters and a lifetime of up to two years")
	}
	if !validScopes(scopes) {
		return "", nil, ErrInvalidScopes
	}
	id, err := crypto.GenerateRandomHex(8)
	if err != nil {
		return "", nil, err
	}
	secret, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return "", nil, err
	}
	raw := "kyp_" + id + "_" + secret
	now := rowTime()
	t := &PlatformToken{ID: id, Name: name, Scopes: scopes, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	err = p.s.auditedTx(audit, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO platform_tokens(id,name,token_hash,scopes,created_at,expires_at) VALUES(?,?,?,?,?,?)`,
			id, name, crypto.HashSHA256(raw), strings.Join(scopes, " "), t.CreatedAt, t.ExpiresAt)
		if audit != nil {
			audit.Action, audit.TargetID, audit.TargetType = "platform.token_created", id, "platform_token"
			setAuditDetails(audit, map[string]any{"name": name, "scopes": scopes, "expiresAt": t.ExpiresAt})
		}
		return err
	})
	if err != nil {
		return "", nil, err
	}
	return raw, t, nil
}

// RevokePlatformToken ends a token now. An unknown or already revoked token is ErrNotFound.
func (p *PlatformStore) RevokePlatformToken(id string, audit *AuditEvent) error {
	return p.s.auditedTx(audit, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE platform_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, rowTime(), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		if audit != nil {
			audit.Action, audit.TargetID, audit.TargetType = "platform.token_revoked", id, "platform_token"
		}
		return nil
	})
}

// ListPlatformTokens lists every token, newest first.
func (p *PlatformStore) ListPlatformTokens() ([]PlatformToken, error) {
	rows, err := p.s.db.Query(`SELECT id,name,scopes,created_at,expires_at,last_used_at,revoked_at FROM platform_tokens ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PlatformToken
	for rows.Next() {
		t, err := scanPlatformToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func scanPlatformToken(r interface{ Scan(...any) error }) (*PlatformToken, error) {
	var t PlatformToken
	var scopes string
	var used, revoked sql.NullTime
	if err := r.Scan(&t.ID, &t.Name, &scopes, &t.CreatedAt, &t.ExpiresAt, &used, &revoked); err != nil {
		return nil, err
	}
	t.Scopes = strings.Fields(scopes)
	if used.Valid {
		t.LastUsedAt = &used.Time
	}
	if revoked.Valid {
		t.RevokedAt = &revoked.Time
	}
	return &t, nil
}

// AuthenticatePlatformToken finds the live token raw names. Anything else, malformed,
// unknown, revoked or expired, is nil with no error.
func (p *PlatformStore) AuthenticatePlatformToken(raw string) (*PlatformToken, error) {
	rest, ok := strings.CutPrefix(raw, "kyp_")
	id, secret, ok2 := strings.Cut(rest, "_")
	if !ok || !ok2 || len(id) != 16 || len(secret) != 64 {
		return nil, nil
	}
	now := rowTime()
	t, err := scanPlatformToken(p.s.db.QueryRow(`SELECT id,name,scopes,created_at,expires_at,last_used_at,revoked_at FROM platform_tokens
 WHERE token_hash=? AND id=? AND revoked_at IS NULL AND expires_at>?`, crypto.HashSHA256(raw), id, now))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// At most once a minute, so a busy token does not write on every call.
	if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) > time.Minute {
		if _, err := p.s.db.Exec(`UPDATE platform_tokens SET last_used_at=? WHERE id=?`, now, t.ID); err != nil {
			return nil, err
		}
	}
	return t, nil
}
