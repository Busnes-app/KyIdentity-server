package store

import (
	"database/sql"
	"errors"
	"time"
)

var ErrAppAuthentication = errors.New("application authentication requirements not met")

// Zero factor age means no additional age limit. Fresh mode requires a new bound
// login for each authorization; it does not give the resulting code a zero TTL.
type AppAuthenticationPolicy struct {
	Mode          string `json:"mode"`
	PrimaryMaxAge int64  `json:"primaryMaxAge"`
	Factor        string `json:"factor"`
	FactorMaxAge  int64  `json:"factorMaxAge"`
}

func (p AppAuthenticationPolicy) Valid() bool {
	return (p.Mode == "reuse" || p.Mode == "fresh" || p.Mode == "max_age") &&
		(p.Factor == "password" || p.Factor == "mfa" || p.Factor == "passkey") &&
		p.PrimaryMaxAge >= 0 && p.PrimaryMaxAge <= 2147483647 && p.FactorMaxAge >= 0 && p.FactorMaxAge <= 2147483647 &&
		((p.Mode == "max_age" && p.PrimaryMaxAge > 0) || (p.Mode != "max_age" && p.PrimaryMaxAge == 0)) &&
		(p.Factor != "password" || p.FactorMaxAge == 0)
}

// EvidenceReason checks only proof, not whether the request completed a fresh
// interaction. Both the HTTP decision and the final store transaction use it.
func (p AppAuthenticationPolicy) EvidenceReason(e AuthenticationEvidence, now time.Time) string {
	if p.Mode != "reuse" || p.Factor != "password" {
		if e.PrimaryAuthenticatedAt == nil || e.PrimaryAuthenticatedAt.After(now) {
			return "password_required"
		}
	}
	if p.Mode == "max_age" && e.PrimaryAuthenticatedAt.Add(time.Duration(p.PrimaryMaxAge)*time.Second).Before(now) {
		return "password_expired"
	}
	if p.Factor != "password" {
		if e.FactorAuthenticatedAt == nil || e.FactorAuthenticatedAt.After(now) {
			return "factor_required"
		}
		if p.Factor == "passkey" && e.FactorMethod != "webauthn" {
			return "passkey_required"
		}
		if e.FactorMethod != "totp" && e.FactorMethod != "push" && e.FactorMethod != "webauthn" {
			return "factor_required"
		}
		if p.FactorMaxAge > 0 && e.FactorAuthenticatedAt.Add(time.Duration(p.FactorMaxAge)*time.Second).Before(now) {
			return "factor_expired"
		}
	}
	return ""
}

func (p AppAuthenticationPolicy) Deadline(e AuthenticationEvidence) *time.Time {
	var deadline *time.Time
	if p.Mode == "max_age" && e.PrimaryAuthenticatedAt != nil {
		at := e.PrimaryAuthenticatedAt.Add(time.Duration(p.PrimaryMaxAge) * time.Second)
		deadline = &at
	}
	if p.FactorMaxAge > 0 && e.FactorAuthenticatedAt != nil {
		at := e.FactorAuthenticatedAt.Add(time.Duration(p.FactorMaxAge) * time.Second)
		if deadline == nil || at.Before(*deadline) {
			deadline = &at
		}
	}
	return deadline
}

func (s *Store) migrateAppAuthentication() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, spec := range []struct{ table, column, ddl string }{
		{"app_registry", "auth_mode", `ALTER TABLE app_registry ADD COLUMN auth_mode TEXT NOT NULL DEFAULT 'reuse' CHECK(auth_mode IN ('reuse','fresh','max_age'));
 ALTER TABLE app_registry ADD COLUMN auth_primary_max_age INTEGER NOT NULL DEFAULT 0 CHECK(auth_primary_max_age BETWEEN 0 AND 2147483647);
 ALTER TABLE app_registry ADD COLUMN auth_factor TEXT NOT NULL DEFAULT 'password' CHECK(auth_factor IN ('password','mfa','passkey'));
 ALTER TABLE app_registry ADD COLUMN auth_factor_max_age INTEGER NOT NULL DEFAULT 0 CHECK(auth_factor_max_age BETWEEN 0 AND 2147483647);
 ALTER TABLE app_registry ADD COLUMN auth_revision INTEGER NOT NULL DEFAULT 1;`},
		{"authorization_codes", "auth_app_id", `ALTER TABLE authorization_codes ADD COLUMN auth_app_id TEXT NOT NULL DEFAULT '';
 ALTER TABLE authorization_codes ADD COLUMN auth_policy_revision INTEGER NOT NULL DEFAULT 0;
 DELETE FROM authorization_codes;`},
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
	return tx.Commit()
}

func (s *Store) ClientAuthenticationPolicy(clientID string) (AppAuthenticationPolicy, error) {
	var p AppAuthenticationPolicy
	err := s.db.QueryRow(`SELECT auth_mode,auth_primary_max_age,auth_factor,auth_factor_max_age FROM app_registry WHERE client_id=?`, clientID).Scan(&p.Mode, &p.PrimaryMaxAge, &p.Factor, &p.FactorMaxAge)
	return p, err
}

func (s *Store) SetAppAuthenticationPolicy(id string, p AppAuthenticationPolicy, revision int, audit *AuditEvent) error {
	if !p.Valid() {
		return ErrAppAuthentication
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	a, err := lockAppRecord(tx, id, revision)
	if err != nil {
		return err
	}
	if a.ClientID == "" {
		return ErrAppAuthentication
	}
	if a.Authentication == p {
		if err = appRegistryAudit(audit, map[string]any{"app": a, "authentication": p, "unchanged": true}); err != nil {
			return err
		}
		if err = recordAuditTx(tx, audit); err != nil {
			return err
		}
		return tx.Commit()
	}
	if _, err = tx.Exec(`UPDATE app_registry SET auth_mode=?,auth_primary_max_age=?,auth_factor=?,auth_factor_max_age=?,auth_revision=auth_revision+1,revision=revision+1 WHERE id=?`, p.Mode, p.PrimaryMaxAge, p.Factor, p.FactorMaxAge, id); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM authorization_interactions WHERE client_id=?`, a.ClientID); err != nil {
		return err
	}
	// All policy edits invalidate old grants, including relaxations. Reverting a
	// policy cannot revive an authorization that was already invalidated.
	if _, err = tx.Exec(`DELETE FROM authorization_codes WHERE client_id=?`, a.ClientID); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE issued_tokens SET revoked_at=? WHERE client_id=? AND revoked_at IS NULL`, time.Now().UTC(), a.ClientID); err != nil {
		return err
	}
	if err = appRegistryAudit(audit, map[string]any{"app": a, "authentication": p, "policyRevision": a.AuthenticationRevision + 1}); err != nil {
		return err
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

// Called under the code transaction's writer lock, before consuming an interaction.
func checkCodeAppAuthenticationTx(tx *sql.Tx, code *AuthorizationCode) error {
	var p AppAuthenticationPolicy
	if err := tx.QueryRow(`SELECT id,auth_revision,role_revision,auth_mode,auth_primary_max_age,auth_factor,auth_factor_max_age FROM app_registry WHERE client_id=?`, code.ClientID).Scan(&code.AuthenticationAppID, &code.AuthenticationPolicyRevision, &code.RoleRevision, &p.Mode, &p.PrimaryMaxAge, &p.Factor, &p.FactorMaxAge); err != nil {
		return err
	}
	if !p.Valid() || p.EvidenceReason(code.AuthenticationEvidence, time.Now().UTC()) != "" {
		return ErrAppAuthentication
	}
	if p.Mode == "fresh" {
		var created time.Time
		if err := tx.QueryRow(`SELECT created_at FROM authorization_interactions WHERE hash=? AND session_id=? AND expires_at>?`, code.InteractionHash, code.SessionID, time.Now().UTC()).Scan(&created); err != nil {
			return ErrAppAuthentication
		}
		if code.PrimaryAuthenticatedAt == nil || code.PrimaryAuthenticatedAt.Before(created) {
			return ErrAppAuthentication
		}
	}
	if at := p.Deadline(code.AuthenticationEvidence); at != nil && (code.AuthenticationExpiresAt == nil || at.Before(*code.AuthenticationExpiresAt)) {
		code.AuthenticationExpiresAt = at
	}
	return nil
}
