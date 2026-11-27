package store

import (
	"database/sql"
	"errors"
	"strings"
)

const oldEnrollmentCheck = `CHECK((group_id IS NULL AND scope IN ('organization','administrators')) OR (group_id IS NOT NULL AND scope='group:'||group_id))`
const orgEnrollmentCheck = `CHECK((group_id IS NULL AND (scope IN ('organization','administrators') OR scope LIKE 'org:%')) OR (group_id IS NOT NULL AND scope='group:'||group_id))`
const oldRestoreReasonCheck = `CHECK (status_reason IN ('','payment','abuse','operator'))`
const newRestoreReasonCheck = `CHECK (status_reason IN ('','payment','abuse','operator','restore_reconciliation'))`
const orgEnrollmentEnabled = `EXISTS(SELECT 1 FROM system_settings WHERE key='tenancy_mode' AND value='multi')`
const enrollmentScopesSQL = `(SELECT 'organization' UNION ALL SELECT 'org:'||u.org_id WHERE ` + orgEnrollmentEnabled + ` UNION ALL SELECT 'administrators' WHERE (u.role='admin' OR EXISTS(SELECT 1 FROM admin_delegations d WHERE d.user_id=u.id)) UNION ALL SELECT 'group:'||m.group_id FROM group_memberships m WHERE m.user_id=u.id)`
const orgApplicableSQL = `SELECT u.id user_id,p.scope,p.allowed_mask,p.grace_seconds FROM users u JOIN enrollment_policies p ON p.required AND (p.scope='organization' OR p.scope='org:'||u.org_id AND ` + orgEnrollmentEnabled + `)
 UNION ALL SELECT u.id,p.scope,p.allowed_mask,p.grace_seconds FROM users u JOIN enrollment_policies p ON p.required AND p.scope='administrators' WHERE (u.role='admin' OR EXISTS(SELECT 1 FROM admin_delegations d WHERE d.user_id=u.id))
 UNION ALL SELECT m.user_id,p.scope,p.allowed_mask,p.grace_seconds FROM group_memberships m JOIN enrollment_policies p ON p.group_id=m.group_id AND p.required`
const orgRequirementsSQL = `SELECT u.id user_id,
 EXISTS(SELECT 1 FROM enrollment_policies p WHERE p.required AND p.scope IN ` + enrollmentScopesSQL + `) required,
 COALESCE((SELECT MIN(p.allowed_mask&1)+MIN(p.allowed_mask&2)+MIN(p.allowed_mask&4) FROM enrollment_policies p WHERE p.required AND p.scope IN ` + enrollmentScopesSQL + `),7) allowed_mask,
 COALESCE((SELECT MIN(COALESCE(d.due_at,0)) FROM enrollment_policies p LEFT JOIN enrollment_deadlines d ON d.user_id=u.id AND d.scope=p.scope WHERE p.required AND p.scope IN ` + enrollmentScopesSQL + `),0) due_at FROM users u`

func migrateOrgEnrollment(tx *sql.Tx) error {
	for _, c := range []struct{ table, old, next string }{{"enrollment_policies", oldEnrollmentCheck, orgEnrollmentCheck}, {"orgs", oldRestoreReasonCheck, newRestoreReasonCheck}} {
		var def string
		if err := tx.QueryRow(`SELECT sql FROM sqlite_schema WHERE type='table' AND name=?`, c.table).Scan(&def); err != nil {
			return err
		}
		if strings.Contains(def, c.next) {
			continue
		}
		if strings.Count(def, c.old) != 1 {
			return errors.New("store: missing org enrollment/restore constraint")
		}
		if err := editSchema(tx, `UPDATE sqlite_schema SET sql=? WHERE type='table' AND name=?`, strings.Replace(def, c.old, c.next, 1), c.table); err != nil {
			return err
		}
	}
	_, err := tx.Exec(`DROP VIEW applicable_enrollment_policies; DROP VIEW enrollment_requirements;
 CREATE VIEW applicable_enrollment_policies AS ` + orgApplicableSQL + `;
 CREATE VIEW enrollment_requirements AS ` + orgRequirementsSQL + `;
 INSERT OR IGNORE INTO enrollment_policies(scope) SELECT 'org:'||id FROM orgs;
 CREATE TRIGGER IF NOT EXISTS enrollment_new_org AFTER INSERT ON orgs BEGIN INSERT INTO enrollment_policies(scope) VALUES('org:'||NEW.id); END;`)
	return err
}
func migrateOrgEnrollmentPostgres(tx *sql.Tx) error {
	_, err := tx.Exec(`ALTER TABLE enrollment_policies DROP CONSTRAINT enrollment_policies_check;
 ALTER TABLE enrollment_policies ADD CONSTRAINT enrollment_policies_check ` + orgEnrollmentCheck + `;
 ALTER TABLE orgs DROP CONSTRAINT orgs_status_reason_check;
 ALTER TABLE orgs ADD CONSTRAINT orgs_status_reason_check ` + newRestoreReasonCheck + `;
 CREATE OR REPLACE VIEW applicable_enrollment_policies AS ` + orgApplicableSQL + `;
 CREATE OR REPLACE VIEW enrollment_requirements AS ` + orgRequirementsSQL + `;
 INSERT INTO enrollment_policies(scope) SELECT 'org:'||id FROM orgs ON CONFLICT DO NOTHING;
 CREATE FUNCTION enrollment_new_org() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 INSERT INTO enrollment_policies(scope) VALUES('org:'||NEW.id); RETURN NEW; END $$;
 CREATE TRIGGER enrollment_new_org AFTER INSERT ON orgs FOR EACH ROW EXECUTE FUNCTION enrollment_new_org();`)
	return err
}

// OrgEnrollmentPolicies returns only the selected org's policy, with no foreign scopes.
func (o *OrgStore) OrgEnrollmentPolicies() ([]EnrollmentPolicy, error) {
	var p EnrollmentPolicy
	var mask int
	err := o.s.db.QueryRow(`SELECT scope,required,allowed_mask,grace_seconds,revision FROM enrollment_policies WHERE scope=?`, "org:"+o.org).Scan(&p.Scope, &p.Required, &mask, &p.GraceSeconds, &p.Revision)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.AllowedMethods = factorNames(mask)
	return []EnrollmentPolicy{p}, nil
}
