package store

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Store scoping (tenancy design, "Isolation enforcement"; build plan PR 2). Every method
// that reads or writes an org-owned table is on OrgStore and binds org_id itself; the
// *Store keeps only the pre-org lookups that find the principal deciding the org.
// Workers and the few cross-org reads use PlatformStore.

// OrgID names an org. It is built only from a principal the store loaded (User.Org), as
// the default org of a single-tenant install (Store.DefaultOrg), or in tests.
type OrgID struct{ id string }

func (o OrgID) String() string { return o.id }

// OrgStore is the store bound to one org.
type OrgStore struct {
	s   *Store
	org string
}

// Org binds the store to an org. A zero OrgID is a bug in the caller, never "every org".
func (s *Store) Org(id OrgID) *OrgStore {
	if id.id == "" {
		panic("store: Org with a zero OrgID")
	}
	return &OrgStore{s: s, org: id.id}
}

// ID is the org this handle is bound to.
func (o *OrgStore) ID() OrgID { return OrgID{o.org} }

// Org is the org of a user row read by the store. A User built by a caller has none,
// and Store.Org refuses it.
func (u *User) Org() OrgID { return OrgID{u.orgID} }

// DefaultOrg is the single-tenant org. A multi-tenant install has no such row, so a read
// through it finds nothing and a write fails the org existence trigger. Only the
// single-tenant operator paths and tests call it (TestDefaultOrgCallers).
func (s *Store) DefaultOrg() *OrgStore { return &OrgStore{s: s, org: DefaultOrgID} }

// PlatformStore holds the reads that span every org. Each row it returns names its org.
type PlatformStore struct{ s *Store }

func (s *Store) Platform() *PlatformStore { return &PlatformStore{s} }

// ErrStaffOnly: an administrator or a delegation outside the staff org (D8). In a
// single-tenant install every account is in the default org, where both are allowed.
var ErrStaffOnly = errors.New("administrators and delegations belong to the staff org only")

const msgStaffOnly = "administrators and delegations belong to the staff org only"

// staffOrgError maps the D8 trigger to ErrStaffOnly.
func staffOrgError(err error) error {
	if err != nil && strings.Contains(err.Error(), msgStaffOnly) {
		return ErrStaffOnly
	}
	return err
}

// CreateOrgForTest adds an active org of the kind given and returns it. Test binaries
// only: orgs are created by the platform API (build plan PR 4).
func CreateOrgForTest(s *Store, kind string) (OrgID, error) {
	if !testing.Testing() {
		panic("store: CreateOrgForTest outside a test binary")
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	_, err := s.db.Exec(`INSERT INTO orgs(id,name,kind,status,created_at,updated_at) VALUES(?,?,?,'active',?,?)`, id, kind+" "+id[:8], kind, now, now)
	return OrgID{id}, err
}

// connectorOrgTx is the org of an inbound SCIM connector: its token decided it, so every
// account it writes is in that org. A missing connector is ErrNotFound.
func connectorOrgTx(q interface {
	QueryRow(string, ...any) *sql.Row
}, connectorID string) (string, error) {
	var org string
	err := q.QueryRow(`SELECT org_id FROM scim_connectors WHERE id=?`, connectorID).Scan(&org)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return org, err
}
