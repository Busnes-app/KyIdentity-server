package store

import (
	"database/sql"
	"errors"
	"time"
)

// Explanations. An access decision is explained from the same rows that make it: the
// facts view for the verdict and its reason, the grant rows with their instants, the
// role mappings, the app's authentication policy and its revisions. Nothing here is a
// second decision procedure; the verdict is read from effective_app_access itself.

// AccessGrant is one contributing (or lapsed) source of access.
type AccessGrant struct {
	Kind              string     `json:"kind"` // direct, group
	GroupID           string     `json:"groupId,omitempty"`
	GroupName         string     `json:"groupName,omitempty"`
	SourceConnectorID string     `json:"sourceConnectorId,omitempty"`
	ExpiresAt         *time.Time `json:"expiresAt,omitempty"`
	Live              bool       `json:"live"`
}

// RoleGrant is one app role the user holds and how.
type RoleGrant struct {
	Role      string `json:"role"`
	Via       string `json:"via"` // direct, group
	GroupName string `json:"groupName,omitempty"`
}

type AccessExplanation struct {
	AppID          string                  `json:"appId"`
	AppName        string                  `json:"appName"`
	UserID         string                  `json:"userId"`
	Username       string                  `json:"username"`
	Allowed        bool                    `json:"allowed"`
	Reason         string                  `json:"reason"`
	AccessMode     string                  `json:"accessMode"`
	AppEnabled     bool                    `json:"appEnabled"`
	ClientEnabled  bool                    `json:"clientEnabled"`
	UserStatus     string                  `json:"userStatus"`
	UserEndsAt     *time.Time              `json:"userEndsAt,omitempty"`
	Grants         []AccessGrant           `json:"grants"`
	Roles          []RoleGrant             `json:"roles"`
	AccessEndsAt   *time.Time              `json:"accessEndsAt,omitempty"`
	Authentication AppAuthenticationPolicy `json:"authentication"`
	Revision       int                     `json:"revision"`
	AuthRevision   int                     `json:"authenticationRevision"`
	RoleRevision   int                     `json:"roleRevision"`
	Requestable    bool                    `json:"requestable"`
}

// accessReasonSQL names why the facts row allows or denies; the listing and the
// explanation share it so they can never disagree.
const accessReasonSQL = `CASE WHEN NOT f.active THEN 'user_disabled' WHEN NOT f.enabled THEN 'app_disabled' WHEN NOT f.client_enabled THEN 'client_disabled' WHEN f.access_mode='all_active_users' THEN 'all_active_users' WHEN f.direct THEN 'direct_assignment' WHEN f.group_assigned THEN 'group_assignment' ELSE 'not_assigned' END`

// ExplainAccess explains one user's access to one app as it stands now. Group names
// appear only for groups assigned to the app, in grants and in role sources alike.
func (s *Store) ExplainAccess(userID, appID string) (*AccessExplanation, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	app, err := scanAppRecord(tx.QueryRow(appRecordSelect+appRecordFrom+` WHERE a.id=?`, appID))
	if err != nil {
		return nil, err
	}
	u, err := scanUser(tx.QueryRow(`SELECT `+userColumns+` FROM users WHERE id=?`, userID))
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrUserMissing
	}
	e := &AccessExplanation{AppID: app.ID, UserID: u.ID, Username: u.Username, AccessMode: app.AccessMode, AppEnabled: app.Enabled, UserStatus: u.Status, UserEndsAt: u.EndsAt,
		Authentication: app.Authentication, Revision: app.Revision, AuthRevision: app.AuthenticationRevision, RoleRevision: app.RoleRevision, Requestable: app.Requestable,
		Grants: []AccessGrant{}, Roles: []RoleGrant{}}
	if err := tx.QueryRow(`SELECT `+appDisplayName+appRecordFrom+` WHERE a.id=?`, appID).Scan(&e.AppName); err != nil {
		return nil, err
	}
	if err := tx.QueryRow(`SELECT f.client_enabled,`+accessReasonSQL+`,EXISTS(SELECT 1 FROM effective_app_access x WHERE x.app_id=f.app_id AND x.user_id=f.user_id) FROM app_access_facts f WHERE f.app_id=? AND f.user_id=?`, appID, userID).Scan(&e.ClientEnabled, &e.Reason, &e.Allowed); err != nil {
		return nil, err
	}
	if u.EndsAt != nil && !u.EndsAt.After(time.Now()) {
		e.Reason = "account_ended"
	}
	var direct sql.NullInt64
	switch err := tx.QueryRow(`SELECT expires_at FROM app_user_assignments WHERE app_id=? AND user_id=?`, appID, userID).Scan(&direct); {
	case err == nil:
		at := timeFromUnix(direct)
		e.Grants = append(e.Grants, AccessGrant{Kind: "direct", ExpiresAt: at, Live: at == nil || at.After(time.Now())})
	case !errors.Is(err, sql.ErrNoRows):
		return nil, err
	}
	rows, err := tx.Query(`SELECT g.id,g.name,COALESCE(g.source_connector_id,''),m.expires_at FROM app_group_assignments ga JOIN directory_groups g ON g.id=ga.group_id JOIN group_memberships m ON m.group_id=g.id AND m.user_id=? WHERE ga.app_id=? ORDER BY g.name COLLATE NOCASE`, userID, appID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var g AccessGrant
		var expires sql.NullInt64
		if err := rows.Scan(&g.GroupID, &g.GroupName, &g.SourceConnectorID, &expires); err != nil {
			rows.Close()
			return nil, err
		}
		g.Kind, g.ExpiresAt = "group", timeFromUnix(expires)
		g.Live = g.ExpiresAt == nil || g.ExpiresAt.After(time.Now())
		e.Grants = append(e.Grants, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !e.Allowed && e.Reason == "not_assigned" && len(e.Grants) > 0 {
		e.Reason = "grants_expired"
	}
	rows, err = tx.Query(`SELECT r.name,'direct','' FROM app_roles r JOIN app_role_user_assignments a ON a.role_id=r.id WHERE r.app_id=? AND a.user_id=?
 UNION ALL SELECT r.name,'group',g.name FROM app_roles r JOIN app_role_group_assignments a ON a.role_id=r.id JOIN app_group_assignments ga ON ga.app_id=r.app_id AND ga.group_id=a.group_id JOIN live_group_memberships m ON m.group_id=a.group_id JOIN directory_groups g ON g.id=a.group_id WHERE r.app_id=? AND m.user_id=? ORDER BY 1,2,3`, appID, userID, appID, userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r RoleGrant
		if err := rows.Scan(&r.Role, &r.Via, &r.GroupName); err != nil {
			rows.Close()
			return nil, err
		}
		e.Roles = append(e.Roles, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if e.Allowed && app.ClientID != "" {
		if e.AccessEndsAt, err = s.AccessEndsAt(userID, app.ClientID); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// ExplainClientAccess explains access to the app behind an OAuth client; a client with
// no app record explains as nothing.
func (s *Store) ExplainClientAccess(userID, clientID string) (*AccessExplanation, error) {
	var appID string
	err := s.db.QueryRow(`SELECT id FROM app_registry WHERE client_id=?`, clientID).Scan(&appID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAppRecordMissing
	}
	if err != nil {
		return nil, err
	}
	return s.ExplainAccess(userID, appID)
}
