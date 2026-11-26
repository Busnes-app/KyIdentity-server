package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
)

// Entitlements from the platform API (tenancy build plan 6): billing turns apps on and
// off for an org and sets their opaque quotas, which apps read from /api/suite/orgs.

// MaxQuotasBytes bounds one app's quotas object as stored (design: ≤ 4 KiB).
const MaxQuotasBytes = 4096

// ErrInvalidApps: an apps entry names no registered OAuth client, has no enabled, or its
// quotas are not a JSON object within MaxQuotasBytes.
var ErrInvalidApps = errors.New("invalid_apps")

// OrgApp is one app's entitlement in POST or PATCH /platform/v1/orgs, keyed by client ID.
// Enabled is required; Quotas omitted keeps the stored ones ({} for a new row).
type OrgApp struct {
	Enabled *bool           `json:"enabled"`
	Quotas  json.RawMessage `json:"quotas,omitempty"`
}

// canonicalQuotas is the quotas object compacted with sorted keys, numbers kept exact.
func canonicalQuotas(raw json.RawMessage) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if dec.Decode(&obj) != nil || obj == nil {
		return "", ErrInvalidApps
	}
	b, err := json.Marshal(obj)
	if err != nil || len(b) > MaxQuotasBytes {
		return "", ErrInvalidApps
	}
	return string(b), nil
}

// setOrgAppsTx writes each app's enablement and quotas for the org, leaving its
// access_mode (staff's) alone, and takes a new org revision when anything changed so
// /api/suite/orgs?since= finds it. It answers the changes (client: enabled) for the audit row.
func setOrgAppsTx(tx *sql.Tx, org string, apps map[string]OrgApp) (map[string]bool, error) {
	clients := make([]string, 0, len(apps))
	for c := range apps {
		clients = append(clients, c)
	}
	sort.Strings(clients)
	changed := map[string]bool{}
	for _, client := range clients {
		a := apps[client]
		if a.Enabled == nil {
			return nil, ErrInvalidApps
		}
		var app string
		if err := tx.QueryRow(`SELECT id FROM app_registry WHERE client_id=?`, client).Scan(&app); errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidApps
		} else if err != nil {
			return nil, err
		}
		var enabled bool
		quotas := "{}"
		err := tx.QueryRow(`SELECT enabled,quotas_json FROM org_apps WHERE org_id=? AND app_id=?`, org, app).Scan(&enabled, &quotas)
		exists := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		want := quotas
		if a.Quotas != nil {
			if want, err = canonicalQuotas(a.Quotas); err != nil {
				return nil, err
			}
		}
		switch {
		case !exists:
			_, err = tx.Exec(`INSERT INTO org_apps(org_id,app_id,enabled,quotas_json) VALUES(?,?,?,?)`, org, app, *a.Enabled, want)
		case enabled != *a.Enabled || quotas != want:
			_, err = tx.Exec(`UPDATE org_apps SET enabled=?,quotas_json=? WHERE org_id=? AND app_id=?`, *a.Enabled, want, org, app)
		default:
			continue
		}
		if err != nil {
			return nil, err
		}
		changed[client] = *a.Enabled
	}
	if len(changed) == 0 {
		return changed, nil
	}
	if _, err := tx.Exec(`UPDATE orgs SET revision=`+nextOrgRevisionSQL+` WHERE id=?`, org); err != nil {
		return nil, err
	}
	for _, on := range changed {
		if !on {
			// A disabled app keeps no token, code or client session of the org's users.
			return changed, revokeLostAppAccessTx(tx)
		}
	}
	return changed, nil
}
