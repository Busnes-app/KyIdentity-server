package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// LauncherPrefs is how one user arranges their own launcher. It is cosmetic: access is
// decided by LauncherAppAccess, and a key here for an app the user cannot reach is
// ignored, not shown.
type LauncherPrefs struct {
	Layout string          `json:"layout"`
	Groups []LauncherGroup `json:"groups"`
	Hidden []string        `json:"hidden"`
}

type LauncherGroup struct {
	Name string   `json:"name"`
	Apps []string `json:"apps"`
}

const (
	maxLauncherGroups    = 20
	maxLauncherGroupName = 40
	maxLauncherKeys      = 500
)

// Client ids are free-form, so a key is only bounded, not patterned.
const maxLauncherKeyLen = 256

func validLauncherKey(k string) bool {
	id, ok := strings.CutPrefix(k, "client:")
	if !ok {
		id, ok = strings.CutPrefix(k, "custom:")
	}
	return ok && id != "" && len(k) <= maxLauncherKeyLen && utf8.ValidString(k) &&
		!strings.ContainsFunc(k, unicode.IsControl)
}

var ErrInvalidLauncherPrefs = errors.New("invalid launcher preferences")

// Validate also trims group names, so what is stored is what is shown.
func (p *LauncherPrefs) Validate() error {
	if p.Layout != "tiles" && p.Layout != "dock" {
		return ErrInvalidLauncherPrefs
	}
	if len(p.Groups) > maxLauncherGroups {
		return ErrInvalidLauncherPrefs
	}
	seen := map[string]bool{}
	check := func(keys []string) error {
		for _, k := range keys {
			if !validLauncherKey(k) || seen[k] {
				return ErrInvalidLauncherPrefs
			}
			seen[k] = true
		}
		if len(seen) > maxLauncherKeys {
			return ErrInvalidLauncherPrefs
		}
		return nil
	}
	for i := range p.Groups {
		name := strings.TrimSpace(p.Groups[i].Name)
		if name == "" || utf8.RuneCountInString(name) > maxLauncherGroupName {
			return ErrInvalidLauncherPrefs
		}
		p.Groups[i].Name = name
		if err := check(p.Groups[i].Apps); err != nil {
			return err
		}
	}
	return check(p.Hidden)
}

func (s *Store) migrateLauncherPrefs() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS launcher_prefs (
		user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
		prefs TEXT NOT NULL,
		updated_at DATETIME NOT NULL
	)`)
	return err
}

// GetLauncherPrefs returns nil when the user has never customised their launcher.
func (s *Store) GetLauncherPrefs(userID string) (*LauncherPrefs, error) {
	var raw string
	err := s.db.QueryRow(`SELECT prefs FROM launcher_prefs WHERE user_id = ?`, userID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p LauncherPrefs
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) SetLauncherPrefs(userID string, p LauncherPrefs) error {
	if err := p.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO launcher_prefs (user_id, prefs, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET prefs = excluded.prefs, updated_at = excluded.updated_at`,
		userID, string(raw), time.Now().UTC())
	return err
}

func (s *Store) DeleteLauncherPrefs(userID string) error {
	_, err := s.db.Exec(`DELETE FROM launcher_prefs WHERE user_id = ?`, userID)
	return err
}
