package store

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/adpass"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/google/uuid"
)

// Active Directory connectors (docs/superpowers/specs/2026-11-19-active-directory-design.md).
// ad_passwords holds at most one undelivered ciphertext per connector and user, sealed to
// the agent's public key; KyIdentity cannot open it. A cleared ciphertext (”) is a
// delivered, rejected or expired entry.
const adSchemaSQL = `CREATE TABLE IF NOT EXISTS ad_connectors (
 system_id TEXT PRIMARY KEY REFERENCES paired_systems(id) ON DELETE CASCADE,
 bind_dn TEXT NOT NULL, base_dn TEXT NOT NULL, ca_pem TEXT NOT NULL,
 agent_public_key TEXT NOT NULL DEFAULT '', agent_key_mac TEXT NOT NULL DEFAULT '', agent_token_hash TEXT NOT NULL DEFAULT '',
 password_ttl_minutes %[1]s NOT NULL DEFAULT 1440 CHECK(password_ttl_minutes BETWEEN 10 AND 1440));
 CREATE UNIQUE INDEX IF NOT EXISTS ad_connectors_token ON ad_connectors(agent_token_hash) WHERE agent_token_hash<>'';
 CREATE TABLE IF NOT EXISTS ad_passwords (
 system_id TEXT NOT NULL REFERENCES paired_systems(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 seq %[1]s NOT NULL, ciphertext TEXT NOT NULL DEFAULT '', signature TEXT NOT NULL DEFAULT '', expires_at %[2]s,
 attempts %[1]s NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '',
 password_tag TEXT NOT NULL DEFAULT '', delivered_seq %[1]s NOT NULL DEFAULT 0, delivered_at %[2]s,
 PRIMARY KEY(system_id,user_id));
 CREATE INDEX IF NOT EXISTS ad_passwords_due ON ad_passwords(system_id,expires_at) WHERE ciphertext<>''`

func migrateAD(tx *sql.Tx) error {
	_, err := tx.Exec(fmt.Sprintf(adSchemaSQL, "INTEGER", "DATETIME"))
	return err
}

func migrateADPostgres(tx *sql.Tx) error {
	_, err := tx.Exec(fmt.Sprintf(adSchemaSQL, "BIGINT", "TIMESTAMPTZ"))
	return err
}

// ADKeys are derived from the deployment encryption key, which never lives in the
// database: a database writer can neither swap an agent key unnoticed nor forge an entry.
type ADKeys struct {
	mac  []byte
	sign ed25519.PrivateKey
}

// NewADKeys derives the agent-key MAC key and the entry-signing key.
func NewADKeys(encryptionKey []byte) ADKeys {
	return ADKeys{mac: crypto.DeriveKey(encryptionKey, "kyidentity:ad-agent-key-mac"),
		sign: ed25519.NewKeyFromSeed(crypto.DeriveKey(encryptionKey, "kyidentity:ad-entry-signing"))}
}

// KeyMAC binds an agent public key to its connector.
func (k ADKeys) KeyMAC(systemID, publicKey string) string {
	h := hmac.New(sha256.New, k.mac)
	h.Write([]byte(systemID + "\x00" + publicKey))
	return hex.EncodeToString(h.Sum(nil))
}

// SigningPublicKey is what the agent pins to verify entries.
func (k ADKeys) SigningPublicKey() string {
	return adpass.EncodeSigningKey(k.sign.Public().(ed25519.PublicKey))
}

// ADConnector is an Active Directory connector's settings. The LDAPS URL is the paired
// system's callback URL and the bind password its sealed secret; neither is here.
type ADConnector struct {
	SystemID           string `json:"systemId"`
	BindDN             string `json:"bindDn"`
	BaseDN             string `json:"baseDn"`
	CAPEM              string `json:"caPem"`
	AgentPublicKey     string `json:"agentPublicKey"`
	AgentKeyMAC        string `json:"-"`
	AgentTokenSet      bool   `json:"agentTokenSet"`
	PasswordTTLMinutes int    `json:"passwordTtlMinutes"`
}

// ADConnector returns a connector's settings, or nil when it has none.
func (s *Store) ADConnector(systemID string) (*ADConnector, error) {
	c := &ADConnector{SystemID: systemID}
	err := s.db.QueryRow(`SELECT bind_dn,base_dn,ca_pem,agent_public_key,agent_token_hash<>'',password_ttl_minutes FROM ad_connectors WHERE system_id=?`, systemID).
		Scan(&c.BindDN, &c.BaseDN, &c.CAPEM, &c.AgentPublicKey, &c.AgentTokenSet, &c.PasswordTTLMinutes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

// CreateADSystem creates the paired system and its settings in one transaction. Groups
// are always delivered to a directory.
func (s *Store) CreateADSystem(ps *PairedSystem, c *ADConnector, audit *AuditEvent) error {
	ps.CreatedAt, ps.GroupsEnabled = time.Now().UTC(), true
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO paired_systems (id,name,system_type,description,icon_url,callback_url,hmac_secret_encrypted,status,created_at,groups_enabled) VALUES (?,?,?,?,?,?,?,?,?,TRUE)`,
			ps.ID, ps.Name, ps.SystemType, ps.Description, ps.IconURL, ps.CallbackURL, ps.HMACSecretEncrypted, ps.Status, ps.CreatedAt); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO ad_connectors (system_id,bind_dn,base_dn,ca_pem,agent_public_key,agent_key_mac,password_ttl_minutes) VALUES (?,?,?,?,?,?,?)`,
			ps.ID, c.BindDN, c.BaseDN, c.CAPEM, c.AgentPublicKey, c.AgentKeyMAC, c.PasswordTTLMinutes)
		return err
	})
}

// ConfigureADSystem replaces a connector's settings; encrypted, when not empty, replaces
// the bind password. A new agent key drops queued ciphertext the old key sealed: the new
// agent could never open it.
func (s *Store) ConfigureADSystem(systemID, callbackURL, encrypted string, c *ADConnector, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		r, err := tx.Exec(`UPDATE paired_systems SET callback_url=?,hmac_secret_encrypted=CASE WHEN ?='' THEN hmac_secret_encrypted ELSE ? END WHERE id=? AND system_type='active_directory'`,
			callbackURL, encrypted, encrypted, systemID)
		if err != nil {
			return err
		}
		if n, err := r.RowsAffected(); err != nil || n != 1 {
			return errors.Join(err, ErrNotFound)
		}
		if _, err := tx.Exec(`UPDATE ad_passwords SET ciphertext='',signature='',expires_at=NULL,last_error='agent_key_replaced' WHERE system_id=? AND ciphertext<>''
 AND (SELECT agent_public_key FROM ad_connectors WHERE system_id=?)<>?`, systemID, systemID, c.AgentPublicKey); err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE ad_connectors SET bind_dn=?,base_dn=?,ca_pem=?,agent_public_key=?,agent_key_mac=?,password_ttl_minutes=? WHERE system_id=?`,
			c.BindDN, c.BaseDN, c.CAPEM, c.AgentPublicKey, c.AgentKeyMAC, c.PasswordTTLMinutes, systemID)
		return err
	})
}

// HashAgentToken is the stored form of an agent token.
func HashAgentToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// SetADAgentToken replaces the connector's agent token; the old one stops working.
func (s *Store) SetADAgentToken(systemID, token string, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		r, err := tx.Exec(`UPDATE ad_connectors SET agent_token_hash=? WHERE system_id=?`, HashAgentToken(token), systemID)
		if err != nil {
			return err
		}
		if n, err := r.RowsAffected(); err != nil || n != 1 {
			return errors.Join(err, ErrNotFound)
		}
		return nil
	})
}

// ADSystemForAgentToken names the connector a live agent token belongs to. A disabled
// connector's token answers ErrNotFound.
func (s *Store) ADSystemForAgentToken(token string) (string, error) {
	if token == "" {
		return "", ErrNotFound
	}
	var id string
	err := s.db.QueryRow(`SELECT c.system_id FROM ad_connectors c JOIN paired_systems p ON p.id=c.system_id
 WHERE c.agent_token_hash=? AND p.status<>'disabled'`, HashAgentToken(token)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}

func passwordTag(hash string) string {
	sum := sha256.Sum256([]byte(hash))
	return hex.EncodeToString(sum[:])
}

// QueueDirectoryPassword seals plaintext for every AD connector that holds the user and has
// an agent key, replacing any undelivered entry. It queues only while passwordHash is still
// the user's current hash, so of two racing changes only the current one is queued, and
// with the higher sequence number. audit builds one row per queued entry.
func (s *Store) QueueDirectoryPassword(keys ADKeys, userID, passwordHash string, plaintext []byte, audit func(systemID string, seq int64, superseded bool) *AuditEvent) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var current string
	err = tx.QueryRow(`SELECT password_hash FROM users WHERE id=?`, userID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if current == "" || current != passwordHash {
		return 0, nil
	}
	type target struct {
		id, key, mac string
		ttl          int
		last         int64
		pending      bool
	}
	rows, err := tx.Query(`SELECT c.system_id,c.agent_public_key,c.agent_key_mac,c.password_ttl_minutes,COALESCE(p.seq,0),COALESCE(p.ciphertext,'')<>''
 FROM ad_connectors c JOIN paired_systems s ON s.id=c.system_id
 JOIN sync_resource_state st ON st.system_id=c.system_id AND st.resource_id=? AND st.kind='user' AND st.active
 LEFT JOIN ad_passwords p ON p.system_id=c.system_id AND p.user_id=?
 WHERE s.status<>'disabled' AND c.agent_public_key<>'' ORDER BY c.system_id`, userID, userID)
	if err != nil {
		return 0, err
	}
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.key, &t.mac, &t.ttl, &t.last, &t.pending); err != nil {
			rows.Close()
			return 0, err
		}
		targets = append(targets, t)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	queued := 0
	var tampered []string
	for _, t := range targets {
		// Time-based, so a database restored from an older backup still issues numbers
		// above anything the agent has applied.
		seq := max(t.last+1, now.UnixMilli())
		// A key the database holds but this server never approved gets nothing. Only that
		// connector is skipped: the user's other connectors still get the password.
		if !hmac.Equal([]byte(t.mac), []byte(keys.KeyMAC(t.id, t.key))) {
			tampered = append(tampered, t.id)
			continue
		}
		ct, err := adpass.Seal(t.key, t.id, userID, seq, plaintext)
		if err != nil {
			return 0, err
		}
		expires := now.Add(time.Duration(t.ttl) * time.Minute).Truncate(time.Second)
		sig := adpass.SignEntry(keys.sign, t.id, userID, seq, expires.Unix(), ct)
		if _, err := tx.Exec(`INSERT INTO ad_passwords (system_id,user_id,seq,ciphertext,signature,expires_at,password_tag) VALUES (?,?,?,?,?,?,?)
 ON CONFLICT(system_id,user_id) DO UPDATE SET seq=excluded.seq,ciphertext=excluded.ciphertext,signature=excluded.signature,expires_at=excluded.expires_at,
 attempts=0,last_error='',password_tag=excluded.password_tag`,
			t.id, userID, seq, ct, sig, expires, passwordTag(passwordHash)); err != nil {
			return 0, err
		}
		if audit != nil {
			if err := recordAuditTx(tx, audit(t.id, seq, t.pending)); err != nil {
				return 0, err
			}
		}
		queued++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if len(tampered) > 0 {
		// Committed: the count is what was queued, and the error names what was not.
		return queued, fmt.Errorf("%w: connector %s", ErrAgentKeyTampered, strings.Join(tampered, ", "))
	}
	return queued, nil
}

// ErrAgentKeyTampered is an agent public key whose MAC does not verify. QueueDirectoryPassword
// returns it after committing the entries for every other connector.
var ErrAgentKeyTampered = errors.New("agent public key failed its integrity check; set it again")

// ADPasswordEntry is one queued ciphertext as the agent receives it, signed by KyIdentity.
type ADPasswordEntry struct {
	UserID     string `json:"userId"`
	Seq        int64  `json:"seq"`
	ExpiresAt  int64  `json:"expiresAt"`
	Ciphertext string `json:"ciphertext"`
	Signature  string `json:"signature"`
}

// PendingADPasswords returns a connector's live entries, least-tried first, then oldest, so
// entries the agent keeps retrying cannot hold newer ones off the page. A connector under a
// restore hold gets none until an operator releases it.
func (s *Store) PendingADPasswords(systemID string, now time.Time, limit int) ([]ADPasswordEntry, error) {
	now = now.UTC()
	rows, err := s.db.Query(`SELECT a.user_id,a.seq,a.expires_at,a.ciphertext,a.signature FROM ad_passwords a JOIN paired_systems p ON p.id=a.system_id
 WHERE a.system_id=? AND NOT p.provisioning_hold AND a.ciphertext<>'' AND a.expires_at>? ORDER BY a.attempts,a.seq LIMIT ?`, systemID, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ADPasswordEntry{}
	for rows.Next() {
		var e ADPasswordEntry
		var expires time.Time
		if err := rows.Scan(&e.UserID, &e.Seq, &expires, &e.Ciphertext, &e.Signature); err != nil {
			return nil, err
		}
		e.ExpiresAt = expires.Unix()
		out = append(out, e)
	}
	return out, rows.Err()
}

// ExpireADPasswords clears entries past their time, with one audit row each.
func (s *Store) ExpireADPasswords(now time.Time) (int, error) {
	now = now.UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`UPDATE ad_passwords SET ciphertext='',signature='',expires_at=NULL,last_error='expired' WHERE ciphertext<>'' AND expires_at<=? RETURNING system_id,user_id,seq`, now)
	if err != nil {
		return 0, err
	}
	type expired struct {
		system, user string
		seq          int64
	}
	var gone []expired
	for rows.Next() {
		var e expired
		if err := rows.Scan(&e.system, &e.user, &e.seq); err != nil {
			rows.Close()
			return 0, err
		}
		gone = append(gone, e)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for _, e := range gone {
		if err := recordAuditTx(tx, directoryAudit("directory.password_expired", e.user, e.system, e.seq, "")); err != nil {
			return 0, err
		}
	}
	return len(gone), tx.Commit()
}

func directoryAudit(action, userID, systemID string, seq int64, reason string) *AuditEvent {
	details := fmt.Sprintf(`{"systemId":%q,"seq":%d}`, systemID, seq)
	if reason != "" {
		details = fmt.Sprintf(`{"systemId":%q,"seq":%d,"reason":%q}`, systemID, seq, reason)
	}
	return &AuditEvent{ID: uuid.NewString(), ActorUsername: "kyidentity-dc-agent", Action: action, TargetID: userID, TargetType: "user", Outcome: "success", DetailsJSON: details}
}

// ADPasswordReasons are the only reasons an agent may report.
var ADPasswordReasons = map[string]bool{"signature_invalid": true, "expired": true, "password_policy": true, "user_not_found": true, "decrypt_failed": true, "replay_refused": true, "directory_error": true}

// FinishADPassword records the agent's result for the entry the agent was given. Applied
// and rejected clear the ciphertext; retry counts an attempt. An entry a newer password
// has replaced, or one already finished, is ErrNotFound.
func (s *Store) FinishADPassword(systemID, userID string, seq int64, outcome, reason string) error {
	if outcome != "applied" && !ADPasswordReasons[reason] {
		return InputError("unknown reason")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var r sql.Result
	now := time.Now().UTC()
	match := ` WHERE system_id=? AND user_id=? AND seq=? AND ciphertext<>''`
	switch outcome {
	case "applied":
		r, err = tx.Exec(`UPDATE ad_passwords SET ciphertext='',signature='',expires_at=NULL,last_error='',delivered_seq=seq,delivered_at=?`+match, now, systemID, userID, seq)
	case "rejected":
		r, err = tx.Exec(`UPDATE ad_passwords SET ciphertext='',signature='',expires_at=NULL,last_error=?`+match, reason, systemID, userID, seq)
	case "retry":
		r, err = tx.Exec(`UPDATE ad_passwords SET attempts=attempts+1,last_error=?`+match, reason, systemID, userID, seq)
	default:
		return InputError("outcome must be applied, rejected or retry")
	}
	if err != nil {
		return err
	}
	if n, err := r.RowsAffected(); err != nil || n != 1 {
		return errors.Join(err, ErrNotFound)
	}
	switch outcome {
	case "applied":
		err = recordAuditTx(tx, directoryAudit("directory.password_delivered", userID, systemID, seq, ""))
	case "rejected":
		err = recordAuditTx(tx, directoryAudit("directory.password_rejected", userID, systemID, seq, reason))
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// ADPasswordStatus is where one managed user's directory password stands.
type ADPasswordStatus struct {
	UserID      string `json:"userId"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	// State: current, pending, stale (the directory has an older password), rejected,
	// or missing (no password delivered yet).
	State       string     `json:"state"`
	LastError   string     `json:"lastError,omitempty"`
	DeliveredAt *time.Time `json:"deliveredAt,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
}

// ADPasswordStatuses lists every user the connector holds, by username.
// ponytail: unpaged; page it if a directory outgrows one answer.
func (s *Store) ADPasswordStatuses(systemID string) ([]ADPasswordStatus, error) {
	rows, err := s.db.Query(`SELECT u.id,u.username,u.display_name,u.password_hash,u.password_change_required,COALESCE(p.ciphertext,'')<>'',COALESCE(p.seq,0),COALESCE(p.delivered_seq,0),
 COALESCE(p.password_tag,''),COALESCE(p.last_error,''),p.delivered_at,p.expires_at
 FROM sync_resource_state st JOIN users u ON u.id=st.resource_id
 LEFT JOIN ad_passwords p ON p.system_id=st.system_id AND p.user_id=u.id
 WHERE st.system_id=? AND st.kind='user' AND st.active ORDER BY u.username LIMIT 5000`, systemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ADPasswordStatus{}
	for rows.Next() {
		var st ADPasswordStatus
		var hash, tag string
		var pending, mustChange bool
		var seq, delivered int64
		if err := rows.Scan(&st.UserID, &st.Username, &st.DisplayName, &hash, &mustChange, &pending, &seq, &delivered, &tag, &st.LastError, &st.DeliveredAt, &st.ExpiresAt); err != nil {
			return nil, err
		}
		switch {
		case pending:
			st.State = "pending"
		case delivered > 0 && delivered == seq && hash != "" && tag == passwordTag(hash) && mustChange:
			// What was delivered is the random lock queued for a temporary password.
			st.State = "locked"
		case delivered > 0 && delivered == seq && hash != "" && tag == passwordTag(hash):
			st.State = "current"
		case st.LastError != "" && st.LastError != "expired" && st.LastError != "agent_key_replaced" && st.LastError != "restored":
			st.State = "rejected"
		case delivered > 0:
			st.State = "stale"
		default:
			st.State = "missing"
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// ADGroupMembers is what a directory group should hold: the group's name and the IDs of
// its in-scope members, or exists=false once the group is gone.
func (s *Store) ADGroupMembers(systemID, groupID string) (name string, exists bool, userIDs []string, err error) {
	err = s.db.QueryRow(`SELECT name FROM directory_groups WHERE id=?`, groupID).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil, nil
	}
	if err != nil {
		return "", false, nil, err
	}
	userIDs, err = scanStrings(s.db.Query(`SELECT m.user_id FROM live_group_memberships m WHERE m.group_id=?
 AND EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id WHERE a.system_id=? AND e.user_id=m.user_id) ORDER BY m.user_id`, groupID, systemID))
	return name, true, userIDs, err
}
