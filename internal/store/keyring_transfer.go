package store

import (
	"database/sql"
	"time"
)

func (o *OrgStore) RequestKeyringTransfer(p KeyringSession, ring, id string, request KeyringTransferRequest, audit *AuditEvent) (int64, error) {
	var expiry int64
	err := o.keyringTx(p, nil, audit, func(tx *sql.Tx, now time.Time) error {
		if err := o.keyringVersionTx(tx, p.UserID, ring); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM keyring_transfers WHERE org_id=? AND user_id=? AND expires_at<=?`, o.org, p.UserID, now.Unix()); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM keyring_transfers WHERE org_id=? AND user_id=?`, o.org, p.UserID).Scan(&count); err != nil {
			return err
		}
		if count >= maxKeyringTransfers {
			return ErrKeyringConflict
		}
		expiry = now.Add(keyringTransferTTL).Unix()
		res, err := tx.Exec(`INSERT INTO keyring_transfers(org_id,user_id,id,request_session,expires_at,recipient_key,request_mac)
 VALUES(?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`, o.org, p.UserID, id, p.SessionID, expiry, request.RecipientKey, request.RequestMAC)
		return keyringAffected(res, err, ErrKeyringConflict)
	})
	return expiry, err
}

// KeyringPendingTransfer adds the requesting session so the approver can recognise it.
type KeyringPendingTransfer struct {
	KeyringTransferRequest
	UserAgent string `json:"user_agent"`
	IPAddress string `json:"ip_address"`
	SignedIn  int64  `json:"signed_in_at"`
}

func (o *OrgStore) KeyringTransfer(p KeyringSession, id string) (KeyringPendingTransfer, error) {
	var out KeyringPendingTransfer
	err := o.keyringTx(p, nil, nil, func(tx *sql.Tx, now time.Time) error {
		var signedIn time.Time
		err := tx.QueryRow(`SELECT t.recipient_key,t.request_mac,s.user_agent,s.ip_address,s.created_at
 FROM keyring_transfers t JOIN sessions s ON s.id=t.request_session AND s.user_id=t.user_id
 WHERE t.org_id=? AND t.user_id=? AND t.id=? AND t.request_session<>? AND t.expires_at>? AND t.sealed=''`,
			o.org, p.UserID, id, p.SessionID, now.Unix()).Scan(&out.RecipientKey, &out.RequestMAC, &out.UserAgent, &out.IPAddress, &signedIn)
		out.SignedIn = signedIn.Unix()
		return err
	})
	return out, err
}

func (o *OrgStore) ApproveKeyringTransfer(p KeyringSession, id, device, deviceHash string, response KeyringTransferResponse, grant KeyringGrant, audit *AuditEvent) error {
	return o.keyringTx(p, &grant, audit, func(tx *sql.Tx, now time.Time) error {
		res, err := tx.Exec(`UPDATE keyring_transfers SET approved_device=?,sender_key=?,sealed=? WHERE org_id=? AND user_id=? AND id=?
 AND expires_at>? AND request_session<>? AND sealed=''
 AND EXISTS(SELECT 1 FROM keyring_wrappers w WHERE w.org_id=keyring_transfers.org_id AND w.user_id=keyring_transfers.user_id
 AND w.id=? AND w.kind='device' AND w.device_hash=?)`, device, response.SenderKey, response.Sealed, o.org, p.UserID, id, now.Unix(), p.SessionID, device, deviceHash)
		return keyringAffected(res, err, sql.ErrNoRows)
	})
}

func (o *OrgStore) ClaimKeyringTransfer(p KeyringSession, id string, audit *AuditEvent) (KeyringTransferResponse, error) {
	var response KeyringTransferResponse
	err := o.keyringTx(p, nil, audit, func(tx *sql.Tx, now time.Time) error {
		return tx.QueryRow(`DELETE FROM keyring_transfers WHERE org_id=? AND user_id=? AND id=?
 AND request_session=? AND expires_at>? AND sealed<>'' RETURNING sender_key,sealed`,
			o.org, p.UserID, id, p.SessionID, now.Unix()).Scan(&response.SenderKey, &response.Sealed)
	})
	return response, err
}

func (o *OrgStore) CancelKeyringTransfer(p KeyringSession, id string, audit *AuditEvent) error {
	return o.keyringTx(p, nil, audit, func(tx *sql.Tx, _ time.Time) error {
		res, err := tx.Exec(`DELETE FROM keyring_transfers WHERE org_id=? AND user_id=? AND id=? AND request_session=?`, o.org, p.UserID, id, p.SessionID)
		return keyringAffected(res, err, sql.ErrNoRows)
	})
}

func (s *Store) DeleteExpiredKeyringTransfers() error {
	_, err := s.db.Exec(`DELETE FROM keyring_transfers WHERE expires_at<=?`, time.Now().Unix())
	return err
}
