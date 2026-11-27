package store

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestKeyringXwingUpgradePreservesDurableEnvelopes(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	o := s.DefaultOrg()
	login := keyringTestSession(t, s, u.ID)
	ring, device, recovery := uuid.NewString(), keyringTestWrapper("device"), keyringTestWrapper("recovery")
	if err := o.InitializeKeyring(login, ring, device, recovery, keyringTestGrant(t, s, login, "initialize"), nil); err != nil {
		t.Fatal(err)
	}
	// Recreate the exact shipped v18 table and a pending classical approval.
	legacy := migrateKeyring
	upgrade := migrateKeyringXwing
	if s.postgres {
		legacy = migrateKeyringPostgres
		upgrade = migrateKeyringXwingPostgres
	}
	if err := s.inTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec("DROP TABLE keyring_transfers"); err != nil {
			return err
		}
		if err := legacy(tx); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO keyring_transfers(org_id,user_id,id,request_session,expires_at,recipient_key,request_mac,approved_device,sender_key,sealed) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			o.org, u.ID, uuid.NewString(), login.SessionID, 4000000000, strings.Repeat("A", 87), strings.Repeat("B", 43), device.ID, strings.Repeat("C", 87), device.Sealed)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.inTx(upgrade); err != nil {
		t.Fatal(err)
	}
	if countRows(t, s, "SELECT count(*) FROM keyring_transfers") != 0 {
		t.Fatal("classical approval survived upgrade")
	}
	status, err := o.KeyringStatus(login)
	if err != nil || status.Version != ring || len(status.Wrappers) != 2 {
		t.Fatalf("durable state lost: %+v %v", status, err)
	}
	if got, err := o.KeyringWrapper(login, device.ID, device.DeviceHash); err != nil || got.Sealed != device.Sealed {
		t.Fatalf("device changed: %+v %v", got, err)
	}
	if _, err := o.RequestKeyringTransfer(login, ring, uuid.NewString(), KeyringTransferRequest{RecipientKey: strings.Repeat("A", 1622), RequestMAC: strings.Repeat("B", 43)}, nil); err != nil {
		t.Fatal("new X-Wing request refused:", err)
	}
	// Schema still refuses tenant mutation, including after the table replacement.
	if _, err := s.db.Exec("UPDATE keyring_transfers SET org_id=?", uuid.NewString()); err == nil {
		t.Fatal("org mutation accepted")
	}
}
