package store

import (
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func keyringTestSession(t *testing.T, s *Store, user string) KeyringSession {
	t.Helper()
	p := KeyringSession{UserID: user, SessionID: uuid.NewString()}
	err := s.CreateSession(&Session{ID: p.SessionID, UserID: user, SessionTokenHash: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func keyringTestGrant(t *testing.T, s *Store, p KeyringSession, op string) KeyringGrant {
	t.Helper()
	g := KeyringGrant{Hash: uuid.NewString(), Operation: op}
	err := s.CreateStepUpToken(&StepUpToken{ID: uuid.NewString(), UserID: p.UserID, SessionID: p.SessionID,
		TokenHash: g.Hash, Operation: g.Operation, ExpiresAt: time.Now().UTC().Add(time.Minute)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func keyringTestWrapper(kind string) KeyringWrapper {
	w := KeyringWrapper{KeyringWrapperInfo: KeyringWrapperInfo{ID: uuid.NewString(), Kind: kind}, Sealed: strings.Repeat("X", 80)}
	if kind == "device" {
		w.DeviceHash = strings.Repeat("a", 64)
	}
	return w
}

func TestKeyringAtomicWritesAndIsolation(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	o := s.DefaultOrg()
	up := migrateKeyring
	if s.postgres {
		up = migrateKeyringPostgres
	}
	if err := s.inTx(up); err != nil {
		t.Fatal("keyring migration rerun:", err)
	}
	p := keyringTestSession(t, s, u.ID)
	version, device, recovery := uuid.NewString(), keyringTestWrapper("device"), keyringTestWrapper("recovery")
	initialize := func(g KeyringGrant, audit *AuditEvent) error {
		return o.InitializeKeyring(p, version, device, recovery, g, audit)
	}
	if err := initialize(KeyringGrant{}, nil); !errors.Is(err, ErrKeyringStepUp) {
		t.Fatalf("initialization accepted without grant: %v", err)
	}
	g := keyringTestGrant(t, s, p, "POST /api/user/keyring")
	if err := initialize(g, poisonedAudit(t, s, "keyring.initialized", u.ID)); err == nil {
		t.Fatal("initialization accepted without durable audit")
	}
	if out, err := o.KeyringStatus(p); err != nil || out.Version != "" || len(out.Wrappers) != 0 {
		t.Fatalf("failed write changed keyring: %+v, %v", out, err)
	}
	if err := initialize(g, &AuditEvent{ID: uuid.NewString(), ActorID: u.ID, Action: "keyring.initialized", Outcome: "success"}); err != nil {
		t.Fatal("grant did not survive audit rollback:", err)
	}
	if countRows(t, s, `SELECT count(*) FROM audit_events WHERE action='keyring.initialized'`) != 1 {
		t.Fatal("keyring initialized with no audit")
	}
	if err := initialize(g, nil); !errors.Is(err, ErrKeyringStepUp) {
		t.Fatalf("spent grant accepted: %v", err)
	}
	if _, err := o.KeyringWrapper(p, device.ID, "wrong"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("device wrapper disclosed without capability: %v", err)
	}
	if got, err := o.KeyringWrapper(p, device.ID, device.DeviceHash); err != nil || got.Sealed != device.Sealed {
		t.Fatalf("device fetch: %+v, %v", got, err)
	}

	tenant, err := CreateOrgForTest(s, "customer")
	if err != nil {
		t.Fatal(err)
	}
	neighbor := s.Org(tenant)
	other := &User{ID: "neighbor", Username: "neighbor", Email: "neighbor@example.test", Role: "user", Status: "active", PasswordHash: "hash"}
	if err := neighbor.CreateUser(other); err != nil {
		t.Fatal(err)
	}
	if _, err := neighbor.KeyringStatus(p); !errors.Is(err, ErrKeyringDenied) {
		t.Fatalf("valid session crossed tenant: %v", err)
	}
	if _, err := neighbor.KeyringWrapper(keyringTestSession(t, s, other.ID), device.ID, device.DeviceHash); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("neighbor fetched wrapper: %v", err)
	}
	replacement := keyringTestWrapper("recovery")
	rotate := keyringTestGrant(t, s, p, "PUT /api/user/keyring/recovery")
	if err := o.RotateKeyringRecovery(p, version, "stale", replacement, rotate, nil); !errors.Is(err, ErrKeyringConflict) {
		t.Fatalf("stale recovery rotation: %v", err)
	}
	if err := o.RotateKeyringRecovery(p, version, recovery.ID, replacement, rotate, nil); err != nil {
		t.Fatal("rotate recovery:", err)
	}
	if _, err := o.KeyringWrapper(p, recovery.ID, ""); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("prior kit wrapper still served: %v", err)
	}

	req := KeyringTransferRequest{RecipientKey: strings.Repeat("A", 1622), RequestMAC: strings.Repeat("B", 43)}
	if _, err := o.RequestKeyringTransfer(p, version, uuid.NewString(), req, nil); err != nil {
		t.Fatal(err)
	}
	u.Status = "disabled"
	if err := s.UpdateUserWithSyncEvents(u, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := o.KeyringStatus(p); !errors.Is(err, ErrKeyringDenied) {
		t.Fatalf("offboarded account kept access: %v", err)
	}
	if countRows(t, s, `SELECT count(*) FROM keyring_transfers`) != 0 || countRows(t, s, `SELECT count(*) FROM keyring_wrappers`) != 2 {
		t.Fatal("disablement must clear the transfer and preserve the durable wrappers")
	}
}

func TestKeyringTransferSingleClaimExpiryRevocationAndRestore(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	o := s.DefaultOrg()
	sender := keyringTestSession(t, s, u.ID)
	receiver := keyringTestSession(t, s, u.ID)
	version, device, recovery := uuid.NewString(), keyringTestWrapper("device"), keyringTestWrapper("recovery")
	if err := o.InitializeKeyring(sender, version, device, recovery, keyringTestGrant(t, s, sender, "initialize"), nil); err != nil {
		t.Fatal(err)
	}
	req := KeyringTransferRequest{RecipientKey: strings.Repeat("A", 1622), RequestMAC: strings.Repeat("B", 43)}
	reply := KeyringTransferResponse{SenderKey: "xwing:1", Sealed: strings.Repeat("C", 1559)}
	request := func() string {
		t.Helper()
		id := uuid.NewString()
		if expiry, err := o.RequestKeyringTransfer(receiver, version, id, req, nil); err != nil || expiry <= time.Now().Unix() {
			t.Fatalf("request: %d, %v", expiry, err)
		}
		return id
	}
	approve := func(id string) {
		t.Helper()
		grant := keyringTestGrant(t, s, sender, "approve "+id)
		if err := o.ApproveKeyringTransfer(sender, id, device.ID, "", reply, grant, nil); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("approval without device capability: %v", err)
		}
		if err := o.ApproveKeyringTransfer(sender, id, device.ID, device.DeviceHash, reply, grant, nil); err != nil {
			t.Fatal(err)
		}
	}
	id := request()
	if _, err := o.KeyringTransfer(receiver, id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("same-session approval exposed request: %v", err)
	}
	if seen, err := o.KeyringTransfer(sender, id); err != nil || seen.KeyringTransferRequest != req || seen.SignedIn <= 0 {
		t.Fatalf("approver must see the request and its session: %+v, %v", seen, err)
	}
	approve(id)
	if _, err := o.ClaimKeyringTransfer(sender, id, nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("sender claimed recipient's packet: %v", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			out, err := o.ClaimKeyringTransfer(receiver, id, nil)
			if err == nil && out != reply {
				err = errors.New("claim returned the wrong packet")
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	var claimed, absent int
	for err := range errs {
		switch {
		case err == nil:
			claimed++
		case errors.Is(err, sql.ErrNoRows):
			absent++
		default:
			t.Fatal(err)
		}
	}
	if claimed != 1 || absent != 1 {
		t.Fatalf("claim results: %d claimed, %d absent", claimed, absent)
	}

	id = request()
	approve(id)
	mustExec(t, s, `UPDATE keyring_transfers SET expires_at=1`)
	if _, err := o.ClaimKeyringTransfer(receiver, id, nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expired response returned: %v", err)
	}
	if err := s.DeleteExpiredKeyringTransfers(); err != nil || countRows(t, s, `SELECT count(*) FROM keyring_transfers`) != 0 {
		t.Fatalf("expiry cleanup failed: %v", err)
	}

	id = request()
	approve(id)
	if err := o.RevokeKeyringWrapper(sender, device.ID, keyringTestGrant(t, s, sender, "revoke"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ClaimKeyringTransfer(receiver, id, nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("revoked device approval survived: %v", err)
	}
	request()
	if _, err := s.ApplyRestoredState(time.Now().UTC(), nil); err != nil {
		t.Fatal(err)
	}
	if countRows(t, s, `SELECT count(*) FROM keyring_transfers`) != 0 || countRows(t, s, `SELECT count(*) FROM keyring_wrappers`) != 1 {
		t.Fatal("restore must delete requests and preserve the recovery wrapper")
	}
	if _, err := o.KeyringStatus(receiver); !errors.Is(err, ErrKeyringDenied) {
		t.Fatalf("restored session retained keyring access: %v", err)
	}
	if err := o.DeleteUserWithSyncEvents(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	if countRows(t, s, `SELECT count(*) FROM keyrings`) != 0 || countRows(t, s, `SELECT count(*) FROM keyring_wrappers`) != 0 {
		t.Fatal("user deletion retained keyring ciphertext")
	}
}
