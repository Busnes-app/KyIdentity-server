package store

import (
	"testing"
	"time"
)

func pairingDevice(userID, key string) (*NativeDevice, *MFAMethod) {
	return &NativeDevice{ID: "dev-" + key, UserID: userID, DeviceName: "Phone", DeviceIdentifier: "ident", PublicKey: key, IsMFAApprover: true},
		&MFAMethod{ID: "m-" + key, UserID: userID, MethodType: "push", EncryptedSecret: key}
}

func pairingAudit(id string) func(*NativeDevice) *AuditEvent {
	return func(d *NativeDevice) *AuditEvent {
		return &AuditEvent{ID: id, Action: "user.device_paired", TargetID: d.ID, Outcome: "success", CreatedAt: time.Now().UTC()}
	}
}

// Guards single use of pairing tokens: the first registration spends the token and
// enrols the device with its audit row; a replay of the same token enrols nothing.
func TestRegisterNativeDeviceWithPairingTokenSingleUse(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	livePairingTokens(t, s, u.ID, "pin")
	dev, m := pairingDevice(u.ID, "key-1")
	ok, err := s.RegisterNativeDeviceWithPairingToken(u.ID+"pin", dev, m, pairingAudit("pair-1"))
	if err != nil || !ok {
		t.Fatalf("pair = %v, %v", ok, err)
	}
	if count(t, s, `SELECT COUNT(*) FROM native_devices WHERE user_id=? AND public_key='key-1' AND is_mfa_approver AND attested_level='none'`, u.ID) != 1 ||
		count(t, s, `SELECT COUNT(*) FROM mfa_methods WHERE user_id=? AND method_type='push'`, u.ID) != 1 ||
		count(t, s, `SELECT COUNT(*) FROM audit_events WHERE id='pair-1' AND target_id=?`, dev.ID) != 1 {
		t.Fatal("pairing did not enrol device, method and audit together")
	}
	replay, m2 := pairingDevice(u.ID, "attacker-key")
	replay.DeviceIdentifier = "other"
	if ok, err := s.RegisterNativeDeviceWithPairingToken(u.ID+"pin", replay, m2, pairingAudit("pair-2")); err != nil || ok {
		t.Fatalf("replay = %v, %v; want false", ok, err)
	}
	if count(t, s, `SELECT COUNT(*) FROM native_devices WHERE public_key='attacker-key'`)+auditActions(t, s, "user.device_paired") != 1 {
		t.Fatal("replayed token enrolled a device or audited")
	}
	if ok, err := s.ConsumeDevicePairingToken(u.ID + "pin"); err != nil || ok {
		t.Fatal("spent token consumed again", ok, err)
	}
}

// Guards that re-pairing the same device identifier keeps the stored id but replaces
// the key, so the old key can no longer sign.
func TestRegisterNativeDeviceWithPairingTokenRepairKeepsID(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	livePairingTokens(t, s, u.ID, "a", "b")
	first, m := pairingDevice(u.ID, "key-1")
	if ok, err := s.RegisterNativeDeviceWithPairingToken(u.ID+"a", first, m, nil); err != nil || !ok {
		t.Fatal(ok, err)
	}
	again, m2 := pairingDevice(u.ID, "key-2")
	if ok, err := s.RegisterNativeDeviceWithPairingToken(u.ID+"b", again, m2, nil); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if again.ID != first.ID {
		t.Fatalf("re-pair changed id %s -> %s", first.ID, again.ID)
	}
	if count(t, s, `SELECT COUNT(*) FROM native_devices WHERE user_id=?`, u.ID) != 1 || count(t, s, `SELECT COUNT(*) FROM native_devices WHERE public_key='key-1'`) != 0 {
		t.Fatal("re-pair kept the old key")
	}
}

// Guards expiry and rollback: an expired token pairs nothing, and an invalid grade or an
// audit failure rolls back the spend so the token stays usable.
func TestRegisterNativeDeviceWithPairingTokenRefusals(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	livePairingTokens(t, s, u.ID, "old", "live")
	mustExec(t, s, `UPDATE device_pairing_tokens SET expires_at=? WHERE id=?`, time.Now().UTC().Add(-time.Second), u.ID+"old")
	dev, m := pairingDevice(u.ID, "key")
	if ok, err := s.RegisterNativeDeviceWithPairingToken(u.ID+"old", dev, m, nil); err != nil || ok {
		t.Fatalf("expired token = %v, %v", ok, err)
	}
	if ok, err := s.ConsumeDevicePairingToken(u.ID + "old"); err != nil || ok {
		t.Fatal("expired token consumed", ok, err)
	}
	dev, m = pairingDevice(u.ID, "key")
	dev.AttestedLevel = "forged"
	if _, err := s.RegisterNativeDeviceWithPairingToken(u.ID+"live", dev, m, nil); err == nil {
		t.Fatal("invalid attestation level accepted")
	}
	dev, m = pairingDevice(u.ID, "key")
	poisoned := poisonedAudit(t, s, "user.device_paired", "")
	if _, err := s.RegisterNativeDeviceWithPairingToken(u.ID+"live", dev, m, func(*NativeDevice) *AuditEvent { return poisoned }); err == nil {
		t.Fatal("pairing ignored audit failure")
	}
	if count(t, s, `SELECT COUNT(*) FROM native_devices`)+count(t, s, `SELECT COUNT(*) FROM mfa_methods`) != 0 {
		t.Fatal("failed pairing left a device or method")
	}
	if tok, err := s.GetValidDevicePairingToken("tok-" + u.ID + "live"); err != nil || tok == nil {
		t.Fatal("failed pairing spent the token", err)
	}
	if ok, err := s.ConsumeDevicePairingToken(u.ID + "live"); err != nil || !ok {
		t.Fatal("live token not consumable", ok, err)
	}
	if tok, _ := s.GetValidDevicePairingToken("tok-" + u.ID + "live"); tok != nil {
		t.Fatal("consumed token still valid")
	}
}
