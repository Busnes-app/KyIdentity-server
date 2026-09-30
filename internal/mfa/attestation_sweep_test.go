package mfa

import (
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

type staticStatus map[string]bool

func (s staticStatus) Revoked(serial string) (bool, bool) { return s[serial], true }

type unknownStatus struct{}

func (unknownStatus) Revoked(string) (bool, bool) { return false, false }

func TestSweepDowngradesRevokedAndUnlocked(t *testing.T) {
	engine, dbStore, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	mk := func(id, boot string, serials []string) {
		dev := &store.NativeDevice{ID: id, UserID: user.ID, DeviceName: id, DeviceIdentifier: id, PublicKey: "pk", IsMFAApprover: true, CanSignOn: true}
		if err := dbStore.UpsertNativeDevice(dev); err != nil {
			t.Fatal(err)
		}
		if err := dbStore.SetNativeDeviceAttestation(id, "tee", boot, serials, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	mk("ok", "locked-verified", []string{"aa"})
	mk("revoked", "locked-verified", []string{"bb"})
	mk("unlocked", "unlocked", []string{"cc"})
	var reasons []string
	n, err := engine.SweepAttestations(staticStatus{"bb": true}, true, func(id, uid, reason string) { reasons = append(reasons, id+":"+reason) })
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	for id, want := range map[string]string{"ok": "tee", "revoked": "none", "unlocked": "none"} {
		if d, _ := dbStore.GetNativeDevice(id); d.AttestedLevel != want {
			t.Fatalf("%s: %s", id, d.AttestedLevel)
		}
	}
	if len(reasons) != 2 {
		t.Fatalf("reasons %v", reasons)
	}
	// status unknown: nothing is downgraded (fail safe for the sweep; registration is the strict path)
	n, _ = engine.SweepAttestations(unknownStatus{}, false, func(string, string, string) {})
	if n != 0 {
		t.Fatal("unknown status must not downgrade")
	}
}
