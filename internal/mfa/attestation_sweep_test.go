package mfa

import (
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

type staticStatus map[string]bool

func (s staticStatus) Revoked(serial string) (bool, bool) { return s[serial], true }

// unknownStatus says revoked but not known, as a stale list would.
type unknownStatus map[string]bool

func (s unknownStatus) Revoked(serial string) (bool, bool) { return s[serial], false }

// repairingStatus re-pairs a device with a new key while the sweep is mid-flight.
type repairingStatus struct {
	staticStatus
	repair func()
}

func (s repairingStatus) Revoked(serial string) (bool, bool) {
	s.repair()
	return s.staticStatus.Revoked(serial)
}

func TestSweepDowngradesRevokedAndUnlocked(t *testing.T) {
	engine, dbStore, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	mk := func(id, boot string, serials []string) {
		dev := &store.NativeDevice{ID: id, UserID: user.ID, DeviceName: id, DeviceIdentifier: id, PublicKey: "pk", IsMFAApprover: true, CanSignOn: true}
		if err := dbStore.UpsertNativeDevice(dev); err != nil {
			t.Fatal(err)
		}
		if ok, err := dbStore.SetNativeDeviceAttestation(id, "pk", "tee", boot, serials, time.Now()); err != nil || !ok {
			t.Fatalf("attest %s: %v %v", id, ok, err)
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
	mk("revoked", "locked-verified", []string{"bb"})
	n, err = engine.SweepAttestations(unknownStatus{"bb": true}, false, func(string, string, string) {})
	if err != nil || n != 0 {
		t.Fatalf("unknown status must not downgrade: n=%d err=%v", n, err)
	}
	if d, _ := dbStore.GetNativeDevice("revoked"); d.AttestedLevel != "tee" {
		t.Fatalf("unknown status downgraded a listed serial: %s", d.AttestedLevel)
	}
}

func TestSweepSkipsDeviceRepairedMidSweep(t *testing.T) {
	engine, dbStore, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	dev := &store.NativeDevice{ID: "d", UserID: user.ID, DeviceName: "d", DeviceIdentifier: "d", PublicKey: "old", IsMFAApprover: true,
		AttestedLevel: "tee", BootState: "locked-verified", AttestationSerials: []string{"bb"}}
	if err := dbStore.UpsertNativeDevice(dev); err != nil {
		t.Fatal(err)
	}
	repair := func() {
		if err := dbStore.UpsertNativeDevice(&store.NativeDevice{ID: "new", UserID: user.ID, DeviceName: "d", DeviceIdentifier: "d", PublicKey: "new", IsMFAApprover: true,
			AttestedLevel: "strongbox", BootState: "locked-verified", AttestationSerials: []string{"cc"}}); err != nil {
			t.Fatal(err)
		}
	}
	audited := 0
	n, err := engine.SweepAttestations(repairingStatus{staticStatus{"bb": true}, repair}, false, func(string, string, string) { audited++ })
	if err != nil || n != 0 || audited != 0 {
		t.Fatalf("n=%d audited=%d err=%v", n, audited, err)
	}
	if d, _ := dbStore.GetNativeDevice("d"); d.PublicKey != "new" || d.AttestedLevel != "strongbox" {
		t.Fatalf("re-paired device downgraded: key=%s level=%s", d.PublicKey, d.AttestedLevel)
	}
}
