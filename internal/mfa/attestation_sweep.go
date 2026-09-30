package mfa

import (
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/attest"
)

// SweepAttestations drops attested devices whose certificates are now revoked or
// whose bootloader no longer satisfies policy. An unknown status list never downgrades.
func (e *Engine) SweepAttestations(status attest.Status, requireLocked bool, audit func(deviceID, userID, reason string)) (int, error) {
	devices, err := e.store.ListAttestedDevices()
	if err != nil {
		return 0, err
	}
	downgraded := 0
	for _, d := range devices {
		reason := ""
		for _, s := range d.AttestationSerials {
			revoked, known := status.Revoked(s)
			if known && revoked {
				reason = "certificate " + s + " revoked"
				break
			}
		}
		if reason == "" && requireLocked && d.BootState != "locked-verified" && d.BootState != "locked-selfsigned" {
			reason = "bootloader not locked (" + d.BootState + ")"
		}
		if reason == "" {
			continue
		}
		// Bound to the key read above: a device re-paired since then keeps its new grade.
		changed, err := e.store.SetNativeDeviceAttestation(d.ID, d.PublicKey, "none", d.BootState, d.AttestationSerials, time.Now())
		if err != nil {
			return downgraded, err
		}
		if !changed {
			continue
		}
		audit(d.ID, d.UserID, reason)
		downgraded++
	}
	return downgraded, nil
}
