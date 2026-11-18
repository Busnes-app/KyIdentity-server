package api

import (
	"context"
	"errors"

	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/config"
)

// UseBackupFakesForTest makes every server built afterwards deposit through depositor and
// run drill in place of the restore drill, and returns the undo. It exists for the shutdown
// tests in cmd/kyidentity, which cannot reach this package's own test hooks.
func UseBackupFakesForTest(depositor backup.Depositor, drill func(context.Context) error) (undo func()) {
	prevClient, prevDrill := newRecoveryClient, runRestoreDrill
	newRecoveryClient = func(*config.Config) recoveryClient { return depositOnly{depositor} }
	runRestoreDrill = func(ctx context.Context, _, _, _ string, _ []backup.File, _, _ map[string]any, _ backup.RecoveryKey) (*backup.DrillResult, error) {
		if err := drill(ctx); err != nil {
			return nil, err
		}
		return &backup.DrillResult{Passed: true}, nil
	}
	return func() { newRecoveryClient, runRestoreDrill = prevClient, prevDrill }
}

type depositOnly struct{ backup.Depositor }

func (depositOnly) ClaimPairing(context.Context, string, string, string, string) (backup.PairingResult, error) {
	return backup.PairingResult{}, errors.New("pairing is not available in this test")
}
