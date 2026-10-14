package store

import (
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"
)

func livePairingTokens(t *testing.T, s *Store, userID string, pins ...string) {
	t.Helper()
	for _, pin := range pins {
		if err := s.CreateDevicePairingToken(&DevicePairingToken{ID: userID + pin, UserID: userID, TokenHash: "tok-" + userID + pin, PINHash: pin, ExpiresAt: time.Now().UTC().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPairingPINWithinBudgetStillMatches(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	livePairingTokens(t, s, u.ID, "right")

	for range PairingPINBudget - 1 {
		if got, err := s.MatchDevicePairingPIN(u.ID, "wrong"); err != nil || got != nil {
			t.Fatalf("wrong PIN matched: %+v %v", got, err)
		}
	}
	if got, err := s.MatchDevicePairingPIN(u.ID, "right"); err != nil || got == nil {
		t.Fatalf("right PIN refused within budget: %v", err)
	}
}

func TestPairingPINLockoutBurnsEveryLiveToken(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	other := createTestUser(t, s)
	livePairingTokens(t, s, u.ID, "first", "second")
	livePairingTokens(t, s, other.ID, "others")

	for range PairingPINBudget {
		if _, err := s.MatchDevicePairingPIN(u.ID, "wrong"); err != nil {
			t.Fatal(err)
		}
	}
	for _, pin := range []string{"first", "second"} {
		if got, _ := s.MatchDevicePairingPIN(u.ID, pin); got != nil {
			t.Errorf("PIN %q still redeemable after %d misses", pin, PairingPINBudget)
		}
		if got, _ := s.GetValidDevicePairingToken("tok-" + u.ID + pin); got != nil {
			t.Errorf("QR token %q still live after PIN lockout", pin)
		}
	}
	if got, _ := s.MatchDevicePairingPIN(other.ID, "others"); got == nil {
		t.Error("another user's pairing token was burned")
	}
}

func TestConcurrentPairingPINMissesCannotOverspend(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	livePairingTokens(t, s, u.ID, "right")

	var wg sync.WaitGroup
	for range 4 * PairingPINBudget {
		wg.Go(func() {
			if _, err := s.MatchDevicePairingPIN(u.ID, "wrong"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()

	var failures int
	if err := s.db.QueryRow(`SELECT pin_failures FROM device_pairing_tokens WHERE user_id = ?`, u.ID).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if failures != PairingPINBudget {
		t.Errorf("%d misses were counted, want exactly %d", failures, PairingPINBudget)
	}
	if got, _ := s.MatchDevicePairingPIN(u.ID, "right"); got != nil {
		t.Error("right PIN redeemable after the budget was spent")
	}
}

func TestDeviceMutationsReportUnknownDevice(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	for name, err := range map[string]error{
		"delete":   s.DeleteNativeDevice("missing", u.ID, nil),
		"approver": s.SetNativeDeviceMFAApprover("missing", u.ID, true, nil),
		"sign-on":  s.SetNativeDeviceCanSignOn("missing", u.ID, false, nil),
	} {
		if !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("%s of an unknown device: %v, want sql.ErrNoRows", name, err)
		}
	}
}
