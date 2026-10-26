package mfa

import (
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// Codes at Unix 59 for 1/15/16/20 decoded bytes of 0x42, calculated independently
// of the TOTP implementation so its refusal cannot manufacture the test input.
func TestTOTPKeyFloorPreservesLegacyRecords(t *testing.T) {
	for _, tc := range []struct {
		name, secret, code string
		strong             bool
	}{
		{"one byte", "II", "939160", false},
		{"15 bytes", "IJBEEQSCIJBEEQSCIJBEEQSC", "594168", false},
		{"16 bytes", "IJBEEQSCIJBEEQSCIJBEEQSCII", "533835", true},
		{"20 bytes", "IJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSC", "597808", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, database, user, cleanup := setupTestMFAEngine(t)
			defer cleanup()
			setTOTPClock(t, time.Unix(59, 0))
			if ValidateTOTP(tc.secret, tc.code) != tc.strong {
				t.Error("TOTP verification did not enforce decoded key length")
			}
			secret, _, err := e.GenerateTOTPSecret(user.Username, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := e.SaveUserTOTP(user.ID, secret, nil); err != nil {
				t.Fatal(err)
			}
			before, err := database.GetMFAMethod(user.ID, "totp")
			if err != nil {
				t.Fatal(err)
			}
			err = e.SaveUserTOTP(user.ID, tc.secret, nil)
			if (err == nil) != tc.strong {
				t.Errorf("enrollment accepted=%v, want %v", err == nil, tc.strong)
			}
			if !tc.strong {
				retained, err := database.GetMFAMethod(user.ID, "totp")
				if err != nil || retained.EncryptedSecret != before.EncryptedSecret {
					t.Fatal("rejected enrollment replaced the existing secret")
				}
			}
			// Model an already stored legacy record without using new enrollment.
			sealed, err := crypto.Seal(e.encryptionKey, store.SealTOTP, user.ID, []byte(tc.secret))
			if err != nil {
				t.Fatal(err)
			}
			before.EncryptedSecret = sealed
			if err := database.SetMFAMethod(before, nil); err != nil {
				t.Fatal(err)
			}
			ok, err := e.VerifyUserTOTP(user.ID, tc.code)
			if err != nil || ok != tc.strong {
				t.Fatalf("stored-key verification=%v, error=%v", ok, err)
			}
			retained, err := database.GetMFAMethod(user.ID, "totp")
			if err != nil || retained.EncryptedSecret != sealed {
				t.Fatal("verification rewrote the stored secret")
			}
			if tc.strong {
				if ok, err := e.VerifyUserTOTP(user.ID, tc.code); ok || err != nil {
					t.Fatalf("replay accepted=%v, error=%v", ok, err)
				}
			}
		})
	}
}
