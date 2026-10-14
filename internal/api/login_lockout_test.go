package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func enrolTOTP(t *testing.T, f *stepUpFixture) string {
	t.Helper()
	secret, _, err := f.srv.mfaEngine.GenerateTOTPSecret(f.user.Username, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.srv.mfaEngine.SaveUserTOTP(f.user.ID, secret, nil); err != nil {
		t.Fatal(err)
	}
	return secret
}

func recordFailures(t *testing.T, f *stepUpFixture, n int) {
	t.Helper()
	for range n {
		if _, err := f.store.RecordFailedLogin(f.user.ID); err != nil {
			t.Fatal(err)
		}
	}
}

func assertLocked(t *testing.T, f *stepUpFixture, want bool) {
	t.Helper()
	locked, err := f.store.IsAccountLocked(f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if locked != want {
		t.Fatalf("account locked = %v, want %v", locked, want)
	}
}

// Knowing the password must not fund unlimited TOTP guesses: every login resets nothing,
// and wrong codes spread over fresh mfa tokens add up to the account lockout.
func TestWrongTOTPAcrossFreshLoginsLocksAccount(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	secret := enrolTOTP(t, f)

	first := passwordLogin(t, f.srv, f.user.Username, f.pass)
	spare := passwordLogin(t, f.srv, f.user.Username, f.pass)
	guess := 0
	wrong := func(token string) {
		guess++
		rec := anonPostFrom(t, f.srv, fmt.Sprintf("198.51.100.%d", guess), "/api/auth/mfa/totp/verify", map[string]string{"mfaToken": token, "code": "invalid"})
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid_totp_code") {
			t.Fatalf("wrong code %d: %d %s", guess, rec.Code, rec.Body.String())
		}
	}
	for range mfa.MaxMFAAttempts {
		wrong(first)
	}
	// A correct password between guesses used to clear the counter.
	second := passwordLogin(t, f.srv, f.user.Username, f.pass)
	for range store.MaxFailedLogins - mfa.MaxMFAAttempts {
		wrong(second)
	}
	assertLocked(t, f, true)

	rec := anonPostFrom(t, f.srv, "198.51.100.200", "/api/auth/mfa/totp/verify", map[string]string{"mfaToken": spare, "code": testTOTPCode(t, secret)})
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "account_locked") {
		t.Fatalf("a token issued before the lockout finished login: %d %s", rec.Code, rec.Body.String())
	}
	rec = anonPost(t, f.srv, "/api/auth/login", map[string]string{"username": f.user.Username, "password": f.pass})
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "account_locked") {
		t.Fatalf("locked account accepted its password: %d %s", rec.Code, rec.Body.String())
	}
}

// The counter clears only after the whole login, and the guess that spends a token's last
// attempt may still be the right one.
func TestFailedLoginsClearOnlyAfterFullLogin(t *testing.T) {
	t.Run("password_only", func(t *testing.T) {
		f, cleanup := newStepUpFixture(t)
		defer cleanup()
		recordFailures(t, f, store.MaxFailedLogins-1)
		rec := anonPost(t, f.srv, "/api/auth/login", map[string]string{"username": f.user.Username, "password": f.pass})
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"success":true`) {
			t.Fatalf("password-only login: %d %s", rec.Code, rec.Body.String())
		}
		recordFailures(t, f, 1)
		assertLocked(t, f, false)
	})
	t.Run("totp_on_last_attempt", func(t *testing.T) {
		f, cleanup := newStepUpFixture(t)
		defer cleanup()
		secret := enrolTOTP(t, f)
		token := passwordLogin(t, f.srv, f.user.Username, f.pass)
		for i := range mfa.MaxMFAAttempts - 1 {
			anonPostFrom(t, f.srv, fmt.Sprintf("198.51.100.%d", i+1), "/api/auth/mfa/totp/verify", map[string]string{"mfaToken": token, "code": "invalid"})
		}
		recordFailures(t, f, store.MaxFailedLogins-mfa.MaxMFAAttempts)
		rec := anonPost(t, f.srv, "/api/auth/mfa/totp/verify", map[string]string{"mfaToken": token, "code": testTOTPCode(t, secret)})
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"success":true`) {
			t.Fatalf("correct code on the last attempt: %d %s", rec.Code, rec.Body.String())
		}
		recordFailures(t, f, 1)
		assertLocked(t, f, false)
	})
}

// Concurrent guesses on one token used to pass the attempts check before any of them
// incremented it.
func TestParallelTOTPGuessesStayWithinTokenCap(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	enrolTOTP(t, f)
	token := passwordLogin(t, f.srv, f.user.Username, f.pass)
	// MaxFailedLogins-1 headroom: more than MaxMFAAttempts recorded failures locks it.
	recordFailures(t, f, store.MaxFailedLogins-1-mfa.MaxMFAAttempts)

	const racers = 30
	var wg sync.WaitGroup
	var mu sync.Mutex
	start := make(chan struct{})
	checked := 0
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := anonPostFrom(t, f.srv, fmt.Sprintf("203.0.113.%d", i+1), "/api/auth/mfa/totp/verify", map[string]string{"mfaToken": token, "code": "invalid"})
			if strings.Contains(rec.Body.String(), "invalid_totp_code") {
				mu.Lock()
				checked++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if checked != mfa.MaxMFAAttempts {
		t.Fatalf("%d parallel codes were checked against one token, want exactly %d", checked, mfa.MaxMFAAttempts)
	}
	assertLocked(t, f, false)
}

// Recovery codes have their own limiter; sharing a bucket name with TOTP let one route's
// traffic drain the other and made the effective limit depend on which ran first.
func TestRecoveryCodesUseTheirOwnRateLimit(t *testing.T) {
	srv, _, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	body := map[string]string{"mfaToken": "bogus", "code": "bogus"}
	for i := range 10 {
		if rec := anonPost(t, srv, "/api/auth/mfa/totp/verify", body); rec.Code != http.StatusUnauthorized {
			t.Fatalf("totp request %d: %d %s", i+1, rec.Code, rec.Body.String())
		}
	}
	if rec := anonPost(t, srv, "/api/auth/mfa/totp/verify", body); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("totp limiter did not engage: %d", rec.Code)
	}
	if rec := anonPost(t, srv, "/api/auth/mfa/recovery/verify", body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("recovery verify after draining the totp bucket: %d %s", rec.Code, rec.Body.String())
	}
}

// A saturated Argon2 pool is load, not a wrong password: 503 with Retry-After, and no
// failure is recorded, on the login, unknown-user and step-up paths alike.
func TestArgonBusyIsNotAFailedLogin(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	recordFailures(t, f, store.MaxFailedLogins-1)

	release := sync.OnceFunc(auth.Saturate())
	defer release()
	for name, send := range map[string]func() *httptest.ResponseRecorder{
		"login": func() *httptest.ResponseRecorder {
			return anonPost(t, f.srv, "/api/auth/login", map[string]string{"username": f.user.Username, "password": "wrong-password-123"})
		},
		"unknown_user": func() *httptest.ResponseRecorder {
			return anonPost(t, f.srv, "/api/auth/login", map[string]string{"username": "nobody", "password": "wrong-password-123"})
		},
		"step_up": func() *httptest.ResponseRecorder {
			return f.post(t, "/api/auth/step-up", map[string]string{"password": "wrong-password-123", "operation": "POST /api/user/recovery-codes"}, "")
		},
	} {
		rec := send()
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" || !strings.Contains(rec.Body.String(), `"error":"temporarily_unavailable"`) {
			t.Fatalf("%s while busy: %d %q %s", name, rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
		}
	}
	release()
	assertLocked(t, f, false)
}
