package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
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

	// Past the password the caller already knows the account exists, so this may say locked.
	rec := anonPostFrom(t, f.srv, "198.51.100.200", "/api/auth/mfa/totp/verify", map[string]string{"mfaToken": spare, "code": testTOTPCode(t, secret)})
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "account_locked") {
		t.Fatalf("a token issued before the lockout finished login: %d %s", rec.Code, rec.Body.String())
	}
	rec = anonPost(t, f.srv, "/api/auth/login", map[string]string{"username": f.user.Username, "password": f.pass})
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid_credentials") {
		t.Fatalf("locked account accepted its password: %d %s", rec.Code, rec.Body.String())
	}
}

// Before the password is proven, a locked account, an inactive one, an unknown name and a
// foreign authorization interaction must all read as a wrong password; only audit differs.
func TestLoginRefusalsAreIndistinguishable(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	other := func(name, status string) *store.User {
		u := &store.User{ID: name + "-" + f.user.ID, Username: name, Email: name + "@stepup.test",
			PasswordHash: f.user.PasswordHash, Role: "user", Status: status}
		if err := f.store.CreateUser(u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	locked := other("locked-user", "active")
	for range store.MaxFailedLogins {
		if _, err := f.store.RecordFailedLogin(locked.ID); err != nil {
			t.Fatal(err)
		}
	}
	disabled := other("disabled-user", "disabled")

	cases := map[string]map[string]string{
		"wrong_password":      {"username": f.user.Username, "password": "wrong-password-123"},
		"unknown_user":        {"username": "nobody-here", "password": "wrong-password-123"},
		"locked_right_pass":   {"username": locked.Username, "password": f.pass},
		"disabled_right_pass": {"username": disabled.Username, "password": f.pass},
		"bad_interaction":     {"username": f.user.Username, "password": "wrong-password-123", "interaction": "not-a-real-interaction"},
	}
	var want string
	ip := 0
	for name, body := range cases {
		ip++
		rec := anonPostFrom(t, f.srv, fmt.Sprintf("198.51.100.%d", ip), "/api/auth/login", body)
		got := fmt.Sprintf("%d %s", rec.Code, rec.Body.String())
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %s", name, got)
		}
		if want == "" {
			want = got
		} else if got != want {
			t.Errorf("%s answered %q, others %q", name, got, want)
		}
	}

	reasons := map[string]bool{}
	for _, row := range auditRows(t, f.store, "auth.login") {
		var details struct{ Reason string }
		_ = json.Unmarshal([]byte(row.DetailsJSON), &details)
		reasons[row.Outcome+":"+details.Reason] = true
	}
	for _, r := range []string{"denied:account_locked", "denied:user_disabled", "failure:user_not_found", "failure:invalid_password"} {
		if !reasons[r] {
			t.Errorf("audit lacks %s: %v", r, reasons)
		}
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

// Legacy unsalted recovery codes keep working, and /api/auth/me tells the user to regenerate.
func TestMeFlagsLegacyRecoveryCodes(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	flag := func() string {
		t.Helper()
		var me struct {
			Legacy *bool `json:"recoveryCodesNeedRegeneration"`
		}
		rec := f.do(t, "GET", "/api/auth/me", "")
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &me) != nil || me.Legacy == nil {
			t.Fatalf("me: %d %s", rec.Code, rec.Body.String())
		}
		return fmt.Sprint(*me.Legacy)
	}
	if err := f.store.ReplaceRecoveryCodes(f.user.ID, []store.RecoveryCode{{ID: "legacy", UserID: f.user.ID, CodeHash: crypto.HashSHA256("ABCD2345")}}, nil); err != nil {
		t.Fatal(err)
	}
	if got := flag(); got != "true" {
		t.Fatalf("legacy codes flagged %s", got)
	}
	if _, err := f.srv.mfaEngine.GenerateRecoveryCodes(f.user.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got := flag(); got != "false" {
		t.Fatalf("regenerated codes flagged %s", got)
	}
}
