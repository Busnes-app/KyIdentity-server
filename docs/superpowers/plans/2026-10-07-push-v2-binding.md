# Push v2 Binding (Server) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make KyIdentity verify `kyidentity-push-v2` push approvals that bind issuer origin, user, device, challenge, purpose and expiry, and send the phone what it needs to build them.

**Architecture:** The signed message is rebuilt server-side from stored values only. Challenges gain a stored purpose and a second-truncated expiry; the push `data` map carries both; the respond request names its device and only that device's key is tried. v1 is removed.

**Tech Stack:** Go, SQLite store (`internal/store`), `internal/mfa`, `internal/api`, push relay Workers (unchanged).

**Spec:** `../kyauth-android-pushv2/docs/superpowers/specs/2026-10-07-push-mfa-binding-design.md` (kyauth-android branch `feat/push-v2-binding`). Copy its Message, Origin and Golden-vector sections into this repo's `design.md` in Task 4.

## Global Constraints

- Prefix `kyidentity-push-v2`; fields and order exactly as the spec's Message section; `|`-joined, no trailing separator.
- `purpose` is `login` or `step_up`; nothing else.
- Origin normalization per the spec's table; derived from `KYIDENTITY_ISSUER_URL`, never from the request.
- Golden vectors (must appear verbatim in a test):
  `kyidentity-push-v2|https://id.example.com|u-123|d-456|c-789|login|1791331200000|approve|42` and
  `kyidentity-push-v2|https://id.example.com|u-123|d-456|c-789|step_up|1791331200000|deny|`
- No v1 fallback. `kysignon-push-token-v1` and every other device-signature scheme are unchanged.
- Verification failures stay generic: never reveal whether the device, owner, approver flag or signature failed.
- Read the root `AGENTS.md` before editing; CI gates: `gofmt`, `go build ./...`, `go vet ./...`, `go test -race ./...`.

## Review Focus

1. **A respond request naming another user's device.** Expect: generic signature failure, challenge untouched. Pinned in Task 3.
2. **A respond request naming the right device but signed over v1.** Expect: rejected. Pinned in Task 3.
3. **An issuer URL with a path or default port.** Expect: origin per the spec table. Pinned in Task 1.
4. **A challenge whose stored expiry has sub-second precision from an older row.** Expect: the message uses the stored value's milliseconds consistently on create, push and verify. Pinned in Task 2 by asserting `ExpiresAt` has zero nanoseconds after create.
5. **Step-up push.** Expect: purpose `step_up` in the push data and in the verified message. Pinned in Task 2/3.

---

### Task 1: Message and origin

**Files:**
- Modify: `internal/mfa/mfa.go` (`PushResponseMessage`)
- Create: `internal/mfa/push_message_test.go`

**Interfaces:**
- Produces: `func IssuerOrigin(issuerURL string) (string, error)`; `type PushBinding struct { Origin, UserID, DeviceID, ChallengeID, Purpose string; ExpiresAtMS int64 }`; `func PushResponseMessage(b PushBinding, approve bool, selectedDigits string) ([]byte, error)`.

- [ ] **Step 1: Failing tests**

```go
package mfa

import "testing"

func TestPushResponseMessageGoldenVectors(t *testing.T) {
	b := PushBinding{Origin: "https://id.example.com", UserID: "u-123", DeviceID: "d-456", ChallengeID: "c-789", Purpose: "login", ExpiresAtMS: 1791331200000}
	got, err := PushResponseMessage(b, true, "42")
	if err != nil || string(got) != "kyidentity-push-v2|https://id.example.com|u-123|d-456|c-789|login|1791331200000|approve|42" {
		t.Fatalf("approve = %q, %v", got, err)
	}
	b.Purpose = "step_up"
	got, err = PushResponseMessage(b, false, "")
	if err != nil || string(got) != "kyidentity-push-v2|https://id.example.com|u-123|d-456|c-789|step_up|1791331200000|deny|" {
		t.Fatalf("deny = %q, %v", got, err)
	}
}

func TestPushResponseMessageRefusesAmbiguousFields(t *testing.T) {
	ok := PushBinding{Origin: "https://id.example.com", UserID: "u", DeviceID: "d", ChallengeID: "c", Purpose: "login", ExpiresAtMS: 1}
	bad := []PushBinding{}
	for _, mutate := range []func(*PushBinding){
		func(b *PushBinding) { b.UserID = "u|x" },
		func(b *PushBinding) { b.DeviceID = "" },
		func(b *PushBinding) { b.ChallengeID = "" },
		func(b *PushBinding) { b.Origin = "" },
		func(b *PushBinding) { b.Purpose = "session" },
	} {
		b := ok
		mutate(&b)
		bad = append(bad, b)
	}
	for _, b := range bad {
		if _, err := PushResponseMessage(b, true, "42"); err == nil {
			t.Fatalf("accepted %+v", b)
		}
	}
	if _, err := PushResponseMessage(ok, true, "4|2"); err == nil {
		t.Fatal("accepted digits with a separator")
	}
}

func TestIssuerOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://ID.Example.com/":                 "https://id.example.com",
		"https://id.example.com:443":              "https://id.example.com",
		"https://id.example.com:8443/kyidentity":  "https://id.example.com:8443",
		"http://127.0.0.1:8080":                   "http://127.0.0.1:8080",
	} {
		if got, err := IssuerOrigin(in); err != nil || got != want {
			t.Errorf("IssuerOrigin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := IssuerOrigin("not a url"); err == nil {
		t.Error("accepted a non-URL")
	}
}
```

- [ ] **Step 2: Run** `go test ./internal/mfa -run 'PushResponseMessage|IssuerOrigin'` — Expected: compile FAIL (`undefined: PushBinding`).

- [ ] **Step 3: Implement** (replace the v1 `PushResponseMessage`):

```go
// PushBinding is everything a push approval states: which server, account, device, challenge,
// purpose and deadline the user saw. Every value comes from the server's own records.
type PushBinding struct {
	Origin, UserID, DeviceID, ChallengeID, Purpose string
	ExpiresAtMS                                    int64
}

// PushResponseMessage builds the exact byte string a device signs to answer a challenge.
func PushResponseMessage(b PushBinding, approve bool, selectedDigits string) ([]byte, error) {
	if b.Purpose != "login" && b.Purpose != "step_up" {
		return nil, errors.New("unknown push purpose")
	}
	for _, f := range []string{b.Origin, b.UserID, b.DeviceID, b.ChallengeID} {
		if f == "" || strings.Contains(f, "|") {
			return nil, errors.New("invalid push binding field")
		}
	}
	if strings.Contains(selectedDigits, "|") {
		return nil, errors.New("invalid digits")
	}
	verb := "deny"
	if approve {
		verb = "approve"
	}
	return []byte(strings.Join([]string{
		"kyidentity-push-v2", b.Origin, b.UserID, b.DeviceID, b.ChallengeID, b.Purpose,
		strconv.FormatInt(b.ExpiresAtMS, 10), verb, selectedDigits,
	}, "|")), nil
}

// IssuerOrigin normalizes an issuer URL to scheme://host[:port], dropping the default port.
func IssuerOrigin(issuerURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(issuerURL))
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return "", errors.New("issuer URL has no origin")
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	return scheme + "://" + host, nil
}
```

Add imports `net`, `net/url` as needed. Leave `PushTokenRefreshMessage` alone. Existing callers of the old signature break; Task 3 fixes them — run only the new tests now.

- [ ] **Step 4: Run** the same command — Expected: PASS.

### Task 2: Purpose, expiry and push data

**Files:**
- Modify: `internal/store/models.go` (`MFAChallenge` gains `Purpose string`), `internal/store/store.go` (column + insert/select; add the column with the repo's existing migration pattern, default `'login'` for existing rows)
- Modify: `internal/mfa/mfa.go` (`CreatePushChallenge(userID, purpose string)`; `ExpiresAt` truncated with `.Truncate(time.Second)`; `MFAChallengePush` gains `Purpose string` and `ExpiresAtMS int64`; `dispatchPushChallenge` fills them)
- Modify: `internal/mfa/push_relay.go` (data map adds `"purpose"` and `"expiresAtEpochMs"` as decimal string)
- Modify: `internal/api/auth_handlers.go` (login passes `"login"`), `internal/api/stepup_handlers.go` (step-up passes `"step_up"`)
- Test: `internal/mfa/push_relay_test.go`, `internal/mfa/mfa_test.go`

- [ ] **Step 1: Failing tests.** In `push_relay_test.go`, extend the data-map test to assert `data["purpose"] == "login"` and `data["expiresAtEpochMs"]` equals `strconv.FormatInt(ch.ExpiresAt.UnixMilli(), 10)`, while `matchDigits`/`decoyDigits` stay absent. In `mfa_test.go` add a test that `CreatePushChallenge(user, "step_up")` stores purpose `step_up`, that its `ExpiresAt.Nanosecond() == 0`, and that `CreatePushChallenge(user, "session")` returns an error.
- [ ] **Step 2: Run** `go test ./internal/mfa` — Expected: compile/assert FAIL.
- [ ] **Step 3: Implement** the file changes listed above. `CreatePushChallenge` rejects any purpose other than `login`/`step_up`.
- [ ] **Step 4: Run** `go test ./internal/mfa ./internal/store` — Expected: PASS except tests that still call the v1 respond path (fixed in Task 3).

### Task 3: Respond names its device; verify v2 only

**Files:**
- Modify: `internal/mfa/mfa.go` (`Engine` gains `issuerOrigin string` and `func (e *Engine) SetIssuerOrigin(o string)`; `RespondPushChallenge(challengeID, deviceID, selectedDigits string, approve bool, signature string)`; `verifyDeviceSignature` replaced by a single-device check)
- Modify: where the engine is constructed (`main.go` or `cmd/...`, next to `SetAttestor`): `origin, err := mfa.IssuerOrigin(cfg.IssuerURL)`; fail startup on error; `engine.SetIssuerOrigin(origin)`
- Modify: `internal/api/auth_handlers.go` (request struct adds `DeviceID string \`json:"deviceId"\``; empty → 400 `{"error":"invalid_request"}`)
- Modify tests: `internal/mfa/mfa_test.go`, `internal/mfa/security_test.go`, `internal/api/push_auth_test.go`, `internal/api/stepup_factors_test.go` — every signing helper builds the v2 message via `PushResponseMessage(PushBinding{...})` and every request carries `deviceId`.

- [ ] **Step 1: Failing tests** (in `internal/api/push_auth_test.go`, following its existing helpers):
  - `TestPushRespondRejectsAnotherUsersDevice`: user A's challenge, request names user B's approver device and is signed by B's key over a v2 message built with B's ID → 400 `challenge_error`, challenge still `pending`.
  - `TestPushRespondRejectsV1Signature`: correct device, signature over `kysignon-push-v1|<id>|approve|<digits>` → 400, challenge still `pending`.
  - `TestPushRespondRequiresDeviceID`: no `deviceId` → 400.
  - Update `TestPushHappyPathStillWorks` and the step-up push test to sign v2 (purpose `login` / `step_up`) and pass.
- [ ] **Step 2: Run** `go test ./internal/api -run Push` — Expected: FAIL.
- [ ] **Step 3: Implement.** In `RespondPushChallenge`, after the pending/expiry checks: load the named device; require `dev != nil && dev.UserID == ch.UserID && dev.IsMFAApprover && dev.PublicKey != ""`, else return the generic signature error (keep `ErrUnsignedDevice` only for "this user has no enrolled signing device at all", as today). Build the message with `PushBinding{Origin: e.issuerOrigin, UserID: ch.UserID, DeviceID: dev.ID, ChallengeID: ch.ID, Purpose: ch.Purpose, ExpiresAtMS: ch.ExpiresAt.UnixMilli()}`; an error building it is a signature failure. Verify with `crypto.VerifyECDSAP256`. An empty `issuerOrigin` refuses every response.
- [ ] **Step 4: Run** `gofmt -l . && go vet ./... && go test -race ./...` — Expected: clean, PASS.

### Task 4: Docs

**Files:** `AGENTS.md` (Native Device Pairing & Push MFA contract), `design.md` (push flow section), `E2EE_PLAN.md` (the reserved `kysignon-push-v2` note).

- [ ] **Step 1:** In `AGENTS.md`, add a bullet: push approvals are `kyidentity-push-v2` binding issuer origin, user, device, challenge, purpose (`login`|`step_up`) and expiry; the respond request names its device and only that device's key is tried; v1 is not accepted.
- [ ] **Step 2:** In `design.md`, replace the push response format with the spec's Message section, origin table and golden vectors; list the new push data fields `purpose` and `expiresAtEpochMs`.
- [ ] **Step 3:** In `E2EE_PLAN.md`, change the reserved `kysignon-push-v2` to "extends `kyidentity-push-v2` by appending `encryptedClientShare`".
- [ ] **Step 4: Commit** (local only; the controller pushes):

```bash
git add -A
git commit -m "feat(mfa): push v2 binds origin, user, device, purpose and expiry"
```
