# KyIdentity WebAuthn Passkeys Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add WebAuthn passkeys to KyIdentity as a second authentication factor, so KyAuth (and any other passkey provider) can satisfy MFA without a merge between KyIdentity and KyPassword.

**Architecture:** A new `internal/webauthn` package verifies ES256 assertions using only stdlib. Credentials and single-use challenges live in two new SQLite tables. Enrollment reuses the existing step-up grant machinery; authentication plugs into the existing `mfaToken` flow exactly as TOTP and recovery codes do, so `Login` gains one method type and nothing else changes.

**Tech Stack:** Go 1.26.5 stdlib (`crypto/ecdsa`, `crypto/x509`, `crypto/sha256`, `encoding/binary`, `encoding/base64`, `encoding/json`), SQLite via `modernc.org/sqlite`, React 19 + TypeScript + Vite, browser WebAuthn API.

**Spec:** `design.md` (sections 2, 8, 9), plus the architecture decision recorded in "Design decisions" below. This plan implements the passkey half of the KyIdentity/KyPassword separation analysis; the companion plans are listed at the end.

## Global Constraints

- Go 1.26.5 (`go.mod`). **No new Go dependencies.** The three direct deps stay: `modernc.org/sqlite`, `golang.org/x/crypto`, `github.com/google/uuid`.
- **No new npm dependencies.** WebAuthn is a browser platform API.
- Backend gates, all of which run in CI (`.github/workflows/ci.yml`): `gofmt -l .` must be empty, `go build ./...`, `go vet ./...`, `govulncheck ./...`, `go test -race -count=1 ./...`.
- Frontend gates: `npm test` and `npm run build` (which is `tsc && vite build`, so it is the typecheck gate) in `web/`.
- Never log or audit-detail a challenge, signature, credential public key, session token or step-up token. Audit details carry IDs and boolean flags only.
- Every state-mutating endpoint goes through the existing CSRF middleware and a named rate-limit bucket.
- Destructive account operations require a step-up grant (`requireStepUp` / `consumeStepUp` in `internal/api/stepup.go`).
- Origin and RP ID are derived from `cfg.IssuerURL`. No new environment variable.
- UI text uses the KySecurity Patina theme and existing class names; the word is "passkey" (lowercase) in user-visible copy.

---

## Design decisions

These are locked. Do not relitigate them mid-implementation; if one turns out to be wrong, stop and raise it.

**1. Second factor only, not passwordless.** A passkey is offered alongside TOTP and push, after the password succeeds. This reuses `resolveMFAToken`/`spendMFAToken` unchanged and needs no discoverable-credential or usernameless handling. Passwordless is a later plan; mark the deferral in code with `ponytail: passwordless passkey login needs discoverable credentials and a userHandle lookup — see companion plan 1b`.

**2. No CBOR parser.** The browser exposes `AuthenticatorAttestationResponse.getPublicKey()` (SPKI DER, readable by `crypto/x509.ParsePKIXPublicKey`) and `.getAuthenticatorData()` (raw bytes). We send those two instead of `attestationObject`, so no CBOR decoder is needed anywhere.

  Why this is safe: KyIdentity does not verify attestation, so it never trusts the authenticator's identity claim regardless. A malicious client could submit a public key that did not come from the authenticator whose authData it also submitted — but it would be registering that credential against its own already-authenticated, step-up-gated session, and every later assertion is bound to the stored key by signature verification. The trust boundary is unchanged.

  `getPublicKey()` returns `null` for algorithms the browser cannot export. We request ES256 only, which every browser can export.

**3. ES256 (`-7`) only.** `pubKeyCredParams` requests ES256 and nothing else. RSA passkeys are rare, and supporting them means a second verification path for no user we have.

**4. Backup flags are recorded, not enforced.** The BE/BS bits in authenticator data tell us whether a credential is synced to a provider cloud. We store both, show "synced" vs "device-bound" in the UI, and put the flag in the enrollment audit event. We do **not** reject synced passkeys — that would break iCloud Keychain and Windows Hello for every user to solve a problem that belongs one layer down. The rule that KyIdentity login credentials must live in KyAuth's device-local `totp_vault.kdbx` rather than the KyPassword-synced `passwords_vault.kdbx` is enforced in KyAuth (companion plan 2), where the vault choice actually happens.

**5. Enrolling a passkey does not revoke sibling sessions.** `EnableTOTP` revokes them because it *replaces* the account's single TOTP factor. Passkeys are additive and a user may enroll several, so revoking every other session on each enrollment is hostile. The enrollment is audited and requires a step-up grant, which is the control that matters.

**6. Sign-count clone detection is enforced when the authenticator provides one.** Many platform authenticators always report `0`. Rule: if the stored count and the presented count are both `0`, accept. Otherwise the presented count must be strictly greater than the stored count.

---

## File structure

**Create:**
- `internal/webauthn/webauthn.go` — pure verification. No database, no HTTP. Parses authenticator data, verifies client data and ES256 assertions, derives RP ID and origin from the issuer URL.
- `internal/webauthn/webauthn_test.go` — table-driven tests over a locally generated P-256 key.
- `internal/api/webauthn_handlers.go` — the six endpoints.
- `internal/api/webauthn_test.go` — endpoint tests, including a helper that mints real assertions.
- `web/src/webauthn.ts` — base64url codecs and the two ceremony wrappers.
- `web/src/webauthn.test.ts` — codec round-trip and option-shaping tests.

**Modify:**
- `internal/store/models.go` — two structs.
- `internal/store/store.go` — two tables in `migrate()`, the CRUD methods, and the two MFA-wipe paths.
- `internal/api/server.go` — routes.
- `internal/api/auth_handlers.go:139-152` — `Login` advertises `webauthn` when the user has a credential.
- `cmd/kyidentity/main.go:148-160` — housekeeping deletes expired challenges.
- `web/src/types.ts` — `Passkey` interface.
- `web/src/components/DeviceSettings.tsx` — enroll, list, delete.
- `web/src/components/LoginView.tsx` — `webauthn` MFA mode.
- `README.md`, `design.md`, `AGENTS.md` — documentation.

---

## Task 1: The `webauthn` verification package

**Files:**
- Create: `internal/webauthn/webauthn.go`
- Test: `internal/webauthn/webauthn_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `webauthn.ParseAuthenticatorData([]byte) (AuthenticatorData, error)`; `webauthn.AuthenticatorData` with fields `RPIDHash []byte`, `Flags byte`, `SignCount uint32` and methods `UserPresent() bool`, `UserVerified() bool`, `BackupEligible() bool`, `BackupState() bool`; `webauthn.ParseES256PublicKey([]byte) (*ecdsa.PublicKey, error)`; `webauthn.VerifyClientData(raw []byte, wantType, wantChallenge, wantOrigin string) error`; `webauthn.VerifyRegistration(RegistrationInput) (AuthenticatorData, error)`; `webauthn.VerifyAssertion(AssertionInput) (AuthenticatorData, error)`; `webauthn.RPIDFromIssuer(string) (rpID string, origin string, err error)`.

- [ ] **Step 1: Write the failing test**

Create `internal/webauthn/webauthn_test.go`:

```go
package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

const testRPID = "auth.example.com"
const testOrigin = "https://auth.example.com"

// authData builds a 37-byte authenticator data header for rpID with the given flags and
// signature counter. Registration responses append attested credential data after it;
// nothing this package does reads past byte 37, so the tests do not synthesise it.
func authData(rpID string, flags byte, count uint32) []byte {
	h := sha256.Sum256([]byte(rpID))
	b := make([]byte, 37)
	copy(b, h[:])
	b[32] = flags
	binary.BigEndian.PutUint32(b[33:37], count)
	return b
}

func clientDataJSON(t *testing.T, typ, challenge, origin string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"type":        typ,
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	return b
}

func testKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return key, spki
}

// signAssertion produces the signature a real authenticator would: over the authenticator
// data concatenated with the SHA-256 of the client data JSON.
func signAssertion(t *testing.T, key *ecdsa.PrivateKey, ad, cdj []byte) []byte {
	t.Helper()
	cdHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	return sig
}

func TestParseAuthenticatorDataFlags(t *testing.T) {
	ad, err := ParseAuthenticatorData(authData(testRPID, FlagUserPresent|FlagUserVerified|FlagBackupEligible|FlagBackupState, 7))
	if err != nil {
		t.Fatalf("ParseAuthenticatorData: %v", err)
	}
	if !ad.UserPresent() || !ad.UserVerified() || !ad.BackupEligible() || !ad.BackupState() {
		t.Fatalf("expected all four flags set, got %#x", ad.Flags)
	}
	if ad.SignCount != 7 {
		t.Fatalf("SignCount = %d, want 7", ad.SignCount)
	}
}

func TestParseAuthenticatorDataRejectsShortInput(t *testing.T) {
	if _, err := ParseAuthenticatorData(make([]byte, 36)); err == nil {
		t.Fatal("expected an error for 36 bytes of authenticator data")
	}
}

func TestVerifyAssertionAcceptsGenuineSignature(t *testing.T) {
	key, spki := testKey(t)
	ad := authData(testRPID, FlagUserPresent|FlagUserVerified, 5)
	cdj := clientDataJSON(t, "webauthn.get", "Q0hBTExFTkdF", testOrigin)

	got, err := VerifyAssertion(AssertionInput{
		AuthenticatorData: ad,
		ClientDataJSON:    cdj,
		Signature:         signAssertion(t, key, ad, cdj),
		PublicKeySPKI:     spki,
		Challenge:         "Q0hBTExFTkdF",
		Origin:            testOrigin,
		RPID:              testRPID,
		StoredSignCount:   4,
	})
	if err != nil {
		t.Fatalf("VerifyAssertion: %v", err)
	}
	if got.SignCount != 5 {
		t.Fatalf("SignCount = %d, want 5", got.SignCount)
	}
}

func TestVerifyAssertionRejects(t *testing.T) {
	key, spki := testKey(t)
	otherKey, _ := testKey(t)

	base := func() AssertionInput {
		ad := authData(testRPID, FlagUserPresent, 5)
		cdj := clientDataJSON(t, "webauthn.get", "Q0hBTExFTkdF", testOrigin)
		return AssertionInput{
			AuthenticatorData: ad,
			ClientDataJSON:    cdj,
			Signature:         signAssertion(t, key, ad, cdj),
			PublicKeySPKI:     spki,
			Challenge:         "Q0hBTExFTkdF",
			Origin:            testOrigin,
			RPID:              testRPID,
			StoredSignCount:   4,
		}
	}

	cases := map[string]func(*AssertionInput){
		"wrong challenge": func(in *AssertionInput) { in.Challenge = "T1RIRVJT" },
		"wrong origin":    func(in *AssertionInput) { in.Origin = "https://evil.example.com" },
		"wrong rp id":     func(in *AssertionInput) { in.RPID = "evil.example.com" },
		"wrong key": func(in *AssertionInput) {
			spki, err := x509.MarshalPKIXPublicKey(&otherKey.PublicKey)
			if err != nil {
				t.Fatalf("MarshalPKIXPublicKey: %v", err)
			}
			in.PublicKeySPKI = spki
		},
		"tampered authenticator data": func(in *AssertionInput) {
			in.AuthenticatorData = authData(testRPID, FlagUserPresent|FlagUserVerified, 5)
		},
		"replayed sign count": func(in *AssertionInput) { in.StoredSignCount = 5 },
		"regressed sign count": func(in *AssertionInput) { in.StoredSignCount = 9 },
		"user not present": func(in *AssertionInput) {
			ad := authData(testRPID, 0x00, 5)
			in.AuthenticatorData = ad
			in.Signature = signAssertion(t, key, ad, in.ClientDataJSON)
		},
		"wrong ceremony type": func(in *AssertionInput) {
			cdj := clientDataJSON(t, "webauthn.create", "Q0hBTExFTkdF", testOrigin)
			in.ClientDataJSON = cdj
			in.Signature = signAssertion(t, key, in.AuthenticatorData, cdj)
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := base()
			mutate(&in)
			if _, err := VerifyAssertion(in); err == nil {
				t.Fatalf("expected VerifyAssertion to reject %s", name)
			}
		})
	}
}

func TestVerifyAssertionAcceptsBothCountersZero(t *testing.T) {
	key, spki := testKey(t)
	ad := authData(testRPID, FlagUserPresent, 0)
	cdj := clientDataJSON(t, "webauthn.get", "Q0hBTExFTkdF", testOrigin)

	if _, err := VerifyAssertion(AssertionInput{
		AuthenticatorData: ad,
		ClientDataJSON:    cdj,
		Signature:         signAssertion(t, key, ad, cdj),
		PublicKeySPKI:     spki,
		Challenge:         "Q0hBTExFTkdF",
		Origin:            testOrigin,
		RPID:              testRPID,
		StoredSignCount:   0,
	}); err != nil {
		t.Fatalf("an authenticator that never increments its counter must be accepted: %v", err)
	}
}

func TestVerifyRegistrationRequiresUserPresence(t *testing.T) {
	_, spki := testKey(t)
	cdj := clientDataJSON(t, "webauthn.create", "Q0hBTExFTkdF", testOrigin)

	in := RegistrationInput{
		AuthenticatorData: authData(testRPID, FlagUserPresent, 0),
		ClientDataJSON:    cdj,
		PublicKeySPKI:     spki,
		Challenge:         "Q0hBTExFTkdF",
		Origin:            testOrigin,
		RPID:              testRPID,
	}
	if _, err := VerifyRegistration(in); err != nil {
		t.Fatalf("VerifyRegistration: %v", err)
	}

	in.AuthenticatorData = authData(testRPID, 0x00, 0)
	if _, err := VerifyRegistration(in); err == nil {
		t.Fatal("expected registration without the user-present bit to be rejected")
	}
}

func TestVerifyRegistrationRejectsNonES256Key(t *testing.T) {
	cdj := clientDataJSON(t, "webauthn.create", "Q0hBTExFTkdF", testOrigin)
	if _, err := VerifyRegistration(RegistrationInput{
		AuthenticatorData: authData(testRPID, FlagUserPresent, 0),
		ClientDataJSON:    cdj,
		PublicKeySPKI:     []byte("not a key"),
		Challenge:         "Q0hBTExFTkdF",
		Origin:            testOrigin,
		RPID:              testRPID,
	}); err == nil {
		t.Fatal("expected an unparseable public key to be rejected")
	}
}

func TestRPIDFromIssuer(t *testing.T) {
	cases := []struct {
		issuer, rpID, origin string
	}{
		{"https://auth.example.com", "auth.example.com", "https://auth.example.com"},
		{"https://auth.example.com/", "auth.example.com", "https://auth.example.com"},
		{"http://localhost:5867", "localhost", "http://localhost:5867"},
	}
	for _, c := range cases {
		rpID, origin, err := RPIDFromIssuer(c.issuer)
		if err != nil {
			t.Fatalf("RPIDFromIssuer(%q): %v", c.issuer, err)
		}
		if rpID != c.rpID || origin != c.origin {
			t.Fatalf("RPIDFromIssuer(%q) = %q, %q; want %q, %q", c.issuer, rpID, origin, c.rpID, c.origin)
		}
	}

	if _, _, err := RPIDFromIssuer("not a url"); err == nil {
		t.Fatal("expected an error for an issuer URL with no host")
	}
}

func TestVerifyClientDataRejectsBase64Variants(t *testing.T) {
	// The challenge is compared as the exact base64url string the browser echoes. A
	// padded or standard-alphabet variant of the same bytes is a different string and
	// must not be accepted, or a lookup keyed on the challenge could miss.
	cdj := clientDataJSON(t, "webauthn.get", "Q0hBTExFTkdF", testOrigin)
	padded := base64.StdEncoding.EncodeToString([]byte("CHALLENGE"))
	if !strings.HasSuffix(padded, "=") {
		t.Skip("test vector no longer produces padding")
	}
	if err := VerifyClientData(cdj, "webauthn.get", padded, testOrigin); err == nil {
		t.Fatal("expected a padded challenge encoding to be rejected")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/webauthn/...`
Expected: FAIL — the package does not exist (`no Go files in .../internal/webauthn`).

- [ ] **Step 3: Write the implementation**

Create `internal/webauthn/webauthn.go`:

```go
// Package webauthn implements the subset of WebAuthn Level 2 that KyIdentity needs: verifying
// an ES256 assertion from a registered credential, and reading the authenticator data that
// accompanies registration.
//
// It deliberately parses no CBOR. The browser exposes the credential public key in SPKI form
// (AuthenticatorAttestationResponse.getPublicKey) and the raw authenticator data
// (getAuthenticatorData), both of which the standard library reads. KyIdentity does not verify
// attestation, so re-deriving those two values from the attestation object ourselves would
// buy no property we do not already have.
package webauthn

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
)

// Authenticator data flag bits (WebAuthn Level 2, section 6.1).
const (
	FlagUserPresent            byte = 0x01
	FlagUserVerified           byte = 0x04
	FlagBackupEligible         byte = 0x08
	FlagBackupState            byte = 0x10
	FlagAttestedCredentialData byte = 0x40
)

// authDataHeaderLen is the fixed prefix: 32-byte RP ID hash, 1 flag byte, 4-byte counter.
const authDataHeaderLen = 37

type AuthenticatorData struct {
	RPIDHash  []byte
	Flags     byte
	SignCount uint32
}

func (a AuthenticatorData) UserPresent() bool    { return a.Flags&FlagUserPresent != 0 }
func (a AuthenticatorData) UserVerified() bool   { return a.Flags&FlagUserVerified != 0 }
func (a AuthenticatorData) BackupEligible() bool { return a.Flags&FlagBackupEligible != 0 }
func (a AuthenticatorData) BackupState() bool    { return a.Flags&FlagBackupState != 0 }

// ParseAuthenticatorData reads the fixed header. Attested credential data and extensions
// follow it during registration; nothing here reads past the header.
func ParseAuthenticatorData(b []byte) (AuthenticatorData, error) {
	if len(b) < authDataHeaderLen {
		return AuthenticatorData{}, fmt.Errorf("authenticator data is %d bytes, need at least %d", len(b), authDataHeaderLen)
	}
	return AuthenticatorData{
		RPIDHash:  b[:32],
		Flags:     b[32],
		SignCount: binary.BigEndian.Uint32(b[33:authDataHeaderLen]),
	}, nil
}

// ParseES256PublicKey reads a DER SPKI public key and rejects anything that is not P-256.
func ParseES256PublicKey(spki []byte) (*ecdsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("credential public key is not a valid SPKI key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("credential public key is not an ECDSA key")
	}
	if pub.Curve != elliptic256() {
		return nil, errors.New("credential public key is not on P-256")
	}
	return pub, nil
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// VerifyClientData checks the three fields that bind a ceremony to this server and this
// request. The challenge is compared as the exact base64url string the server issued: a
// re-encoding of the same bytes is a different string, and accepting it would let a caller
// present a challenge the store cannot match.
func VerifyClientData(raw []byte, wantType, wantChallenge, wantOrigin string) error {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return fmt.Errorf("client data is not valid JSON: %w", err)
	}
	if cd.Type != wantType {
		return fmt.Errorf("client data type is %q, want %q", cd.Type, wantType)
	}
	if subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(wantChallenge)) != 1 {
		return errors.New("client data challenge does not match the issued challenge")
	}
	if subtle.ConstantTimeCompare([]byte(cd.Origin), []byte(wantOrigin)) != 1 {
		return fmt.Errorf("client data origin %q is not this server's origin", cd.Origin)
	}
	return nil
}

type RegistrationInput struct {
	AuthenticatorData []byte
	ClientDataJSON    []byte
	PublicKeySPKI     []byte
	Challenge         string
	Origin            string
	RPID              string
}

// VerifyRegistration checks a credential creation response. Attestation is not verified:
// KyIdentity accepts any authenticator, so the statement would be recorded and never acted on.
func VerifyRegistration(in RegistrationInput) (AuthenticatorData, error) {
	if err := VerifyClientData(in.ClientDataJSON, "webauthn.create", in.Challenge, in.Origin); err != nil {
		return AuthenticatorData{}, err
	}
	ad, err := parseAndBind(in.AuthenticatorData, in.RPID)
	if err != nil {
		return AuthenticatorData{}, err
	}
	if _, err := ParseES256PublicKey(in.PublicKeySPKI); err != nil {
		return AuthenticatorData{}, err
	}
	return ad, nil
}

type AssertionInput struct {
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
	PublicKeySPKI     []byte
	Challenge         string
	Origin            string
	RPID              string
	StoredSignCount   uint32
}

// VerifyAssertion checks a credential assertion end to end and returns the authenticator
// data it verified, so the caller can persist the new signature counter and backup state.
func VerifyAssertion(in AssertionInput) (AuthenticatorData, error) {
	if err := VerifyClientData(in.ClientDataJSON, "webauthn.get", in.Challenge, in.Origin); err != nil {
		return AuthenticatorData{}, err
	}
	ad, err := parseAndBind(in.AuthenticatorData, in.RPID)
	if err != nil {
		return AuthenticatorData{}, err
	}

	pub, err := ParseES256PublicKey(in.PublicKeySPKI)
	if err != nil {
		return AuthenticatorData{}, err
	}

	cdHash := sha256.Sum256(in.ClientDataJSON)
	signed := make([]byte, 0, len(in.AuthenticatorData)+len(cdHash))
	signed = append(signed, in.AuthenticatorData...)
	signed = append(signed, cdHash[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(pub, digest[:], in.Signature) {
		return AuthenticatorData{}, errors.New("assertion signature is not valid for this credential")
	}

	// A counter that fails to advance means the authenticator was cloned, or the response
	// was replayed. Authenticators that never count report zero forever; only those are
	// exempt (WebAuthn Level 2, section 6.1.1).
	if !(ad.SignCount == 0 && in.StoredSignCount == 0) && ad.SignCount <= in.StoredSignCount {
		return AuthenticatorData{}, fmt.Errorf("signature counter did not advance: got %d, stored %d", ad.SignCount, in.StoredSignCount)
	}

	return ad, nil
}

// parseAndBind reads the authenticator data and confirms it was produced for this RP with
// the user physically present.
func parseAndBind(raw []byte, rpID string) (AuthenticatorData, error) {
	ad, err := ParseAuthenticatorData(raw)
	if err != nil {
		return AuthenticatorData{}, err
	}
	want := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(ad.RPIDHash, want[:]) != 1 {
		return AuthenticatorData{}, errors.New("authenticator data was produced for a different relying party")
	}
	if !ad.UserPresent() {
		return AuthenticatorData{}, errors.New("authenticator did not report user presence")
	}
	return ad, nil
}

// RPIDFromIssuer derives the relying party ID and the exact origin from the configured
// issuer URL. The RP ID is the registrable host without the port; the origin keeps it,
// because that is what the browser puts in client data.
func RPIDFromIssuer(issuerURL string) (string, string, error) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return "", "", fmt.Errorf("issuer URL is not parseable: %w", err)
	}
	if u.Scheme == "" || u.Hostname() == "" {
		return "", "", fmt.Errorf("issuer URL %q has no scheme or host", issuerURL)
	}
	return u.Hostname(), u.Scheme + "://" + u.Host, nil
}
```

Add the small helper that keeps the curve check readable, at the bottom of the same file:

```go
// elliptic256 exists so ParseES256PublicKey reads as a single comparison.
func elliptic256() elliptic.Curve { return elliptic.P256() }
```

and add `"crypto/elliptic"` to the import block.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/webauthn/...`
Expected: PASS, all tests.

- [ ] **Step 5: Format, vet, commit**

```bash
gofmt -w internal/webauthn
go vet ./internal/webauthn/...
git add internal/webauthn
git commit -m "feat(webauthn): add stdlib ES256 assertion verification"
```

---

## Task 2: Credential and challenge storage

**Files:**
- Modify: `internal/store/models.go`
- Modify: `internal/store/store.go` (`migrate()` at line 51; `DeleteUserMFAMethods` at line 1369; `ResetUserMFA` at line 1973)
- Test: `internal/store/store_test.go`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `store.WebAuthnCredential`, `store.WebAuthnChallenge`, and these `*Store` methods — `CreateWebAuthnChallenge(*WebAuthnChallenge) error`, `ConsumeWebAuthnChallenge(challenge, purpose, userID string) (bool, error)`, `DeleteExpiredWebAuthnChallenges() error`, `CreateWebAuthnCredential(*WebAuthnCredential, *AuditEvent) error`, `ListUserWebAuthnCredentials(userID string) ([]WebAuthnCredential, error)`, `GetWebAuthnCredential(userID, credentialID string) (*WebAuthnCredential, error)`, `RecordWebAuthnUse(id string, signCount uint32, backupState bool, usedAt time.Time) error`, `DeleteWebAuthnCredential(id, userID string, audit *AuditEvent) (bool, error)`.

- [ ] **Step 1: Write the failing test**

Append to `internal/store/store_test.go`:

```go
func TestWebAuthnChallengeIsSingleUse(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()

	user := createTestUser(t, s)
	ch := &WebAuthnChallenge{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Challenge: "Q0hBTExFTkdF",
		Purpose:   "authenticate",
		ExpiresAt: time.Now().UTC().Add(2 * time.Minute),
	}
	if err := s.CreateWebAuthnChallenge(ch); err != nil {
		t.Fatalf("CreateWebAuthnChallenge: %v", err)
	}

	ok, err := s.ConsumeWebAuthnChallenge(ch.Challenge, "authenticate", user.ID)
	if err != nil || !ok {
		t.Fatalf("first consume: ok=%v err=%v", ok, err)
	}
	ok, err = s.ConsumeWebAuthnChallenge(ch.Challenge, "authenticate", user.ID)
	if err != nil {
		t.Fatalf("second consume errored: %v", err)
	}
	if ok {
		t.Fatal("a challenge must not be redeemable twice")
	}
}

func TestWebAuthnChallengeRejectsWrongPurposeUserAndExpiry(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()

	user := createTestUser(t, s)
	other := createTestUserNamed(t, s, "other-user")

	live := &WebAuthnChallenge{
		ID: uuid.New().String(), UserID: user.ID, Challenge: "TElWRQ",
		Purpose: "authenticate", ExpiresAt: time.Now().UTC().Add(2 * time.Minute),
	}
	expired := &WebAuthnChallenge{
		ID: uuid.New().String(), UserID: user.ID, Challenge: "T0xE",
		Purpose: "authenticate", ExpiresAt: time.Now().UTC().Add(-time.Second),
	}
	for _, ch := range []*WebAuthnChallenge{live, expired} {
		if err := s.CreateWebAuthnChallenge(ch); err != nil {
			t.Fatalf("CreateWebAuthnChallenge: %v", err)
		}
	}

	if ok, _ := s.ConsumeWebAuthnChallenge(live.Challenge, "register", user.ID); ok {
		t.Fatal("a challenge issued for authentication must not satisfy registration")
	}
	if ok, _ := s.ConsumeWebAuthnChallenge(live.Challenge, "authenticate", other.ID); ok {
		t.Fatal("a challenge must not be redeemable by another user")
	}
	if ok, _ := s.ConsumeWebAuthnChallenge(expired.Challenge, "authenticate", user.ID); ok {
		t.Fatal("an expired challenge must not be redeemable")
	}
}

func TestWebAuthnCredentialLifecycle(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()

	user := createTestUser(t, s)
	cred := &WebAuthnCredential{
		ID:             uuid.New().String(),
		UserID:         user.ID,
		CredentialID:   "Y3JlZC1vbmU",
		PublicKeySPKI:  "c3BraQ",
		Name:           "KyAuth on Pixel",
		SignCount:      3,
		BackupEligible: false,
	}
	if err := s.CreateWebAuthnCredential(cred, nil); err != nil {
		t.Fatalf("CreateWebAuthnCredential: %v", err)
	}

	got, err := s.GetWebAuthnCredential(user.ID, cred.CredentialID)
	if err != nil || got == nil {
		t.Fatalf("GetWebAuthnCredential: %v %v", got, err)
	}
	if got.SignCount != 3 || got.Name != "KyAuth on Pixel" {
		t.Fatalf("round trip lost data: %+v", got)
	}

	if err := s.RecordWebAuthnUse(cred.ID, 4, true, time.Now().UTC()); err != nil {
		t.Fatalf("RecordWebAuthnUse: %v", err)
	}
	got, _ = s.GetWebAuthnCredential(user.ID, cred.CredentialID)
	if got.SignCount != 4 || !got.BackupState || got.LastUsedAt == nil {
		t.Fatalf("use was not recorded: %+v", got)
	}

	list, err := s.ListUserWebAuthnCredentials(user.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListUserWebAuthnCredentials = %d creds, %v", len(list), err)
	}

	deleted, err := s.DeleteWebAuthnCredential(cred.ID, "some-other-user", nil)
	if err != nil {
		t.Fatalf("DeleteWebAuthnCredential: %v", err)
	}
	if deleted {
		t.Fatal("a credential must not be deletable by a user who does not own it")
	}

	deleted, err = s.DeleteWebAuthnCredential(cred.ID, user.ID, nil)
	if err != nil || !deleted {
		t.Fatalf("owner delete: deleted=%v err=%v", deleted, err)
	}
}

func TestMFAWipesRemovePasskeys(t *testing.T) {
	// An administrator resetting MFA, and a user replacing their factors, must both strip
	// passkeys. A passkey that survives a reset is an attacker-planted factor that outlives
	// the response to the incident that triggered the reset.
	for _, tc := range []struct {
		name string
		wipe func(*Store, string) error
	}{
		{"ResetUserMFA", func(s *Store, uid string) error { return s.ResetUserMFA(uid, nil, nil) }},
		{"DeleteUserMFAMethods", func(s *Store, uid string) error { return s.DeleteUserMFAMethods(uid) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, cleanup := setupTestStore(t)
			defer cleanup()

			user := createTestUser(t, s)
			if err := s.CreateWebAuthnCredential(&WebAuthnCredential{
				ID: uuid.New().String(), UserID: user.ID,
				CredentialID: "Y3JlZC0" + tc.name, PublicKeySPKI: "c3BraQ", Name: "key",
			}, nil); err != nil {
				t.Fatalf("CreateWebAuthnCredential: %v", err)
			}

			if err := tc.wipe(s, user.ID); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}

			list, err := s.ListUserWebAuthnCredentials(user.ID)
			if err != nil {
				t.Fatalf("ListUserWebAuthnCredentials: %v", err)
			}
			if len(list) != 0 {
				t.Fatalf("%s left %d passkeys behind", tc.name, len(list))
			}
		})
	}
}
```

`internal/store/store_test.go` has no shared setup helper — each existing test opens its own database inline. Add these three at the top of the file, matching that idiom:

```go
func setupTestStore(t *testing.T) (*Store, func()) {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "webauthn.db"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	return s, func() { _ = s.Close() }
}

func createTestUser(t *testing.T, s *Store) *User {
	t.Helper()
	return createTestUserNamed(t, s, "user-"+uuid.New().String()[:8])
}

func createTestUserNamed(t *testing.T, s *Store, username string) *User {
	t.Helper()
	u := &User{
		ID: uuid.New().String(), Username: username,
		DisplayName: username, Email: username + "@test.invalid",
		PasswordHash: "x", Role: "user", Status: "active",
	}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}
```

Confirm `(*Store).Close` exists before using it in the cleanup; if it does not, drop the cleanup body and return a no-op, since `t.TempDir()` is removed automatically.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/store/ -run 'WebAuthn|MFAWipes'`
Expected: FAIL — `undefined: WebAuthnChallenge`, `s.CreateWebAuthnChallenge undefined`.

- [ ] **Step 3: Add the models**

Append to `internal/store/models.go`:

```go
// WebAuthnCredential is one enrolled passkey. The public key is stored SPKI DER,
// base64url-encoded; there is no secret here, so it is not encrypted at rest.
type WebAuthnCredential struct {
	ID            string `json:"id"`
	UserID        string `json:"userId"`
	CredentialID  string `json:"credentialId"`
	PublicKeySPKI string `json:"-"`
	SignCount     uint32 `json:"-"`
	Name          string `json:"name"`
	// BackupEligible reports whether the authenticator may sync this credential to a
	// provider cloud; BackupState whether it currently is. Recorded and surfaced, never
	// enforced here — see the design decisions in the plan.
	BackupEligible bool       `json:"backupEligible"`
	BackupState    bool       `json:"backupState"`
	LastUsedAt     *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
}

// WebAuthnChallenge is a single-use nonce bound to one user and one ceremony.
type WebAuthnChallenge struct {
	ID        string     `json:"id"`
	UserID    string     `json:"userId"`
	Challenge string     `json:"-"`
	Purpose   string     `json:"purpose"` // "register", "authenticate"
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}
```

- [ ] **Step 4: Add the schema**

In `internal/store/store.go`, inside the `schema` string in `migrate()`, after the `step_up_tokens` block (around line 274):

```sql
	CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		credential_id TEXT NOT NULL UNIQUE,
		public_key_spki TEXT NOT NULL,
		sign_count INTEGER NOT NULL DEFAULT 0,
		name TEXT NOT NULL,
		backup_eligible INTEGER NOT NULL DEFAULT 0,
		backup_state INTEGER NOT NULL DEFAULT 0,
		last_used_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id);

	CREATE TABLE IF NOT EXISTS webauthn_challenges (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		challenge TEXT NOT NULL UNIQUE,
		purpose TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		used_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_value ON webauthn_challenges(challenge);
```

No `migrate*` helper function is needed: both tables are new, so `CREATE TABLE IF NOT EXISTS` is the whole migration for existing databases.

- [ ] **Step 5: Add the store methods**

Append to `internal/store/store.go`, after the MFA token methods (after line 1489):

```go
// WebAuthn passkeys

func (s *Store) CreateWebAuthnChallenge(ch *WebAuthnChallenge) error {
	ch.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(
		`INSERT INTO webauthn_challenges (id, user_id, challenge, purpose, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		ch.ID, ch.UserID, ch.Challenge, ch.Purpose, ch.ExpiresAt, ch.CreatedAt)
	return err
}

// ConsumeWebAuthnChallenge redeems a challenge for exactly one ceremony. The purpose and
// the user are part of the predicate, so a challenge minted for enrolment cannot complete
// a login, and one user's challenge cannot complete another's.
func (s *Store) ConsumeWebAuthnChallenge(challenge, purpose, userID string) (bool, error) {
	res, err := s.db.Exec(
		`UPDATE webauthn_challenges SET used_at = ?
		 WHERE challenge = ? AND purpose = ? AND user_id = ? AND used_at IS NULL AND expires_at > ?`,
		time.Now().UTC(), challenge, purpose, userID, time.Now().UTC())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *Store) DeleteExpiredWebAuthnChallenges() error {
	_, err := s.db.Exec(`DELETE FROM webauthn_challenges WHERE expires_at < ? OR used_at IS NOT NULL`, time.Now().UTC())
	return err
}

// CreateWebAuthnCredential enrols a passkey and its audit record in one transaction, so an
// account never gains a factor without a durable trail of where it came from.
func (s *Store) CreateWebAuthnCredential(c *WebAuthnCredential, audit *AuditEvent) error {
	c.CreatedAt = time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`INSERT INTO webauthn_credentials
		 (id, user_id, credential_id, public_key_spki, sign_count, name, backup_eligible, backup_state, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.UserID, c.CredentialID, c.PublicKeySPKI, c.SignCount, c.Name,
		c.BackupEligible, c.BackupState, c.CreatedAt); err != nil {
		return err
	}
	if err := recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func scanWebAuthnCredential(scan func(dest ...any) error) (*WebAuthnCredential, error) {
	c := &WebAuthnCredential{}
	var lastUsed sql.NullTime
	if err := scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKeySPKI, &c.SignCount,
		&c.Name, &c.BackupEligible, &c.BackupState, &lastUsed, &c.CreatedAt); err != nil {
		return nil, err
	}
	if lastUsed.Valid {
		t := lastUsed.Time
		c.LastUsedAt = &t
	}
	return c, nil
}

const webAuthnCredentialColumns = `id, user_id, credential_id, public_key_spki, sign_count, name, backup_eligible, backup_state, last_used_at, created_at`

func (s *Store) ListUserWebAuthnCredentials(userID string) ([]WebAuthnCredential, error) {
	rows, err := s.db.Query(
		`SELECT `+webAuthnCredentialColumns+` FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []WebAuthnCredential
	for rows.Next() {
		c, err := scanWebAuthnCredential(rows.Scan)
		if err != nil {
			return nil, err
		}
		creds = append(creds, *c)
	}
	return creds, rows.Err()
}

// GetWebAuthnCredential looks a credential up within one user. The user ID is part of the
// predicate so a credential ID harvested elsewhere cannot select another account's key.
func (s *Store) GetWebAuthnCredential(userID, credentialID string) (*WebAuthnCredential, error) {
	row := s.db.QueryRow(
		`SELECT `+webAuthnCredentialColumns+` FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?`,
		userID, credentialID)
	c, err := scanWebAuthnCredential(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func (s *Store) RecordWebAuthnUse(id string, signCount uint32, backupState bool, usedAt time.Time) error {
	_, err := s.db.Exec(
		`UPDATE webauthn_credentials SET sign_count = ?, backup_state = ?, last_used_at = ? WHERE id = ?`,
		signCount, backupState, usedAt, id)
	return err
}

// DeleteWebAuthnCredential removes one passkey. Ownership is in the predicate, so the
// handler cannot be tricked into deleting a credential the caller does not hold.
func (s *Store) DeleteWebAuthnCredential(id, userID string, audit *AuditEvent) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	if err := recordAuditTx(tx, audit); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
```

- [ ] **Step 6: Wipe passkeys on both MFA-clearing paths**

In `DeleteUserMFAMethods` (line 1369) and `ResetUserMFA` (line 1973), add this statement immediately after the existing `DELETE FROM recovery_codes` line in each:

```go
	if _, err := tx.Exec(`DELETE FROM webauthn_credentials WHERE user_id = ?`, userID); err != nil {
		return err
	}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test -race ./internal/store/ -run 'WebAuthn|MFAWipes' -v`
Expected: PASS, all four tests.

Then run the whole package to prove nothing regressed: `go test -race ./internal/store/...`

- [ ] **Step 8: Wire housekeeping and commit**

In `cmd/kyidentity/main.go`, inside the `housekeep` closure (line 148), after `_ = dbStore.DeleteExpiredMFAChallenges()`:

```go
			_ = dbStore.DeleteExpiredWebAuthnChallenges()
```

```bash
gofmt -w internal/store cmd/kyidentity
go vet ./...
git add internal/store cmd/kyidentity
git commit -m "feat(store): add webauthn credential and challenge tables"
```

---

## Task 3: Passkey enrolment endpoints

**Files:**
- Create: `internal/api/webauthn_handlers.go`
- Modify: `internal/api/server.go:147-151`
- Test: `internal/api/webauthn_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1 and 2.
- Produces: `config.Config` gains `RPID` and `Origin`; `NewWebAuthnHandler(s *store.Store, audit *audit.Logger, mfaEngine *mfa.Engine, mm *MiddlewareManager, rpID, origin string) *WebAuthnHandler` with methods `BeginRegistration`, `FinishRegistration`, `ListPasskeys`, `DeletePasskey`, `BeginLogin`, `FinishLogin` (the last two are implemented in Task 4). Routes: `POST /api/user/passkeys/register/begin`, `POST /api/user/passkeys/register/finish`.

**Existing test fixtures to reuse — read these before writing anything.** `internal/api/stepup_test.go:28` defines `newStepUpFixture(t)`, which creates a server, a user with password `f.pass`, a live session, and a matching CSRF pair. `f.post(t, path, body, stepUpToken)` issues an authenticated POST with all of that attached; `f.grant(t)` mints a step-up token. Requests are dispatched with `f.srv.httpServer.Handler.ServeHTTP(w, req)` — there is no `Server.Handler()` method. The session cookie is `kyidentity_session` and the CSRF cookie is `kyidentity_csrf`. **Every non-GET request must carry both the `kyidentity_csrf` cookie and a matching `X-CSRF-Token` header** (`internal/api/middleware.go:316`); for a request that also carries a session, the token must be `srv.middleware.IssueCSRFToken(sessionToken)`. None of the passkey routes are on the CSRF bypass list, and none should be added to it.

- [ ] **Step 1: Derive the RP ID at startup**

The issuer URL is already validated in `internal/config/config.go:66`, so deriving the RP ID there means a bad value is a startup error rather than a runtime one, and `routes()` needs no error path.

In `internal/config/config.go`, add two fields to `Config` beside `IssuerURL`:

```go
	// RPID and Origin are the WebAuthn relying party identity, derived from IssuerURL at
	// load so a malformed issuer fails startup rather than the first passkey ceremony.
	RPID   string
	Origin string
```

and populate them immediately after the existing issuer validation block (line 69):

```go
	rpID, rpOrigin, err := webauthn.RPIDFromIssuer(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("KYIDENTITY_ISSUER_URL cannot be used as a WebAuthn relying party: %w", err)
	}
```

then set `RPID: rpID, Origin: rpOrigin` in the returned struct beside `IssuerURL`. Add the import for `internal/webauthn`; there is no cycle, because that package imports nothing internal.

Add to `internal/config/security_test.go`:

```go
func TestLoadDerivesWebAuthnRelyingParty(t *testing.T) {
	t.Setenv("KYIDENTITY_ISSUER_URL", "https://auth.example.com/")
	t.Setenv("KYIDENTITY_DATA_DIR", t.TempDir())

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RPID != "auth.example.com" || cfg.Origin != "https://auth.example.com" {
		t.Fatalf("RPID=%q Origin=%q", cfg.RPID, cfg.Origin)
	}
}
```

Match the env var names and the `Load` signature to what `internal/config/config.go` actually exports; if the existing tests in that package use a different harness, use theirs.

Run: `go test ./internal/config/...` — expected PASS.

Then add the two fields to the `config.Config` literal in `internal/api/api_test.go:44`, so the test server has a relying party:

```go
		RPID:          "localhost",
		Origin:        "http://localhost:5867",
```

- [ ] **Step 2: Write the failing test**

Create `internal/api/webauthn_test.go`:

```go
package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Yoshiofthewire/kyidentity-server/internal/auth"
	"github.com/Yoshiofthewire/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// testAuthenticator is a software authenticator good enough to exercise the endpoints.
type testAuthenticator struct {
	key       *ecdsa.PrivateKey
	credID    string
	signCount uint32
}

func newTestAuthenticator(t *testing.T, credID string) *testAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return &testAuthenticator{key: key, credID: credID}
}

func (a *testAuthenticator) spkiB64(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&a.key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

func (a *testAuthenticator) authData(rpID string, flags byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	b := make([]byte, 37)
	copy(b, h[:])
	b[32] = flags
	binary.BigEndian.PutUint32(b[33:37], a.signCount)
	return b
}

func (a *testAuthenticator) clientData(t *testing.T, typ, challenge, origin string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	return b
}

func (a *testAuthenticator) sign(t *testing.T, ad, cdj []byte) string {
	t.Helper()
	cdHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(sig)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// do issues a GET or DELETE with the fixture's session and CSRF credentials.
// stepUpFixture.post already covers POST; the passkey routes also need these two verbs.
func (f *stepUpFixture) do(t *testing.T, method, path, stepUp string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(f.cookie)
	req.AddCookie(f.csrfCk)
	req.Header.Set("X-CSRF-Token", f.csrf)
	if stepUp != "" {
		req.Header.Set(StepUpHeader, stepUp)
	}
	w := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(w, req)
	return w
}

// anonPost issues an unauthenticated JSON POST with a self-consistent CSRF pair, which is
// all the double-submit check requires of a caller that holds no session.
func anonPost(t *testing.T, srv *Server, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	csrf := "test-csrf-" + uuid.New().String()
	req.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)
	return w
}

func TestPasskeyRegistrationRequiresStepUp(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	rec := f.post(t, "/api/user/passkeys/register/begin", map[string]string{"name": "KyAuth"}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("begin without a step-up grant returned %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

func TestPasskeyRegistrationRoundTrip(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	a := newTestAuthenticator(t, "Y3JlZC1vbmU")

	rec := f.post(t, "/api/user/passkeys/register/begin", map[string]string{"name": "KyAuth on Pixel"}, f.grant(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("begin returned %d: %s", rec.Code, rec.Body.String())
	}

	var begun struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begun); err != nil {
		t.Fatalf("decode begin response: %v", err)
	}
	if begun.Challenge == "" || begun.RPID != "localhost" {
		t.Fatalf("unexpected begin response: %+v", begun)
	}

	ad := a.authData(begun.RPID, 0x01|0x04|0x40)
	cdj := a.clientData(t, "webauthn.create", begun.Challenge, "http://localhost:5867")
	rec = f.post(t, "/api/user/passkeys/register/finish", map[string]string{
		"credentialId":      a.credID,
		"authenticatorData": b64(ad),
		"clientDataJSON":    b64(cdj),
		"publicKey":         a.spkiB64(t),
		"name":              "KyAuth on Pixel",
	}, f.grant(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("finish returned %d: %s", rec.Code, rec.Body.String())
	}

	creds, err := f.store.ListUserWebAuthnCredentials(f.user.ID)
	if err != nil || len(creds) != 1 {
		t.Fatalf("expected one stored credential, got %d (%v)", len(creds), err)
	}
	if creds[0].Name != "KyAuth on Pixel" {
		t.Fatalf("credential name = %q", creds[0].Name)
	}
}

func TestPasskeyRegistrationRejectsForeignOrigin(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	a := newTestAuthenticator(t, "Y3JlZC1ldmls")

	rec := f.post(t, "/api/user/passkeys/register/begin", map[string]string{"name": "evil"}, f.grant(t))
	var begun struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begun); err != nil {
		t.Fatalf("decode begin response: %v", err)
	}

	ad := a.authData(begun.RPID, 0x01)
	cdj := a.clientData(t, "webauthn.create", begun.Challenge, "https://evil.example.com")
	rec = f.post(t, "/api/user/passkeys/register/finish", map[string]string{
		"credentialId":      a.credID,
		"authenticatorData": b64(ad),
		"clientDataJSON":    b64(cdj),
		"publicKey":         a.spkiB64(t),
		"name":              "evil",
	}, f.grant(t))

	if rec.Code == http.StatusOK {
		t.Fatal("a ceremony completed at another origin must not enrol a credential")
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/api/ -run Passkey`
Expected: FAIL — the routes return 404.

- [ ] **Step 4: Write the handler**

Create `internal/api/webauthn_handlers.go`:

```go
package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Yoshiofthewire/kyidentity-server/internal/audit"
	"github.com/Yoshiofthewire/kyidentity-server/internal/crypto"
	"github.com/Yoshiofthewire/kyidentity-server/internal/mfa"
	"github.com/Yoshiofthewire/kyidentity-server/internal/store"
	"github.com/Yoshiofthewire/kyidentity-server/internal/webauthn"
	"github.com/google/uuid"
)

// challengeTTL bounds how long a ceremony may sit half-finished. Long enough for a user to
// find their phone, short enough that a captured challenge is worthless by the time it
// could be replayed — and it is single-use regardless.
const challengeTTL = 3 * time.Minute

// maxPasskeysPerUser caps enrolment. Unbounded credentials per account is a place for an
// attacker with one borrowed session to leave many durable factors behind.
const maxPasskeysPerUser = 10

type WebAuthnHandler struct {
	store      *store.Store
	audit      *audit.Logger
	mfaEngine  *mfa.Engine
	middleware *MiddlewareManager
	rpID       string
	origin     string
}

// NewWebAuthnHandler takes the relying party identity already derived and validated by
// config.Load, so a malformed issuer URL is a startup failure rather than a ceremony that
// fails for the first user who tries it.
func NewWebAuthnHandler(s *store.Store, auditLogger *audit.Logger, mfaEngine *mfa.Engine, mm *MiddlewareManager, rpID, origin string) *WebAuthnHandler {
	return &WebAuthnHandler{store: s, audit: auditLogger, mfaEngine: mfaEngine, middleware: mm, rpID: rpID, origin: origin}
}

type beginRegistrationResponse struct {
	Challenge  string   `json:"challenge"`
	RPID       string   `json:"rpId"`
	RPName     string   `json:"rpName"`
	UserHandle string   `json:"userHandle"`
	Username   string   `json:"username"`
	Exclude    []string `json:"excludeCredentials"`
}

// issueChallenge mints and stores a single-use nonce for one user and one ceremony.
func (h *WebAuthnHandler) issueChallenge(userID, purpose string) (string, error) {
	raw, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		return "", err
	}
	challenge := base64.RawURLEncoding.EncodeToString(raw)
	return challenge, h.store.CreateWebAuthnChallenge(&store.WebAuthnChallenge{
		ID:        uuid.New().String(),
		UserID:    userID,
		Challenge: challenge,
		Purpose:   purpose,
		ExpiresAt: time.Now().UTC().Add(challengeTTL),
	})
}

// BeginRegistration returns the parameters for navigator.credentials.create. The step-up
// grant is checked but not spent: failing here rather than after the user has touched their
// authenticator is the better experience, and FinishRegistration spends it.
func (h *WebAuthnHandler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if err := requireStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	existing, err := h.store.ListUserWebAuthnCredentials(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if len(existing) >= maxPasskeysPerUser {
		http.Error(w, `{"error":"too_many_passkeys","error_description":"Remove an existing passkey before enrolling another"}`, http.StatusConflict)
		return
	}

	challenge, err := h.issueChallenge(user.ID, "register")
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	// Existing credentials are excluded so an authenticator that already holds one for this
	// account says so instead of silently enrolling a duplicate.
	exclude := make([]string, 0, len(existing))
	for _, c := range existing {
		exclude = append(exclude, c.CredentialID)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(beginRegistrationResponse{
		Challenge:  challenge,
		RPID:       h.rpID,
		RPName:     "KyIdentity",
		UserHandle: base64.RawURLEncoding.EncodeToString([]byte(user.ID)),
		Username:   user.Username,
		Exclude:    exclude,
	})
}

type finishRegistrationRequest struct {
	CredentialID      string `json:"credentialId"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	PublicKey         string `json:"publicKey"`
	Name              string `json:"name"`
}

func (h *WebAuthnHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req finishRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		req.CredentialID == "" || req.AuthenticatorData == "" || req.ClientDataJSON == "" || req.PublicKey == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	// A ceremony the caller conducted with their own authenticator proves nothing about
	// the account holder, so entitlement comes from the step-up grant, as it does for TOTP.
	if err := consumeStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	authData, err1 := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	clientData, err2 := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	publicKey, err3 := base64.RawURLEncoding.DecodeString(req.PublicKey)
	if err1 != nil || err2 != nil || err3 != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"Ceremony fields must be base64url"}`, http.StatusBadRequest)
		return
	}

	var cd struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(clientData, &cd); err != nil || cd.Challenge == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	// Redeem before verifying. A challenge that fails verification is burned either way,
	// so a caller cannot grind attempts against one issued nonce.
	spent, err := h.store.ConsumeWebAuthnChallenge(cd.Challenge, "register", user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if !spent {
		http.Error(w, `{"error":"invalid_challenge","error_description":"Registration challenge is unknown, expired, or already used"}`, http.StatusBadRequest)
		return
	}

	ad, err := webauthn.VerifyRegistration(webauthn.RegistrationInput{
		AuthenticatorData: authData,
		ClientDataJSON:    clientData,
		PublicKeySPKI:     publicKey,
		Challenge:         cd.Challenge,
		Origin:            h.origin,
		RPID:              h.rpID,
	})
	if err != nil {
		h.audit.Record("mfa.passkey_enrol", user.ID, user.Username, user.ID, "user",
			h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{"reason": "verification_failed"})
		http.Error(w, `{"error":"invalid_credential","error_description":"Passkey registration could not be verified"}`, http.StatusBadRequest)
		return
	}

	name := req.Name
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 64 {
		name = name[:64]
	}

	enrolled := h.audit.Prepare("mfa.passkey_enrol", user.ID, user.Username, user.ID, "user",
		h.middleware.ClientIP(r), r.UserAgent(), "success",
		map[string]any{"backupEligible": ad.BackupEligible(), "userVerified": ad.UserVerified()})
	if err := h.store.CreateWebAuthnCredential(&store.WebAuthnCredential{
		ID:             uuid.New().String(),
		UserID:         user.ID,
		CredentialID:   req.CredentialID,
		PublicKeySPKI:  req.PublicKey,
		SignCount:      ad.SignCount,
		Name:           name,
		BackupEligible: ad.BackupEligible(),
		BackupState:    ad.BackupState(),
	}, enrolled.Row); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	enrolled.Committed()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}
```

- [ ] **Step 5: Wire the routes**

In `internal/api/server.go`, construct the handler in `routes()` (line 95) beside `devH` and the others:

```go
	webauthnH := NewWebAuthnHandler(s.store, s.audit, s.mfaEngine, s.middleware, s.cfg.RPID, s.cfg.Origin)
```

`routes()` returns `*http.ServeMux` and no error; that stays true, which is the reason Step 1 moved the derivation into config.

Register the routes after the TOTP block (line 149):

```go
	mux.Handle("POST /api/user/passkeys/register/begin", authM(s.middleware.RateLimit("passkey_enrol", 10, 0.2)(http.HandlerFunc(webauthnH.BeginRegistration))))
	mux.Handle("POST /api/user/passkeys/register/finish", authM(s.middleware.RateLimit("passkey_enrol", 10, 0.2)(http.HandlerFunc(webauthnH.FinishRegistration))))
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test -race ./internal/api/ -run Passkey -v`
Expected: PASS — all three tests.

- [ ] **Step 7: Commit**

```bash
gofmt -w internal/api internal/config
go vet ./...
git add internal/api internal/config
git commit -m "feat(api): enrol webauthn passkeys behind a step-up grant"
```

---

## Task 4: Passkey as a login factor

**Files:**
- Modify: `internal/api/webauthn_handlers.go`
- Modify: `internal/api/auth_handlers.go:138-152`
- Modify: `internal/api/server.go:126-131`
- Test: `internal/api/webauthn_test.go`

**Interfaces:**
- Consumes: `resolveMFAToken`, `spendMFAToken`, `createSessionAndRespond` from `auth_handlers.go`; everything from Tasks 1–3.
- Produces: `POST /api/auth/mfa/webauthn/begin` (body `{"mfaToken":"..."}` → `{"challenge":"...","rpId":"...","allowCredentials":["..."]}`), `POST /api/auth/mfa/webauthn/verify` (body `{"mfaToken","credentialId","authenticatorData","clientDataJSON","signature"}` → session). `Login` now includes `"webauthn"` in `mfaMethods`.

- [ ] **Step 1: Write the failing test**

Append to `internal/api/webauthn_test.go`:

```go
// enrolPasskey registers a credential directly in the store, so login tests do not depend
// on the enrolment endpoints.
func enrolPasskey(t *testing.T, dbStore *store.Store, userID string, a *testAuthenticator) {
	t.Helper()
	if err := dbStore.CreateWebAuthnCredential(&store.WebAuthnCredential{
		ID:            uuid.New().String(),
		UserID:        userID,
		CredentialID:  a.credID,
		PublicKeySPKI: a.spkiB64(t),
		Name:          "test key",
	}, nil); err != nil {
		t.Fatalf("CreateWebAuthnCredential: %v", err)
	}
}

// passwordLogin performs the first leg and returns the second-factor token.
func passwordLogin(t *testing.T, srv *Server, username, password string) string {
	t.Helper()
	rec := anonPost(t, srv, "/api/auth/login", map[string]string{"username": username, "password": password})
	var resp struct {
		MFAToken string `json:"mfaToken"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.MFAToken == "" {
		t.Fatalf("login did not return an mfa token (%d): %s", rec.Code, rec.Body.String())
	}
	return resp.MFAToken
}

func TestLoginAdvertisesPasskeyMethod(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	enrolPasskey(t, f.store, f.user.ID, newTestAuthenticator(t, "Y3JlZC1sb2dpbg"))

	rec := anonPost(t, f.srv, "/api/auth/login", map[string]string{"username": f.user.Username, "password": f.pass})
	var resp struct {
		MFARequired bool     `json:"mfaRequired"`
		MFAMethods  []string `json:"mfaMethods"`
		MFAToken    string   `json:"mfaToken"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if !resp.MFARequired || resp.MFAToken == "" {
		t.Fatalf("a user with only a passkey must be challenged: %+v", resp)
	}
	found := false
	for _, m := range resp.MFAMethods {
		if m == "webauthn" {
			found = true
		}
	}
	if !found {
		t.Fatalf("mfaMethods = %v, want it to contain webauthn", resp.MFAMethods)
	}
}

// assertionFields drives the begin leg and returns a ready-to-post verify body signed by a.
// checkAllow is skipped for the cross-account test, whose whole point is presenting a
// credential the allow-list does not contain.
func assertionFields(t *testing.T, srv *Server, mfaToken string, a *testAuthenticator, checkAllow bool) map[string]string {
	t.Helper()

	rec := anonPost(t, srv, "/api/auth/mfa/webauthn/begin", map[string]string{"mfaToken": mfaToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("begin returned %d: %s", rec.Code, rec.Body.String())
	}
	var begun struct {
		Challenge        string   `json:"challenge"`
		RPID             string   `json:"rpId"`
		AllowCredentials []string `json:"allowCredentials"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begun); err != nil {
		t.Fatalf("decode begin response: %v", err)
	}
	if checkAllow && (len(begun.AllowCredentials) != 1 || begun.AllowCredentials[0] != a.credID) {
		t.Fatalf("allowCredentials = %v", begun.AllowCredentials)
	}

	a.signCount++
	ad := a.authData(begun.RPID, 0x01|0x04)
	cdj := a.clientData(t, "webauthn.get", begun.Challenge, "http://localhost:5867")
	return map[string]string{
		"mfaToken":          mfaToken,
		"credentialId":      a.credID,
		"authenticatorData": b64(ad),
		"clientDataJSON":    b64(cdj),
		"signature":         a.sign(t, ad, cdj),
	}
}

func TestPasskeyLoginIssuesSession(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	a := newTestAuthenticator(t, "Y3JlZC1sb2dpbg")
	enrolPasskey(t, f.store, f.user.ID, a)

	mfaToken := passwordLogin(t, f.srv, f.user.Username, f.pass)
	rec := anonPost(t, f.srv, "/api/auth/mfa/webauthn/verify", assertionFields(t, f.srv, mfaToken, a, true))
	if rec.Code != http.StatusOK {
		t.Fatalf("verify returned %d: %s", rec.Code, rec.Body.String())
	}

	sessionIssued := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kyidentity_session" && c.Value != "" {
			sessionIssued = true
		}
	}
	if !sessionIssued {
		t.Fatal("a verified passkey assertion must issue a session cookie")
	}

	creds, _ := f.store.ListUserWebAuthnCredentials(f.user.ID)
	if creds[0].SignCount != 1 || creds[0].LastUsedAt == nil {
		t.Fatalf("use was not recorded on the credential: %+v", creds[0])
	}
}

func TestPasskeyLoginRejectsForgedSignature(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	a := newTestAuthenticator(t, "Y3JlZC1sb2dpbg")
	enrolPasskey(t, f.store, f.user.ID, a)

	mfaToken := passwordLogin(t, f.srv, f.user.Username, f.pass)
	fields := assertionFields(t, f.srv, mfaToken, a, true)
	fields["signature"] = b64([]byte("not a signature"))

	if rec := anonPost(t, f.srv, "/api/auth/mfa/webauthn/verify", fields); rec.Code == http.StatusOK {
		t.Fatal("a forged signature must not issue a session")
	}
}

func TestPasskeyAssertionIsSingleUse(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	a := newTestAuthenticator(t, "Y3JlZC1sb2dpbg")
	enrolPasskey(t, f.store, f.user.ID, a)

	mfaToken := passwordLogin(t, f.srv, f.user.Username, f.pass)
	fields := assertionFields(t, f.srv, mfaToken, a, true)

	if rec := anonPost(t, f.srv, "/api/auth/mfa/webauthn/verify", fields); rec.Code != http.StatusOK {
		t.Fatalf("first verify returned %d: %s", rec.Code, rec.Body.String())
	}
	if rec := anonPost(t, f.srv, "/api/auth/mfa/webauthn/verify", fields); rec.Code == http.StatusOK {
		t.Fatal("a replayed assertion must not issue a second session")
	}
}

func TestPasskeyLoginRejectsAnotherUsersCredential(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	// The victim holds their own passkey; the attacker holds one enrolled to a different
	// account and presents it against the victim's second-factor token.
	enrolPasskey(t, f.store, f.user.ID, newTestAuthenticator(t, "Y3JlZC12aWN0aW0"))

	hash, err := auth.HashPassword("AttackerPassword1!")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	attacker := &store.User{
		ID: uuid.New().String(), Username: "attacker-" + uuid.New().String()[:8],
		DisplayName: "Attacker", Email: uuid.New().String()[:8] + "@attacker.test",
		PasswordHash: hash, Role: "user", Status: "active",
	}
	if err := f.store.CreateUser(attacker); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	attackerAuth := newTestAuthenticator(t, "Y3JlZC1hdHRhY2tlcg")
	enrolPasskey(t, f.store, attacker.ID, attackerAuth)

	mfaToken := passwordLogin(t, f.srv, f.user.Username, f.pass)
	fields := assertionFields(t, f.srv, mfaToken, attackerAuth, false)

	if rec := anonPost(t, f.srv, "/api/auth/mfa/webauthn/verify", fields); rec.Code == http.StatusOK {
		t.Fatal("a credential belonging to another account must not satisfy this user's challenge")
	}
}
```

The `auth` and `store` imports are first used here, in the cross-account test. Add them to the import block written in Task 3 when you reach this task, not before, or the package will not compile at the end of Task 3.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/api/ -run 'Passkey|LoginAdvertises'`
Expected: FAIL — `/api/auth/mfa/webauthn/begin` returns 404 and `mfaMethods` does not contain `webauthn`.

- [ ] **Step 3: Advertise the method in Login**

In `internal/api/auth_handlers.go`, after the loop that builds `methodTypes` (around line 145) and before `if len(methodTypes) > 0 {`:

```go
	// Passkeys live in their own table because a user may hold several, so they are not
	// in mfa_methods and have to be counted separately.
	passkeys, err := h.store.ListUserWebAuthnCredentials(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if len(passkeys) > 0 {
		methodTypes = append(methodTypes, "webauthn")
	}
```

- [ ] **Step 4: Write the login handlers**

Append to `internal/api/webauthn_handlers.go`:

```go
type beginLoginRequest struct {
	MFAToken string `json:"mfaToken"`
}

type beginLoginResponse struct {
	Challenge        string   `json:"challenge"`
	RPID             string   `json:"rpId"`
	AllowCredentials []string `json:"allowCredentials"`
}

// BeginLogin returns the parameters for navigator.credentials.get. The user comes from the
// stored second-factor token, never from client input, so the allow-list cannot be steered
// onto another account's credentials.
func (h *WebAuthnHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	var req beginLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MFAToken == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	token, err := h.mfaEngine.ValidateMFAToken(req.MFAToken)
	if err != nil {
		http.Error(w, `{"error":"invalid_mfa_token","error_description":"Second-factor token is invalid or expired"}`, http.StatusUnauthorized)
		return
	}

	creds, err := h.store.ListUserWebAuthnCredentials(token.UserID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if len(creds) == 0 {
		http.Error(w, `{"error":"no_passkey","error_description":"No passkey is enrolled for this account"}`, http.StatusBadRequest)
		return
	}

	challenge, err := h.issueChallenge(token.UserID, "authenticate")
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	allow := make([]string, 0, len(creds))
	for _, c := range creds {
		allow = append(allow, c.CredentialID)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(beginLoginResponse{Challenge: challenge, RPID: h.rpID, AllowCredentials: allow})
}

type finishLoginRequest struct {
	MFAToken          string `json:"mfaToken"`
	CredentialID      string `json:"credentialId"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
}

// FinishLogin verifies an assertion and completes the login. It mirrors VerifyTOTP: the
// same token resolution, the same failure accounting, the same single-use spend.
func (h *WebAuthnHandler) FinishLogin(w http.ResponseWriter, r *http.Request, auth *AuthHandler) {
	var req finishLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		req.MFAToken == "" || req.CredentialID == "" || req.AuthenticatorData == "" ||
		req.ClientDataJSON == "" || req.Signature == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	token, user, ok := auth.resolveMFAToken(w, req.MFAToken)
	if !ok {
		return
	}

	authData, err1 := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	clientData, err2 := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	signature, err3 := base64.RawURLEncoding.DecodeString(req.Signature)
	if err1 != nil || err2 != nil || err3 != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"Ceremony fields must be base64url"}`, http.StatusBadRequest)
		return
	}

	var cd struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(clientData, &cd); err != nil || cd.Challenge == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	failed := func(reason string) {
		attempts, _ := h.mfaEngine.RegisterMFAFailure(token.ID)
		h.audit.Record("auth.mfa_passkey", user.ID, user.Username, user.ID, "user",
			h.middleware.ClientIP(r), r.UserAgent(), "failure",
			map[string]any{"reason": reason, "attempts": attempts})
		http.Error(w, `{"error":"invalid_assertion","error_description":"Passkey verification failed"}`, http.StatusUnauthorized)
	}

	spent, err := h.store.ConsumeWebAuthnChallenge(cd.Challenge, "authenticate", user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if !spent {
		failed("challenge_unusable")
		return
	}

	// The credential is looked up within this user, so an attacker's own passkey cannot
	// answer somebody else's challenge.
	cred, err := h.store.GetWebAuthnCredential(user.ID, req.CredentialID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if cred == nil {
		failed("unknown_credential")
		return
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(cred.PublicKeySPKI)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	ad, err := webauthn.VerifyAssertion(webauthn.AssertionInput{
		AuthenticatorData: authData,
		ClientDataJSON:    clientData,
		Signature:         signature,
		PublicKeySPKI:     publicKey,
		Challenge:         cd.Challenge,
		Origin:            h.origin,
		RPID:              h.rpID,
		StoredSignCount:   cred.SignCount,
	})
	if err != nil {
		failed("assertion_invalid")
		return
	}

	if !auth.spendMFAToken(w, token) {
		return
	}

	if err := h.store.RecordWebAuthnUse(cred.ID, ad.SignCount, ad.BackupState(), time.Now().UTC()); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	h.audit.Record("auth.mfa_passkey", user.ID, user.Username, user.ID, "user",
		h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"userVerified": ad.UserVerified()})
	_ = h.store.ClearFailedLogins(user.ID)
	auth.createSessionAndRespond(w, r, user)
}
```

- [ ] **Step 5: Wire the routes**

In `internal/api/server.go`, beside the other MFA routes (after line 130):

```go
	mux.Handle("POST /api/auth/mfa/webauthn/begin", s.middleware.RateLimit("mfa", 10, 0.2)(http.HandlerFunc(webauthnH.BeginLogin)))
	mux.Handle("POST /api/auth/mfa/webauthn/verify", s.middleware.RateLimit("mfa", 10, 0.2)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webauthnH.FinishLogin(w, r, authH)
	})))
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test -race ./internal/api/ -run 'Passkey|LoginAdvertises' -v`
Expected: PASS — all tests including the replay, forgery and cross-account cases.

Then the full suite: `go test -race -count=1 ./...`

- [ ] **Step 7: Commit**

```bash
gofmt -w internal/api
go vet ./...
git add internal/api
git commit -m "feat(auth): accept a passkey assertion as a second factor"
```

---

## Task 5: Passkey management endpoints

**Files:**
- Modify: `internal/api/webauthn_handlers.go`
- Modify: `internal/api/server.go`
- Test: `internal/api/webauthn_test.go`

**Interfaces:**
- Consumes: Tasks 1–4.
- Produces: `GET /api/user/passkeys` → `[{id, name, backupEligible, backupState, lastUsedAt, createdAt}]`; `DELETE /api/user/passkeys/{id}` (step-up required).

- [ ] **Step 1: Write the failing test**

Append to `internal/api/webauthn_test.go`:

```go
func TestListAndDeletePasskeys(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	enrolPasskey(t, f.store, f.user.ID, newTestAuthenticator(t, "Y3JlZC1saXN0"))

	rec := f.do(t, http.MethodGet, "/api/user/passkeys", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list returned %d: %s", rec.Code, rec.Body.String())
	}

	var listed []struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		PublicKeySPKI string `json:"publicKeySpki"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed) != 1 || listed[0].Name != "test key" {
		t.Fatalf("unexpected list: %+v", listed)
	}
	if listed[0].PublicKeySPKI != "" {
		t.Fatal("the credential public key must not be serialised to clients")
	}

	// Removing a factor is destructive, so it costs a step-up grant.
	rec = f.do(t, http.MethodDelete, "/api/user/passkeys/"+listed[0].ID, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("delete without step-up returned %d, want 403: %s", rec.Code, rec.Body.String())
	}

	rec = f.do(t, http.MethodDelete, "/api/user/passkeys/"+listed[0].ID, f.grant(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete returned %d: %s", rec.Code, rec.Body.String())
	}

	remaining, _ := f.store.ListUserWebAuthnCredentials(f.user.ID)
	if len(remaining) != 0 {
		t.Fatalf("%d passkeys survived deletion", len(remaining))
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/api/ -run ListAndDeletePasskeys`
Expected: FAIL with 404 on `/api/user/passkeys`.

- [ ] **Step 3: Write the handlers**

Append to `internal/api/webauthn_handlers.go`:

```go
// ListPasskeys returns the caller's enrolled passkeys. The public key and signature
// counter are omitted by the struct tags on store.WebAuthnCredential; nothing here needs
// to reach a browser.
func (h *WebAuthnHandler) ListPasskeys(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	creds, err := h.store.ListUserWebAuthnCredentials(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if creds == nil {
		creds = []store.WebAuthnCredential{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(creds)
}

// DeletePasskey removes one of the caller's passkeys. Removing a factor is destructive, so
// it costs a step-up grant: a borrowed session must not be able to strip the account back
// down to a single factor.
func (h *WebAuthnHandler) DeletePasskey(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if err := consumeStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	id := r.PathValue("id")
	removed := h.audit.Prepare("mfa.passkey_removed", user.ID, user.Username, user.ID, "user",
		h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"credentialRecordId": id})
	deleted, err := h.store.DeleteWebAuthnCredential(id, user.ID, removed.Row)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if !deleted {
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	}
	removed.Committed()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}
```

Add `"github.com/Yoshiofthewire/kyidentity-server/internal/store"` to the imports if the file does not already have it.

- [ ] **Step 4: Wire the routes**

In `internal/api/server.go`, beside the other user routes:

```go
	mux.Handle("GET /api/user/passkeys", authM(http.HandlerFunc(webauthnH.ListPasskeys)))
	mux.Handle("DELETE /api/user/passkeys/{id}", authM(http.HandlerFunc(webauthnH.DeletePasskey)))
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test -race ./internal/api/ -run Passkey -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/api
go vet ./...
git add internal/api
git commit -m "feat(api): list and remove enrolled passkeys"
```

---

## Task 6: Frontend WebAuthn helpers

**Files:**
- Create: `web/src/webauthn.ts`
- Test: `web/src/webauthn.test.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks (pure browser-side).
- Produces: `toBase64Url(buf: ArrayBuffer): string`, `fromBase64Url(s: string): Uint8Array`, `isPasskeySupported(): boolean`, `createPasskey(opts: BeginRegistration): Promise<FinishRegistration>`, `getPasskeyAssertion(opts: BeginLogin): Promise<FinishAssertion>`, and the four interfaces they use.

- [ ] **Step 1: Write the failing test**

Create `web/src/webauthn.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { fromBase64Url, toBase64Url } from './webauthn';

describe('base64url codecs', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    expect(Array.from(fromBase64Url(toBase64Url(bytes.buffer)))).toEqual(Array.from(bytes));
  });

  it('emits no padding and no standard-alphabet characters', () => {
    // The server compares the challenge as an exact string. Padding or +/ would not match.
    const bytes = new Uint8Array([251, 255, 190, 254]);
    const encoded = toBase64Url(bytes.buffer);
    expect(encoded).not.toContain('=');
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
  });

  it('decodes a string the server would have produced', () => {
    expect(new TextDecoder().decode(fromBase64Url('Q0hBTExFTkdF'))).toBe('CHALLENGE');
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd web && npx vitest run src/webauthn.test.ts`
Expected: FAIL — cannot resolve `./webauthn`.

- [ ] **Step 3: Write the implementation**

Create `web/src/webauthn.ts`:

```ts
/**
 * Browser half of the WebAuthn ceremonies. The server speaks base64url everywhere, so
 * every ArrayBuffer crossing the wire goes through these two codecs and nothing else.
 */

export function toBase64Url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function isPasskeySupported(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential;
}

export interface BeginRegistration {
  challenge: string;
  rpId: string;
  rpName: string;
  userHandle: string;
  username: string;
  excludeCredentials: string[];
}

export interface FinishRegistration {
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  publicKey: string;
}

/** ES256. The server verifies nothing else, so nothing else is offered. */
const ES256 = -7;

export async function createPasskey(opts: BeginRegistration): Promise<FinishRegistration> {
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: fromBase64Url(opts.challenge),
      rp: { id: opts.rpId, name: opts.rpName },
      user: {
        id: fromBase64Url(opts.userHandle),
        name: opts.username,
        displayName: opts.username,
      },
      pubKeyCredParams: [{ type: 'public-key', alg: ES256 }],
      // Attestation is not verified server-side, so requesting it would only add a
      // consent prompt for data nobody reads.
      attestation: 'none',
      authenticatorSelection: { userVerification: 'preferred', residentKey: 'preferred' },
      excludeCredentials: opts.excludeCredentials.map((id) => ({
        type: 'public-key' as const,
        id: fromBase64Url(id),
      })),
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('Passkey creation was cancelled');

  const response = credential.response as AuthenticatorAttestationResponse;
  const publicKey = response.getPublicKey?.();
  if (!publicKey) {
    throw new Error('This browser or authenticator did not provide an ES256 public key');
  }

  return {
    credentialId: toBase64Url(credential.rawId),
    authenticatorData: toBase64Url(response.getAuthenticatorData()),
    clientDataJSON: toBase64Url(response.clientDataJSON),
    publicKey: toBase64Url(publicKey),
  };
}

export interface BeginLogin {
  challenge: string;
  rpId: string;
  allowCredentials: string[];
}

export interface FinishAssertion {
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
}

export async function getPasskeyAssertion(opts: BeginLogin): Promise<FinishAssertion> {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: fromBase64Url(opts.challenge),
      rpId: opts.rpId,
      allowCredentials: opts.allowCredentials.map((id) => ({
        type: 'public-key' as const,
        id: fromBase64Url(id),
      })),
      userVerification: 'preferred',
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('Passkey sign-in was cancelled');

  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    credentialId: toBase64Url(credential.rawId),
    authenticatorData: toBase64Url(response.authenticatorData),
    clientDataJSON: toBase64Url(response.clientDataJSON),
    signature: toBase64Url(response.signature),
  };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd web && npx vitest run src/webauthn.test.ts && npm run build`
Expected: PASS, and the build (which is `tsc && vite build`) succeeds.

- [ ] **Step 5: Commit**

```bash
git add web/src/webauthn.ts web/src/webauthn.test.ts
git commit -m "feat(web): add webauthn ceremony helpers"
```

---

## Task 7: Enrolment and login UI

**Files:**
- Modify: `web/src/types.ts`
- Modify: `web/src/components/DeviceSettings.tsx`
- Modify: `web/src/components/LoginView.tsx`
- Modify: `web/src/index.css` (only if a new class is genuinely needed)

**Interfaces:**
- Consumes: Task 6's helpers, Tasks 3–5's endpoints.
- Produces: no exported API; user-visible behaviour.

- [ ] **Step 1: Add the type**

In `web/src/types.ts`, after the `NativeDevice` interface:

```ts
export interface Passkey {
  id: string;
  name: string;
  backupEligible: boolean;
  backupState: boolean;
  lastUsedAt?: string;
  createdAt: string;
}
```

- [ ] **Step 2: Add enrolment to DeviceSettings**

Read `web/src/components/DeviceSettings.tsx` first and follow its existing patterns for `apiJson`, step-up handling (`isStepUpRequired`), loading state and error display. Add:

- A `passkeys` state array loaded from `GET /api/user/passkeys` on mount, alongside the existing device load.
- An "Add passkey" button, hidden when `!isPasskeySupported()`, that runs:

```ts
const enrollPasskey = async () => {
  setError('');
  try {
    const begun = await apiJson<BeginRegistration>('/api/user/passkeys/register/begin', parseBeginRegistration, {
      method: 'POST',
      body: JSON.stringify({ name: passkeyName || 'Passkey' }),
    });
    const finished = await createPasskey(begun);
    await apiJson('/api/user/passkeys/register/finish', parseSuccess, {
      method: 'POST',
      body: JSON.stringify({ ...finished, name: passkeyName || 'Passkey' }),
    });
    await loadPasskeys();
    setPasskeyName('');
  } catch (err) {
    if (isStepUpRequired(err)) throw err; // let the existing step-up prompt handle it
    setError(errorMessage(err, 'Could not enrol that passkey'));
  }
};
```

- A list rendering each passkey's name, `createdAt`, `lastUsedAt`, and a badge reading `Synced` when `backupEligible` is true and `Device-bound` when it is false, with a `title` explaining that a synced passkey is stored in the provider's cloud.
- A Remove button per row calling `DELETE /api/user/passkeys/{id}`, routed through the same step-up prompt path the other destructive settings actions already use.

Add `parseBeginRegistration` and `parseSuccess` to `web/src/parsers.ts` following the shape of the parsers already there (they validate the response before it is trusted; do not cast).

- [ ] **Step 3: Add the login mode**

In `web/src/components/LoginView.tsx`:

- Widen the mode union at line 21: `useState<'push' | 'totp' | 'recovery' | 'webauthn'>('push')`.
- In the `resp.mfaRequired` branch (line 45), prefer `webauthn` when the server offers it and the browser supports it, before falling back to push then TOTP:

```ts
if (resp.mfaMethods?.includes('webauthn') && isPasskeySupported()) {
  setMfaMode('webauthn');
} else if (resp.mfaMethods?.includes('push')) {
  setMfaMode('push');
} else {
  setMfaMode('totp');
}
```

- Add the handler:

```ts
const submitPasskey = async () => {
  setError('');
  setLoading(true);
  try {
    const begun = await apiJson<BeginLogin>('/api/auth/mfa/webauthn/begin', parseBeginLogin, {
      method: 'POST',
      body: JSON.stringify({ mfaToken }),
    });
    const assertion = await getPasskeyAssertion(begun);
    const resp = await apiJson('/api/auth/mfa/webauthn/verify', parseAuthStep, {
      method: 'POST',
      body: JSON.stringify({ mfaToken, ...assertion }),
    });
    onAuthenticated(resp);
  } catch (err) {
    setError(errorMessage(err, 'Passkey sign-in failed'));
  } finally {
    setLoading(false);
  }
};
```

  Match `onAuthenticated`/`parseAuthStep` to whatever the existing TOTP path at line 142 actually calls; do not introduce a second success path.

- Render a `mfaMode === 'webauthn'` block in the `mfa-challenge-container`, reusing `push-icon-circle` and `mfa-desc`, with a primary button that calls `submitPasskey` and links in `mfa-alt-links` to switch to `totp` and `recovery`.
- Add the reciprocal link from the TOTP and push blocks back to `webauthn`, shown only when the server offered it.

- [ ] **Step 4: Verify**

Run: `cd web && npm test && npm run build`
Expected: PASS and a clean build.

Then run the app and confirm the ceremony end to end against a real authenticator:

```bash
go build -o kyidentity . && KYIDENTITY_ISSUER_URL=http://localhost:5867 ./kyidentity
```

Enrol a passkey from Settings, sign out, sign in with it. Note that browsers permit WebAuthn on `http://localhost` but nowhere else without TLS; testing against a LAN IP will fail in the browser, not in this code.

- [ ] **Step 5: Commit**

```bash
git add web/src
git commit -m "feat(web): enrol and sign in with passkeys"
```

---

## Task 8: Documentation

**Files:**
- Modify: `README.md`, `design.md`, `AGENTS.md`

- [ ] **Step 1: README — capabilities and integration rules**

In "Core Capabilities", extend item 3 (MFA) with:

```markdown
   - **Passkeys (WebAuthn)**: ES256 platform and roaming authenticators as a second factor,
     verified with the standard library alone. Works with KyAuth's Android credential
     provider, and with iCloud Keychain, Windows Hello and hardware keys.
```

In "Integration Requirements", add:

```markdown
**Passkeys are bound to the issuer's origin.** The relying party ID is the hostname of
`KYIDENTITY_ISSUER_URL` and the accepted origin is its scheme, host and port. Changing the
issuer URL invalidates every enrolled passkey, because the browser will not offer a
credential registered under a different RP ID. Browsers permit WebAuthn over plain HTTP only
on `localhost`, so a deployment reached by IP or by a name without TLS cannot enrol one.

**Enrolling or removing a passkey spends a step-up grant**, like every other change to an
account's factors. Resetting a user's MFA deletes their passkeys along with their TOTP
secret and recovery codes.
```

- [ ] **Step 2: design.md — move passkeys out of "Deferred"**

In section 2, add to "Included":

```markdown
- **Passkeys (WebAuthn Level 2)**: ES256 credentials as a second factor, with single-use
  server-issued challenges, signature-counter clone detection, and backup-eligibility
  recorded per credential. Attestation is not verified; passwordless sign-in is deferred.
```

In section 8, add a row to the roles table:

```markdown
| Enrol and remove personal passkeys | Yes | Yes |
```

In section 9, add:

```markdown
- **Passkey Verification**: WebAuthn assertions are ES256 only, verified with `crypto/ecdsa`
  against an SPKI public key recorded at enrolment. Challenges are 256-bit, single-use,
  bound to one user and one ceremony purpose, and expire in three minutes. A signature
  counter that fails to advance rejects the assertion unless the authenticator reports zero
  throughout.
```

- [ ] **Step 3: AGENTS.md — record the boundary**

Add to the root `AGENTS.md`, in whichever section holds the equivalent notes for other subsystems:

```markdown
## WebAuthn

`internal/webauthn` is pure verification: no database, no HTTP, no CBOR. It reads the SPKI
public key and raw authenticator data the browser exports, because attestation is not
verified and re-deriving those from the attestation object would buy nothing.

KyIdentity records whether a passkey is backup-eligible but never rejects one for it. The rule
that a KyIdentity login credential must live in KyAuth's device-local `totp_vault.kdbx` rather
than the KyPasswords-synced `passwords_vault.kdbx` is enforced in KyAuth, where the vault is
chosen.
```

- [ ] **Step 4: Verify and commit**

Run the full gate:

```bash
gofmt -l .
go build ./... && go vet ./... && go test -race -count=1 ./...
govulncheck ./...
cd web && npm test && npm run build
```

Expected: `gofmt -l .` prints nothing; everything else passes.

```bash
git add README.md design.md AGENTS.md
git commit -m "docs: record passkey support and the vault boundary"
```

---

## Self-review notes

- **Spec coverage.** `design.md` section 2 (MVP scope) gains passkeys in Task 8; section 8 (roles) gains the user capability; section 9 (crypto requirements) gains the verification rules. The "no new dependencies" constraint from `README.md`'s architecture section holds — every import used here is stdlib or already present. `SECURITY.md` needs no change: no new secret material is stored, since a WebAuthn public key is not a secret.
- **The step-up contract** in `README.md` says creating or editing account factors costs a step-up grant. Tasks 3 and 5 honour it: `BeginRegistration` checks, `FinishRegistration` and `DeletePasskey` spend.
- **Known gap, deliberate:** the ID token gains no `amr` claim, so a downstream service cannot tell that a passkey was used. Adding it means touching `internal/oauth/oauth.go:315` and the discovery `claims_supported` list. Out of scope here; raise it as its own change if a downstream service needs it.

---

## Companion plans (not covered here)

These come from the same analysis and are deliberately separate — each produces working software on its own, and each lives in a different repository.

**Plan 1b — Passwordless passkey login (KyIdentity).** Discoverable credentials, a `userHandle` → user lookup, and a challenge issued before any user is known. Depends on this plan. Only worth doing if you want to drop the password step entirely.

**Plan 2 — KyAuth vault placement (`kyauth-android`).** Route KyIdentity login passkeys into the device-local `totp_vault.kdbx` instead of the KyPasswords-synced `passwords_vault.kdbx`, or tag them non-syncable. This is what actually enforces `design.md:41` ("MFA independent of password vault"); the server records the flag but cannot enforce it. **Do this immediately after this plan** — until it lands, a user enrolling from KyAuth may put their KyIdentity factor in the synced vault.

**Plan 3 — KyPassword becomes OIDC-only (`kypassword-server`).** Delete `internal/users`' local directory role, keeping only the vault-unlock verifier that cryptographically cannot move to KyIdentity. Removes the duplicate account store and makes KyIdentity the single directory.

**Plan 4 — Shared pairing and audit code (`ky_server_base`).** `zero_code_pairing_handoff_spec.md` is byte-identical across `kyidentity-server` and `kypassword-server` (md5 `24899bae8d11ac740c58dcc5c3581e32`), and both implement 90-second PIN/QR pairing and a hash-chained audit trail separately. Consolidate into `ky_server_base`. Lowest urgency, highest blast radius — do it last, behind full test coverage on both callers.
