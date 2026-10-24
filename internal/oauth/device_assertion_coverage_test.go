package oauth

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// covRaw opens a second connection on the fixture's database for state the store
// does not expose, and for injecting write failures.
func (f *signOnFixture) covRaw(t *testing.T) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", f.dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return raw
}

func (f *signOnFixture) covExchange(t *testing.T, compact string) (*TokenResponse, DeviceSignOnActor, error) {
	t.Helper()
	return f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test")
}

// A structurally broken JWS is refused before any device lookup: no identity is
// reported and no session is created.
func TestExchangeDeviceAssertionRejectsMalformedJWS(t *testing.T) {
	f := newSignOnFixture(t)
	valid := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	parts := strings.Split(valid, ".")
	b64 := base64.RawURLEncoding.EncodeToString
	cases := map[string]string{
		"header not base64url": "!!!." + parts[1] + "." + parts[2],
		"header not JSON":      b64([]byte("not json")) + "." + parts[1] + "." + parts[2],
		"claims not base64url": parts[0] + ".***." + parts[2],
		"claims not JSON":      parts[0] + "." + b64([]byte("[1,2")) + "." + parts[2],
		"signature not base64": parts[0] + "." + parts[1] + ".@@@",
		"padded signature":     parts[0] + "." + parts[1] + "." + parts[2] + "==",
	}
	before := f.sessionCount(t)
	for name, compact := range cases {
		resp, who, err := f.covExchange(t, compact)
		if err == nil || resp != nil {
			t.Errorf("%s: accepted", name)
		}
		if who != (DeviceSignOnActor{}) {
			t.Errorf("%s: reported identity %+v for an unverified assertion", name, who)
		}
	}
	if after := f.sessionCount(t); after != before {
		t.Fatalf("malformed assertions created %d session(s)", after-before)
	}
	// The untouched assertion still works: the refusals did not consume its jti.
	if _, _, err := f.covExchange(t, valid); err != nil {
		t.Fatalf("valid assertion after refusals: %v", err)
	}
}

// Origin binding tolerates a corrupt redirect entry without matching it, and a
// corrupt registration matches nothing.
func TestRegisteredOriginSkipsUnparsableEntries(t *testing.T) {
	if registeredOrigin(`{not json`, "https://kypost.local") {
		t.Fatal("corrupt registration matched an origin")
	}
	if !registeredOrigin(`["https://[::1/cb", "https://kypost.local/callback"]`, "https://kypost.local") {
		t.Fatal("a corrupt sibling entry hid a registered origin")
	}
	if registeredOrigin(`["https://[::1/cb"]`, "https://[::1]") {
		t.Fatal("an unparsable entry matched")
	}
}

// A device token never outlives the user's access grant.
func TestExchangeDeviceAssertionBoundedByAccessGrant(t *testing.T) {
	f := newSignOnFixture(t)
	a := appFor(t, f.db, f.client.ID)
	if err := f.db.SetAppPolicy(a.ID, "assigned_only", true, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	until := time.Now().UTC().Add(5 * time.Minute).Truncate(time.Second)
	if err := f.db.SetAppAssignmentUntil(a.ID, "users", f.user.ID, &until, nil); err != nil {
		t.Fatal(err)
	}
	resp, _, err := f.covExchange(t, signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.ExpiresIn <= 0 || resp.ExpiresIn > 300 {
		t.Fatalf("expires_in %d outlives the 300s grant", resp.ExpiresIn)
	}
	claims, err := f.engine.keyManager.VerifyJWT(resp.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	if exp, _ := claims["exp"].(float64); int64(exp) != until.Unix() {
		t.Fatalf("id token exp %v, want %d", claims["exp"], until.Unix())
	}
}

// An account whose end date has passed reads as inactive: refused, with no session.
func TestExchangeDeviceAssertionRefusesEndedAccount(t *testing.T) {
	f := newSignOnFixture(t)
	if _, err := f.covRaw(t).Exec(`UPDATE users SET ends_at=unixepoch()-60 WHERE id=?`, f.user.ID); err != nil {
		t.Fatal(err)
	}
	before := f.sessionCount(t)
	resp, who, err := f.covExchange(t, signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil)))
	if !errors.Is(err, errUserInactive) || resp != nil {
		t.Fatalf("ended account: %+v %v", resp, err)
	}
	if who.DeviceID != "dev-1" {
		t.Fatalf("verified device not reported for audit: %+v", who)
	}
	if f.sessionCount(t) != before || f.issuedTokenCount(t) != 0 {
		t.Fatal("refusal left a session or token behind")
	}
}

// A lost write anywhere in issuance refuses the sign-on and never leaves an orphaned
// device session: the deferred cleanup removes it.
func TestExchangeDeviceAssertionFailsClosedOnStoreErrors(t *testing.T) {
	for _, table := range []string{"device_signon_jtis", "sessions", "issued_tokens", "oidc_client_sessions"} {
		t.Run(table, func(t *testing.T) {
			f := newSignOnFixture(t)
			covFailWrites(t, f.covRaw(t), table, "INSERT")
			before := f.sessionCount(t)
			resp, _, err := f.covExchange(t, signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil)))
			if err == nil || resp != nil {
				t.Fatalf("issued despite a failed %s insert: %+v", table, resp)
			}
			// A storage fault is not a policy verdict; it must not be audited as one.
			if errors.Is(err, ErrDeviceSignOnNotPermitted) || errors.Is(err, ErrDeviceSignOnDisabled) {
				t.Fatalf("storage fault reported as a policy refusal: %v", err)
			}
			if after := f.sessionCount(t); after != before {
				t.Fatalf("failed issuance left %d device session(s)", after-before)
			}
		})
	}
}

// Oversized identity claims refuse the device sign-on and clean up its session.
func TestExchangeDeviceAssertionRefusesOversizedClaims(t *testing.T) {
	f := newSignOnFixture(t)
	a := appFor(t, f.db, f.client.ID)
	for i := 0; i < 120; i++ {
		r, err := f.db.CreateAppRole(a.ID, "role-"+strings.Repeat("x", 40)+"-"+string(rune('a'+i%26))+string(rune('a'+i/26)), "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.db.SetAppRoleAssignment(a.ID, r.ID, "users", f.user.ID, true, nil); err != nil {
			t.Fatal(err)
		}
	}
	before := f.sessionCount(t)
	_, _, err := f.covExchange(t, signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil)))
	if !errors.Is(err, ErrClaimsTooLarge) {
		t.Fatalf("oversized claims: %v", err)
	}
	if after := f.sessionCount(t); after != before {
		t.Fatalf("refusal left %d session(s)", after-before)
	}
}
