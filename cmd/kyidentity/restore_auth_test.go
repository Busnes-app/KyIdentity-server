package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoverykey"
)

// sealDB seals a capsule holding one database file to pub, as anyone holding the public
// recovery key can.
func sealDB(t *testing.T, pub recoverykey.PublicKey, db string) []byte {
	t.Helper()
	raw, _, err := capsule.Seal("KySignOn", "1.0.0", []capsule.File{{Path: "data/kyidentity.db", Content: []byte(db), Mode: 0600}}, nil, nil, 2, 3, pub)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The recovery public key is not secret, so an attacker who can write the backup directory
// can seal a capsule with their own administrator and keys that opens with the real
// custodian shares. Restore must refuse it before writing anything, and accept only the
// capsule whose digest the deposit record holds.
func TestRestoreOpensOnlyTheDepositedCapsule(t *testing.T) {
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	split, err := recoverykey.Split(priv, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	shares := split[0].String() + "\n" + split[2].String() + "\n"
	genuine := sealDB(t, priv.Public(), "genuine")
	planted := sealDB(t, priv.Public(), "attacker admin")

	dir := t.TempDir()
	capPath := filepath.Join(dir, "KySignOn.cap.kycap")
	target := filepath.Join(dir, "restored")
	run := func(args ...string) error {
		return restoreCommand(append([]string{"-capsule", capPath, "-to", target, "-service", "KySignOn"}, args...),
			strings.NewReader(shares), io.Discard, io.Discard, false)
	}
	untouched := func(why string) {
		t.Helper()
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("%s: restore wrote the target: %v", why, err)
		}
	}

	if err := os.WriteFile(capPath, planted, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil || !strings.Contains(err.Error(), "-expect-digest is required") {
		t.Fatalf("restore without a digest: %v", err)
	}
	untouched("no digest")
	if err := run("-expect-digest", sha256Hex(genuine)); err == nil || !strings.Contains(err.Error(), "did not deposit") {
		t.Fatalf("planted capsule restored against the genuine digest: %v", err)
	}
	untouched("planted capsule")
	if err := run("-expect-digest", "abc"); err == nil {
		t.Fatal("a malformed digest was accepted")
	}
	untouched("malformed digest")

	if err := os.WriteFile(capPath, genuine, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run("-expect-digest", strings.ToUpper(sha256Hex(genuine))); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(target, "data", "kyidentity.db")); err != nil || string(got) != "genuine" {
		t.Fatalf("restored database = %q, %v", got, err)
	}
	body, err := os.ReadFile(filepath.Join(target, "data", restoreMarkerName))
	if err != nil {
		t.Fatal(err)
	}
	var marker restoreMarker
	if err := json.Unmarshal(body, &marker); err != nil || marker.Digest != sha256Hex(genuine) {
		t.Fatalf("marker does not record the verified digest: %s %v", body, err)
	}
}

// The override restores without a digest, says so, and the marker records it as unverified.
func TestRestoreUnauthenticatedOverrideIsExplicit(t *testing.T) {
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	split, err := recoverykey.Split(priv, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	capPath := filepath.Join(dir, "x.kycap")
	if err := os.WriteFile(capPath, sealDB(t, priv.Public(), "db"), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "restored")
	var stderr strings.Builder
	args := []string{"-capsule", capPath, "-to", target, "-service", "KySignOn", "-accept-unauthenticated-capsule"}
	if err := restoreCommand(append(args, "-expect-digest", sha256Hex([]byte("x"))), strings.NewReader(""), io.Discard, &stderr, false); err == nil {
		t.Fatal("both a digest and the override were accepted")
	}
	if err := restoreCommand(args, strings.NewReader(split[0].String()+"\n"+split[1].String()+"\n"), io.Discard, &stderr, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "WARNING") {
		t.Fatal("the override restored silently")
	}
	body, err := os.ReadFile(filepath.Join(target, "data", restoreMarkerName))
	if err != nil || strings.Contains(string(body), `"digest"`) {
		t.Fatalf("marker claims a digest for an unauthenticated restore: %s %v", body, err)
	}
}
