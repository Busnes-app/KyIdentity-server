package backup_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
)

// A snapshot past capsule.MaxFileBytes is split into ordered members the capsule accepts,
// and the restore side joins them back into the same bytes; one that fits stays a single
// member, as every earlier capsule has it.
func TestLargeDatabaseIsSplitAndJoinedBack(t *testing.T) {
	cfg, st := instance(t)
	priv := pair(t, cfg, st)
	key, err := backup.LoadRecoveryKey(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	db := bytes.Repeat([]byte("kyidentity"), int(capsule.MaxFileBytes/10)+2)
	p, err := backup.CollectSealable(cfg, snapshotFunc(func(dest string) error { return os.WriteFile(dest, db, 0600) }), "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if fileData(t, p.Files, "data/kyidentity.db.part000") == nil || fileData(t, p.Files, "data/kyidentity.db.part001") == nil {
		t.Fatalf("snapshot of %d bytes not split", len(db))
	}
	if req, _ := p.VerificationRecipe["required_files"].([]string); !slices.Contains(req, "data/kyidentity.db") || slices.Contains(req, "data/kyidentity.db.part001") {
		t.Fatalf("required_files must name the joined database: %v", req)
	}
	raw, _, err := backup.Seal(p.ServiceName, p.AppVersion, p.Files, p.Dependencies, p.VerificationRecipe, key)
	if err != nil {
		t.Fatalf("a split snapshot must seal: %v", err)
	}
	dir := t.TempDir()
	if _, _, err := capsule.Open(raw, priv, dir); err != nil {
		t.Fatal(err)
	}
	if err := backup.JoinDatabaseParts(dir); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "data/kyidentity.db")); err != nil || !bytes.Equal(got, db) {
		t.Fatalf("joined database differs (%d bytes, %v)", len(got), err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "data/kyidentity.db.part*")); len(left) != 0 {
		t.Fatalf("parts left after joining: %v", left)
	}

	// A single-member capsule needs nothing; a gap in the parts is refused.
	if err := backup.JoinDatabaseParts(dir); err != nil {
		t.Fatalf("single member: %v", err)
	}
	gap := t.TempDir()
	if err := os.MkdirAll(filepath.Join(gap, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kyidentity.db.part000", "kyidentity.db.part002"} {
		if err := os.WriteFile(filepath.Join(gap, "data", name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := backup.JoinDatabaseParts(gap); err == nil {
		t.Fatal("non-consecutive parts joined")
	}
}

// A relay key supplied by environment never reaches the disk; the capsule carries it where
// a restored server without the variable reads it, over any stale file.
func TestCapsuleCarriesTheEnvironmentRelayKey(t *testing.T) {
	cfg, st := instance(t)
	cfg.PushRelayURL, cfg.PushRelayKey = "https://relay.example.test", "env-key"
	stale := mfa.RelayKeyFile(cfg.DataDir, "fcm", cfg.PushRelayURL)
	if err := os.WriteFile(stale, []byte("stale-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := backup.CollectSealable(cfg, st, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	member := "data/" + filepath.Base(stale)
	if got := string(fileData(t, p.Files, member)); got != "env-key\n" {
		t.Fatalf("%s = %q, want the configured key", member, got)
	}
	n := 0
	for _, f := range p.Files {
		if f.Path == member {
			n++
		}
	}
	if n != 1 || !slices.Contains(backup.Members(cfg), member) {
		t.Fatalf("%s appears %d times; members %v", member, n, backup.Members(cfg))
	}
}
