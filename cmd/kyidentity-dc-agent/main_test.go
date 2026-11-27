package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/Busnes-app/ky-primitives/hybridsig"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/adpass"
	"github.com/Busnes-app/kyidentity-server/internal/ldaptest"
	"github.com/go-ldap/ldap/v3"
)

const (
	testOU     = "OU=KyIdentity,DC=kyws,DC=test"
	testBindDN = "CN=kyidentity-agent,CN=Users,DC=kyws,DC=test"
	connector  = "sys-1"
)

// fakeQueue serves the agent endpoints and records results.
type fakeQueue struct {
	mu      sync.Mutex
	entries []entry
	results map[string]map[string]string
	token   string
}

func (q *fakeQueue) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+q.token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodGet {
		_ = json.NewEncoder(w).Encode(map[string]any{"connectorId": connector, "entries": q.entries})
		return
	}
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	q.results[strings.TrimPrefix(r.URL.Path, "/api/ad-agent/v1/passwords/")] = body
	w.Write([]byte(`{"success":true}`))
}

type fixture struct {
	sign  ed25519.PrivateKey
	agent *agent
	dc    *ldaptest.Server
	queue *fakeQueue
	logs  *bytes.Buffer
	dir   string
}

func writeSecret(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	dc := ldaptest.Start(t)
	dc.Users[strings.ToLower(testBindDN)] = "agent-secret"
	q := &fakeQueue{results: map[string]map[string]string{}, token: "kyad_test"}
	srv := httptest.NewServer(q)
	t.Cleanup(srv.Close)
	writeSecret(t, filepath.Join(dir, "token"), "kyad_test\n")
	writeSecret(t, filepath.Join(dir, "bind"), "agent-secret")
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte(dc.CAPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	cfg := config{KyIdentityURL: srv.URL, SigningKey: adpass.EncodeSigningKey(pub), ConnectorID: connector, TokenFile: filepath.Join(dir, "token"), KeyFile: filepath.Join(dir, "agent.key"),
		StateFile: filepath.Join(dir, "state.json"), LDAPSURL: dc.URL, CAFile: filepath.Join(dir, "ca.pem"), BindDN: testBindDN,
		BindPasswordFile: filepath.Join(dir, "bind"), BaseDN: testOU}
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateKey(cfg.KeyFile); err != nil {
		t.Fatal(err)
	}
	a, err := newAgent(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &fixture{sign: priv, agent: a, dc: dc, queue: q, logs: logs, dir: dir}
}

func (f *fixture) account(userID string) string {
	dn := "CN=" + userID + "," + testOU
	f.dc.Put(dn, map[string][]string{"sAMAccountName": {userID}, "adminDescription": {adpass.Marker(connector, "user", userID)}})
	return dn
}

func (f *fixture) seal(t *testing.T, userID string, seq int64, password string) entry {
	t.Helper()
	ct, err := adpass.Seal(adpass.EncodePublicKey(f.agent.key.PublicKey()), connector, userID, seq, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	e := entry{UserID: userID, Seq: seq, ExpiresAt: time.Now().Add(time.Hour).Unix(), Ciphertext: ct}
	e.Signature = adpass.SignEntry(f.sign, connector, userID, seq, e.ExpiresAt, ct)
	return e
}

func (f *fixture) run(t *testing.T, entries ...entry) {
	t.Helper()
	f.queue.mu.Lock()
	f.queue.entries = entries
	f.queue.results = map[string]map[string]string{}
	f.queue.mu.Unlock()
	if err := f.agent.pass(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) result(userID string, seq int64) map[string]string {
	return f.queue.results[userID+"/"+strconv.FormatInt(seq, 10)]
}

func TestAgentSetsPasswordsInOrderAndRefusesReplays(t *testing.T) {
	f := newFixture(t)
	dn := f.account("alice")
	f.run(t, f.seal(t, "alice", 10, "First-Pass-1"))
	if got := f.dc.Get(dn).Attrs["unicodePwd"]; len(got) != 1 || got[0] != adpass.UnicodePwd("First-Pass-1") {
		t.Fatal("password not set", got)
	}
	if r := f.result("alice", 10); r["outcome"] != "applied" {
		t.Fatal(r)
	}
	f.run(t, f.seal(t, "alice", 20, "Second-Pass-2"))
	if f.dc.Get(dn).Attrs["unicodePwd"][0] != adpass.UnicodePwd("Second-Pass-2") {
		t.Fatal("password change not applied")
	}
	// An older entry, even one correctly sealed for this user, is refused.
	f.run(t, f.seal(t, "alice", 15, "Old-Pass-1"))
	if r := f.result("alice", 15); r["outcome"] != "rejected" || r["reason"] != "replay_refused" {
		t.Fatal("out-of-order entry", r)
	}
	if f.dc.Get(dn).Attrs["unicodePwd"][0] != adpass.UnicodePwd("Second-Pass-2") {
		t.Fatal("an out-of-order entry changed the password")
	}
	// A lost acknowledgement is acknowledged again without another write.
	f.run(t, f.seal(t, "alice", 20, "Second-Pass-2"))
	if r := f.result("alice", 20); r["outcome"] != "applied" {
		t.Fatal(r)
	}
	// The applied sequence survives a restart.
	again, err := newAgent(filepath.Join(f.dir, "config.json"))
	if err != nil || again.state["alice"] != 20 {
		t.Fatal("state not kept", again, err)
	}
	if info, _ := os.Stat(filepath.Join(f.dir, "state.json")); info.Mode().Perm() != 0o600 {
		t.Fatal("state file mode", info.Mode())
	}
	if strings.Contains(f.logs.String(), "Pass-") {
		t.Fatal("a password reached the log:", f.logs.String())
	}
}

func TestAgentRefusesCiphertextMovedToAnotherUser(t *testing.T) {
	f := newFixture(t)
	aliceDN, bobDN := f.account("alice"), f.account("bob")
	moved := f.seal(t, "alice", 10, "Alice-Pass-1")
	moved.UserID = "bob"
	f.run(t, moved)
	if r := f.result("bob", 10); r["outcome"] != "rejected" || r["reason"] != "signature_invalid" {
		t.Fatal("moved entry kept its signature", r)
	}
	// Even signed for bob, alice's ciphertext does not open as bob's.
	moved.Signature = adpass.SignEntry(f.sign, connector, "bob", 10, moved.ExpiresAt, moved.Ciphertext)
	f.run(t, moved)
	if r := f.result("bob", 10); r["outcome"] != "rejected" || r["reason"] != "decrypt_failed" {
		t.Fatal("replayed onto another user", r)
	}
	for _, dn := range []string{aliceDN, bobDN} {
		if len(f.dc.Get(dn).Attrs["unicodePwd"]) != 0 {
			t.Fatal("a password was set from a moved ciphertext")
		}
	}
	other, _ := adpass.GenerateKey()
	foreign, _ := adpass.Seal(adpass.EncodePublicKey(other.PublicKey()), connector, "alice", 11, []byte("x"))
	exp := time.Now().Add(time.Hour).Unix()
	f.run(t, entry{UserID: "alice", Seq: 11, ExpiresAt: exp, Ciphertext: foreign, Signature: adpass.SignEntry(f.sign, connector, "alice", 11, exp, foreign)})
	if r := f.result("alice", 11); r["reason"] != "decrypt_failed" {
		t.Fatal("ciphertext for another key", r)
	}
}

func TestAgentReportsDirectoryRejectionWithoutThePassword(t *testing.T) {
	f := newFixture(t)
	f.account("alice")
	f.dc.ModifyResult = func(dn string, attrs []string) uint16 { return ldap.LDAPResultConstraintViolation }
	f.run(t, f.seal(t, "alice", 10, "short"))
	r := f.result("alice", 10)
	if r["outcome"] != "rejected" || r["reason"] != "password_policy" {
		t.Fatal("rejection", r)
	}
	if f.agent.state["alice"] != 0 {
		t.Fatal("a rejected password counted as applied")
	}
	f.dc.ModifyResult = nil
	f.run(t, f.seal(t, "nobody", 12, "Valid-Pass-1"))
	if r := f.result("nobody", 12); r["outcome"] != "retry" || r["reason"] != "user_not_found" {
		t.Fatal("missing account", r)
	}
	if strings.Contains(f.logs.String(), "short") || strings.Contains(f.logs.String(), "Valid-Pass") {
		t.Fatal("a password reached the log:", f.logs.String())
	}
}

func TestAgentRefusesAnotherConnectorsTokenAndPlainHTTP(t *testing.T) {
	f := newFixture(t)
	f.agent.cfg.ConnectorID = "sys-2"
	if err := f.agent.pass(context.Background()); err == nil || !strings.Contains(err.Error(), "another connector") {
		t.Fatal("served another connector's queue:", err)
	}
	f.agent.token = "kyad_wrong"
	if err := f.agent.pass(context.Background()); err == nil {
		t.Fatal("wrong token accepted")
	}
	raw, _ := os.ReadFile(filepath.Join(f.dir, "config.json"))
	var cfg config
	_ = json.Unmarshal(raw, &cfg)
	cfg.KyIdentityURL = "http://kyidentity.example.org"
	raw, _ = json.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(f.dir, "config.json"), raw, 0o644)
	if _, err := newAgent(filepath.Join(f.dir, "config.json")); err == nil {
		t.Fatal("plain http to a remote host accepted")
	}
}

func TestAgentRefusesUnsignedAndExpiredEntries(t *testing.T) {
	f := newFixture(t)
	dn := f.account("alice")
	// Anyone with the public key can encrypt; a database writer cannot sign.
	forged := f.seal(t, "alice", 10, "Forged-Pass-1")
	_, attacker, _ := ed25519.GenerateKey(nil)
	forged.Signature = adpass.SignEntry(attacker, connector, "alice", 10, forged.ExpiresAt, forged.Ciphertext)
	unsigned := f.seal(t, "alice", 11, "Unsigned-Pass-1")
	unsigned.Signature = ""
	stretched := f.seal(t, "alice", 12, "Stretched-Pass-1")
	stretched.ExpiresAt += 3600
	expired := f.seal(t, "alice", 13, "Expired-Pass-1")
	expired.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	expired.Signature = adpass.SignEntry(f.sign, connector, "alice", 13, expired.ExpiresAt, expired.Ciphertext)
	f.run(t, forged, unsigned, stretched, expired)
	for seq, want := range map[int64]string{10: "signature_invalid", 11: "signature_invalid", 12: "signature_invalid", 13: "expired"} {
		if r := f.result("alice", seq); r["outcome"] != "rejected" || r["reason"] != want {
			t.Errorf("seq %d: %v", seq, r)
		}
	}
	if len(f.dc.Get(dn).Attrs["unicodePwd"]) != 0 || f.agent.state["alice"] != 0 {
		t.Fatal("an unauthenticated entry changed the directory password")
	}
}

func TestAgentKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.key")
	k, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(raw), "xwing-private:") {
		t.Fatal("new key is not X-Wing")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatal("key file mode", info.Mode())
	}
	again, err := loadOrCreateKey(path)
	if err != nil || adpass.EncodePrivateKey(again) != adpass.EncodePrivateKey(k) {
		t.Fatal("key not reloaded", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateKey(path); err == nil {
		t.Fatal("a world-readable key was used")
	}
}

func TestRunRefusesAMissingKey(t *testing.T) {
	f := newFixture(t)
	if err := os.Remove(f.agent.cfg.KeyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := newAgent(filepath.Join(f.dir, "config.json")); err == nil || !strings.Contains(err.Error(), "init") {
		t.Fatal("run started without its key", err)
	}
	if _, err := os.Stat(f.agent.cfg.KeyFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("run created a key file", err)
	}
}

func TestAgentAcknowledgesNothingUntilItsStateIsSaved(t *testing.T) {
	f := newFixture(t)
	f.account("alice")
	saved := f.agent.cfg.StateFile
	f.agent.cfg.StateFile = filepath.Join(f.dir, "missing", "state.json")
	e := f.seal(t, "alice", 10, "First-Pass-1")
	f.queue.mu.Lock()
	f.queue.entries, f.queue.results = []entry{e}, map[string]map[string]string{}
	f.queue.mu.Unlock()
	if err := f.agent.pass(context.Background()); err == nil {
		t.Fatal("a pass whose state was not saved succeeded")
	}
	if r := f.result("alice", 10); r["outcome"] != "retry" {
		t.Fatal("unsaved state was acknowledged", r)
	}
	// The server serves the entry again: while the state is still unsaved, nothing is
	// acknowledged, including the equal sequence the agent holds in memory.
	f.queue.mu.Lock()
	f.queue.results = map[string]map[string]string{}
	f.queue.mu.Unlock()
	if err := f.agent.pass(context.Background()); err == nil || len(f.queue.results) != 0 {
		t.Fatal("acknowledged work with the state unsaved", err, f.queue.results)
	}
	f.agent.cfg.StateFile = saved
	f.run(t, e)
	if r := f.result("alice", 10); r["outcome"] != "applied" {
		t.Fatal(r)
	}
	again, err := newAgent(filepath.Join(f.dir, "config.json"))
	if err != nil || again.state["alice"] != 10 {
		t.Fatal("an acknowledged sequence did not survive a restart", again, err)
	}
}

func TestAgentHybridEntryAuthentication(t *testing.T) {
	f := newFixture(t)
	dn := f.account("alice")
	k, err := hybridsig.Generate()
	if err != nil {
		t.Fatal(err)
	}
	f.agent.signing, err = adpass.ParseSigningKey(adpass.EncodeHybridSigningKey(k.Public()))
	if err != nil {
		t.Fatal(err)
	}
	e := f.seal(t, "alice", 10, "Hybrid-Pass-1")
	e.Signature, err = adpass.SignHybridEntry(k, connector, e.UserID, e.Seq, e.ExpiresAt, e.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(e.Signature)
	for _, i := range []int{len(hybridsig.Alg) + 1, len(raw) - 1} {
		changed := bytes.Clone(raw)
		changed[i] ^= 1
		bad := e
		bad.Signature = base64.StdEncoding.EncodeToString(changed)
		f.run(t, bad)
		if r := f.result("alice", 10); r["reason"] != "signature_invalid" {
			t.Fatal("invalid half applied", r)
		}
	}
	f.run(t, f.seal(t, "alice", 10, "Legacy-Signature-1"))
	if r := f.result("alice", 10); r["reason"] != "signature_invalid" {
		t.Fatal("legacy signature accepted under hybrid pin", r)
	}
	if len(f.dc.Get(dn).Attrs["unicodePwd"]) != 0 {
		t.Fatal("invalid signature changed directory")
	}
	f.run(t, e)
	if r := f.result("alice", 10); r["outcome"] != "applied" {
		t.Fatal("hybrid entry not applied", r)
	}
	if f.dc.Get(dn).Attrs["unicodePwd"][0] != adpass.UnicodePwd("Hybrid-Pass-1") {
		t.Fatal("password not set")
	}
}

func TestAgentRetainsLegacyKeyAndSigningPin(t *testing.T) {
	f := newFixture(t)
	path := f.agent.cfg.KeyFile
	legacy := "x25519-private:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	writeSecret(t, path, legacy+"\n")
	k, err := loadOrCreateKey(path)
	if err != nil || !strings.HasPrefix(adpass.EncodePublicKey(k.PublicKey()), "x25519:") {
		t.Fatal("init did not retain legacy key", err)
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != legacy+"\n" {
		t.Fatal("legacy key overwritten")
	}
	again, err := newAgent(filepath.Join(f.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.agent = again
	dn := f.account("alice")
	f.run(t, f.seal(t, "alice", 10, "Legacy-Pass-1"))
	if r := f.result("alice", 10); r["outcome"] != "applied" {
		t.Fatal(r)
	}
	if f.dc.Get(dn).Attrs["unicodePwd"][0] != adpass.UnicodePwd("Legacy-Pass-1") {
		t.Fatal("legacy deployment broken")
	}
	// Re-key without losing replay state: the same path now holds X-Wing and init
	// reloads it; old ciphertext cannot be opened with the replacement key.
	old := f.seal(t, "alice", 11, "Old-Key-Pass-1")
	hybrid, err := adpass.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	writeSecret(t, path, adpass.EncodePrivateKey(hybrid)+"\n")
	again, err = newAgent(filepath.Join(f.dir, "config.json"))
	if err != nil || again.state["alice"] != 10 {
		t.Fatal("re-key lost state", err)
	}
	f.agent = again
	f.run(t, old)
	if r := f.result("alice", 11); r["reason"] != "decrypt_failed" {
		t.Fatal("old key ciphertext applied", r)
	}
	f.run(t, f.seal(t, "alice", 12, "New-Key-Pass-1"))
	if r := f.result("alice", 12); r["outcome"] != "applied" {
		t.Fatal("new key not applied", r)
	}
}
