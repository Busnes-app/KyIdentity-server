package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// replicaEnv is one replica's environment: every shared setting at a known value, keys from
// files outside the data directory, a PostgreSQL database URL. It returns the store a server
// started with it would open.
func replicaEnv(t *testing.T) (dbURL string, keyDir string) {
	t.Helper()
	commandEnv(t)
	if os.Getenv("KYIDENTITY_TEST_DATABASE_URL") == "" {
		t.Skip("needs KYIDENTITY_TEST_DATABASE_URL")
	}
	dbURL, err := store.PostgresURLForTest(filepath.Join(t.TempDir(), "replicas"))
	if err != nil {
		t.Fatal(err)
	}
	keyDir = t.TempDir()
	hexKey := func() string {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	}
	newKeys(t, keyDir)
	for k, v := range map[string]string{
		"KYIDENTITY_DATABASE_URL": dbURL, "KYIDENTITY_DATABASE_URL_FILE": "", "KYIDENTITY_REPLICATED": "true",
		"KYIDENTITY_SECRET_KEY": hexKey(), "KYIDENTITY_ENCRYPTION_KEY": hexKey(),
		"KYIDENTITY_SECRET_KEY_FILE": "", "KYIDENTITY_ENCRYPTION_KEY_FILE": "",
		"KYIDENTITY_RSA_KEY_PATH": filepath.Join(keyDir, "rsa.key"), "KYIDENTITY_VAPID_KEY_PATH": filepath.Join(keyDir, "vapid.key"),
		"KYIDENTITY_ISSUER_URL": "http://localhost:5867", "KYIDENTITY_SECURE_COOKIES": "", "KYIDENTITY_SESSION_TTL": "", "KYIDENTITY_SESSION_IDLE_TTL": "",
		"RATE_LIMIT_EXEMPT_CIDRS": "", "KYIDENTITY_ALLOW_PRIVATE_CALLBACKS": "",
		"PUSH_RELAY_URL": "", "PUSH_RELAY_KEY": "", "APNS_RELAY_URL": "", "APNS_RELAY_KEY": "",
		"KYIDENTITY_UBUNTU_PUSH_URL": "", "KYIDENTITY_UBUNTU_PUSH_APPID": "",
		"KYIDENTITY_BACKUP_DEPOSIT_INTERVAL": "", "KYIDENTITY_BACKUP_ALLOW_PRIVATE_RECOVERY": "",
		"KYIDENTITY_ATTESTATION_STATUS_URL": "", "KYIDENTITY_ATTESTATION_EXTRA_ROOTS": "", "KYIDENTITY_KYAUTH_CERT_SHA256": "",
		"KYIDENTITY_APPATTEST_APP_IDS": "", "KYIDENTITY_APPATTEST_ALLOW_DEVELOPMENT": "",
		"KYIDENTITY_PORT": "", "KYIDENTITY_LISTEN_HOST": "", "TRUSTED_PROXY_CIDRS": "", "KYIDENTITY_FORWARDED_HEADER": "",
		"KYIDENTITY_RECOVERY_KEY_ID": "",
	} {
		t.Setenv(k, v)
	}
	return dbURL, keyDir
}

// newKeys writes an RSA signing key and a VAPID key into dir.
func newKeys(t *testing.T, dir string) {
	t.Helper()
	if _, err := crypto.LoadOrCreateRSAKey(filepath.Join(dir, "rsa.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := mfa.NewUnifiedPushSender(filepath.Join(dir, "vapid.key"), "http://localhost:5867", true); err != nil {
		t.Fatal(err)
	}
}

// startCheck is the configuration check of a server start under the current environment.
func startCheck(t *testing.T) (*store.Store, error) {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	s, err := openStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	keys, err := loadReplicaKeys(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s, checkReplicaConfig(cfg, s, keys)
}

func recorded(t *testing.T, s *store.Store) map[string]string {
	t.Helper()
	raw, err := s.GetSetting(config.ReplicaConfigSetting)
	if err != nil {
		t.Fatal(err)
	}
	var fp map[string]string
	if err := json.Unmarshal([]byte(raw), &fp); err != nil {
		t.Fatal(err)
	}
	return fp
}

// A second replica that differs in any shared setting refuses to start, naming the setting
// and never its value; one that differs only in per-host settings starts.
func TestReplicaConfigRefusesADifferentSharedSetting(t *testing.T) {
	_, keyDir := replicaEnv(t)
	first, err := startCheck(t)
	if err != nil {
		t.Fatal("the first start refused:", err)
	}
	stored := recorded(t, first)
	otherKeys := t.TempDir()
	newKeys(t, otherKeys)
	roots := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(roots, []byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	shared := map[string]string{
		"KYIDENTITY_ISSUER_URL":                    "http://localhost:5999",
		"KYIDENTITY_SECRET_KEY":                    hex.EncodeToString(other),
		"KYIDENTITY_RSA_KEY_PATH":                  filepath.Join(otherKeys, "rsa.key"),
		"KYIDENTITY_VAPID_KEY_PATH":                filepath.Join(otherKeys, "vapid.key"),
		"KYIDENTITY_REPLICATED":                    "false",
		"KYIDENTITY_SECURE_COOKIES":                "true",
		"KYIDENTITY_SESSION_TTL":                   "12h",
		"KYIDENTITY_SESSION_IDLE_TTL":              "4h",
		"RATE_LIMIT_EXEMPT_CIDRS":                  "192.0.2.0/24",
		"KYIDENTITY_ALLOW_PRIVATE_CALLBACKS":       "true",
		"PUSH_RELAY_URL":                           "https://relay.invalid",
		"PUSH_RELAY_KEY":                           "relay-key-value",
		"APNS_RELAY_URL":                           "https://apns.invalid",
		"APNS_RELAY_KEY":                           "apns-key-value",
		"KYIDENTITY_UBUNTU_PUSH_URL":               "https://push.invalid/notify",
		"KYIDENTITY_UBUNTU_PUSH_APPID":             "other.app_other",
		"KYIDENTITY_APP_NAME":                      "OtherService",
		"KYIDENTITY_BACKUP_DEPOSIT_INTERVAL":       "12h",
		"KYIDENTITY_BACKUP_ALLOW_PRIVATE_RECOVERY": "true",
		"KYIDENTITY_ATTESTATION_STATUS_URL":        "https://status.invalid",
		"KYIDENTITY_ATTESTATION_EXTRA_ROOTS":       roots,
		"KYIDENTITY_KYAUTH_CERT_SHA256":            strings.Repeat("c", 64),
		"KYIDENTITY_APPATTEST_APP_IDS":             "ABCDE12345.org.example.other",
		"KYIDENTITY_APPATTEST_ALLOW_DEVELOPMENT":   "true",
	}
	// The table covers every field the record holds, the encryption key aside, and
	// KYIDENTITY_TENANCY: Load accepts only single until multi-tenant mode lands, so
	// TestReplicaFingerprintFollowsTheClassification proves that one.
	names := slices.Sorted(maps.Keys(stored))
	want := append(slices.Sorted(maps.Keys(shared)), config.EncryptionKeyField, "KYIDENTITY_TENANCY")
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Fatalf("the record holds %v, the table covers %v", names, want)
	}
	for name, value := range shared {
		t.Run(name, func(t *testing.T) {
			if name == "KYIDENTITY_REPLICATED" {
				// Without the flag a Postgres server still checks; with it the keys must be files.
				t.Setenv("KYIDENTITY_REPLICATED", value)
			}
			t.Setenv(name, value)
			_, err := startCheck(t)
			if !errors.Is(err, errReplicaConfig) || !strings.Contains(err.Error(), name) {
				t.Fatalf("a different %s: %v", name, err)
			}
			if strings.Contains(err.Error(), value) {
				t.Fatalf("the refusal shows a value: %v", err)
			}
			for _, v := range stored {
				if strings.Contains(err.Error(), v) {
					t.Fatal("the refusal shows a fingerprint")
				}
			}
			if after := recorded(t, first); !maps.Equal(after, stored) {
				t.Fatal("a refused start changed the record")
			}
		})
	}
	t.Run(config.EncryptionKeyField, func(t *testing.T) {
		t.Setenv("KYIDENTITY_ENCRYPTION_KEY", hex.EncodeToString(other))
		_, err := startCheck(t)
		if !errors.Is(err, errReplicaConfig) || !strings.Contains(err.Error(), "KYIDENTITY_ENCRYPTION_KEY differs") || strings.Contains(err.Error(), "KYIDENTITY_ISSUER_URL") {
			t.Fatalf("a different encryption key is reported alone: %v", err)
		}
	})
	t.Run("per-host settings may differ", func(t *testing.T) {
		moved := t.TempDir()
		for _, f := range []string{"rsa.key", "vapid.key"} {
			raw, err := os.ReadFile(filepath.Join(keyDir, f))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(moved, f), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for k, v := range map[string]string{
			"KYIDENTITY_PORT": "6001", "KYIDENTITY_LISTEN_HOST": "127.0.0.1", "KYIDENTITY_DATA_DIR": t.TempDir(),
			"KYIDENTITY_RSA_KEY_PATH": filepath.Join(moved, "rsa.key"), "KYIDENTITY_VAPID_KEY_PATH": filepath.Join(moved, "vapid.key"),
			"TRUSTED_PROXY_CIDRS": "10.1.2.3/32", "KYIDENTITY_FORWARDED_HEADER": "X-Real-IP",
			"KYIDENTITY_BACKUP_DIR": t.TempDir(), "KYIDENTITY_BACKUP_KEEP": "3",
			"BOOTSTRAP_ADMIN_USER": "someone", "BOOTSTRAP_ADMIN_PASS": "a-different-first-password",
			"KYIDENTITY_RECOVERY_KEY_ID": strings.Repeat("ab", 32),
			"KYIDENTITY_DATABASE_URL":    os.Getenv("KYIDENTITY_DATABASE_URL") + "&application_name=other",
		} {
			t.Setenv(k, v)
		}
		if _, err := startCheck(t); err != nil {
			t.Fatal("per-host differences refused the start:", err)
		}
	})
}

// Two first starts at once with different configurations: one records, the other refuses.
func TestConcurrentFirstStartsRecordOneConfiguration(t *testing.T) {
	replicaEnv(t)
	for round := range 4 {
		dbURL, err := store.PostgresURLForTest(filepath.Join(t.TempDir(), "race"))
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("KYIDENTITY_DATABASE_URL", dbURL)
		a, err := config.Load()
		if err != nil {
			t.Fatal(err)
		}
		b := *a
		b.IssuerURL = "http://localhost:5999"
		keys, err := loadReplicaKeys(a)
		if err != nil {
			t.Fatal(err)
		}
		sa, err := openStore(a)
		if err != nil {
			t.Fatal(err)
		}
		sb, err := openStore(&b)
		if err != nil {
			t.Fatal(err)
		}
		errs := make([]error, 2)
		done := make(chan struct{})
		start := make(chan struct{})
		for i, c := range []struct {
			cfg *config.Config
			s   *store.Store
		}{{a, sa}, {&b, sb}} {
			go func() { <-start; errs[i] = checkReplicaConfig(c.cfg, c.s, keys); done <- struct{}{} }()
		}
		close(start)
		<-done
		<-done
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else if !errors.Is(err, errReplicaConfig) || !strings.Contains(err.Error(), "KYIDENTITY_ISSUER_URL") {
				t.Fatalf("round %d: the loser failed for another reason: %v", round, err)
			}
		}
		if ok != 1 {
			t.Fatalf("round %d: %d of two different first starts were accepted: %v", round, ok, errs)
		}
		sa.Close()
		sb.Close()
	}
}

// SQLite is one server: nothing is recorded or compared, and accept-replica-config refuses.
func TestSQLiteRecordsNoReplicaConfiguration(t *testing.T) {
	t.Setenv("KYIDENTITY_TEST_DATABASE_URL", "")
	cfg, _ := commandInstance(t, false)
	s := handles(t, cfg.DBPath, 1)[0]
	if s.Postgres() {
		t.Fatal("expected a SQLite store")
	}
	keys := config.ReplicaKeys{RSAPublic: []byte("r"), VAPIDPublic: []byte("v")}
	if err := checkReplicaConfig(cfg, s, keys); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSetting(config.ReplicaConfigSetting); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("SQLite recorded a replica configuration: %v", err)
	}
	if err := acceptReplicaConfig(cfg, s, keys, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "PostgreSQL replicas only") {
		t.Fatalf("accept on SQLite: %v", err)
	}
}

// accept-replica-config rewrites the record after a deliberate change, with an audit row
// naming the changed fields only; it never prints a fingerprint and never accepts a
// different encryption key.
func TestAcceptReplicaConfig(t *testing.T) {
	replicaEnv(t)
	s, err := startCheck(t)
	if err != nil {
		t.Fatal(err)
	}
	before := recorded(t, s)

	other := make([]byte, 32)
	_, _ = rand.Read(other)
	t.Run("refuses a different encryption key", func(t *testing.T) {
		t.Setenv("KYIDENTITY_ENCRYPTION_KEY", hex.EncodeToString(other))
		var out bytes.Buffer
		if err := runAcceptReplicaConfig(nil, &out, io.Discard); err == nil || !strings.Contains(err.Error(), "KYIDENTITY_ENCRYPTION_KEY differs") {
			t.Fatalf("accept with another encryption key: %v", err)
		}
		if after := recorded(t, s); !maps.Equal(after, before) {
			t.Fatal("a refused accept changed the record")
		}
	})

	t.Setenv("KYIDENTITY_ISSUER_URL", "http://localhost:5999")
	if _, err := startCheck(t); !errors.Is(err, errReplicaConfig) {
		t.Fatalf("the changed issuer started before it was accepted: %v", err)
	}
	var out bytes.Buffer
	logged := captureLog(t, func() {
		if err := runAcceptReplicaConfig(nil, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out.String(), "Changed: KYIDENTITY_ISSUER_URL") {
		t.Fatalf("output: %s", out.String())
	}
	after := recorded(t, s)
	for _, fp := range []map[string]string{before, after} {
		for _, v := range fp {
			if strings.Contains(out.String()+logged, v) {
				t.Fatal("accept-replica-config printed a fingerprint")
			}
		}
	}
	if _, err := startCheck(t); err != nil {
		t.Fatal("the accepted configuration refused to start:", err)
	}
	t.Setenv("KYIDENTITY_ISSUER_URL", "http://localhost:5867")
	if _, err := startCheck(t); !errors.Is(err, errReplicaConfig) {
		t.Fatalf("the old configuration still starts: %v", err)
	}
	events, _, err := s.DefaultOrg().SearchAuditEvents(store.AuditFilter{Action: "admin.replica_config_accepted", Limit: 5})
	if err != nil || len(events) != 1 {
		t.Fatalf("audit rows: %d %v", len(events), err)
	}
	var details struct {
		Fields []string `json:"fields"`
	}
	if err := json.Unmarshal([]byte(events[0].DetailsJSON), &details); err != nil || !slices.Equal(details.Fields, []string{"KYIDENTITY_ISSUER_URL"}) || events[0].ActorUsername != "kyidentity-cli" {
		t.Fatalf("audit row: %+v %v", events[0], err)
	}
	for _, v := range after {
		if strings.Contains(events[0].DetailsJSON, v) {
			t.Fatal("the audit row holds a fingerprint")
		}
	}
}

// A field the record lacks (one a later release adds) is recorded by the first start that
// knows it. Two such starts at once with different values for it: one records, and the other
// re-reads after losing the swap and refuses, naming the field.
func TestARaceToRecordANewFieldHasOneWinner(t *testing.T) {
	replicaEnv(t)
	first, err := startCheck(t)
	if err != nil {
		t.Fatal(err)
	}
	base := recorded(t, first)
	delete(base, "KYIDENTITY_APP_NAME") // as if recorded by a release before the field existed
	older, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	a, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := loadReplicaKeys(a)
	if err != nil {
		t.Fatal(err)
	}
	b := *a
	b.AppName = "AnotherService"
	stores := []*store.Store{}
	for range 2 {
		s, err := openStore(a)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		stores = append(stores, s)
	}
	for round := range 20 {
		if err := first.SetSetting(config.ReplicaConfigSetting, string(older)); err != nil {
			t.Fatal(err)
		}
		errs := make([]error, 2)
		start := make(chan struct{})
		done := make(chan struct{}, 2)
		for i, cfg := range []*config.Config{a, &b} {
			go func() { <-start; errs[i] = checkReplicaConfig(cfg, stores[i], keys); done <- struct{}{} }()
		}
		close(start)
		<-done
		<-done
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else if !errors.Is(err, errReplicaConfig) || !strings.Contains(err.Error(), "KYIDENTITY_APP_NAME") {
				t.Fatalf("round %d: the loser failed for another reason: %v", round, err)
			}
		}
		if ok != 1 {
			t.Fatalf("round %d: %d of two starts with different values for a new field were accepted", round, ok)
		}
	}
}

// accept-replica-config reads its arguments before it loads anything: -h prints the usage and
// a stray flag or argument is refused, all without touching the configuration or a database.
// The database URL here names nothing that would answer, so any database work would fail.
func TestAcceptReplicaConfigParsesItsArgumentsFirst(t *testing.T) {
	commandEnv(t)
	t.Setenv("KYIDENTITY_DATABASE_URL", "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	t.Setenv("KYIDENTITY_ISSUER_URL", "not a url") // config.Load would fail on this
	for _, c := range []struct {
		args    []string
		wantErr string
	}{
		{[]string{"-h"}, ""},
		{[]string{"--help"}, ""},
		{[]string{"--dry-run"}, "flag provided but not defined"},
		{[]string{"now"}, "takes no arguments"},
	} {
		var out, errOut bytes.Buffer
		begun := time.Now()
		err := runAcceptReplicaConfig(c.args, &out, &errOut)
		if c.wantErr == "" && err != nil || c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
			t.Fatalf("%v: err %v, want %q", c.args, err, c.wantErr)
		}
		if !strings.Contains(errOut.String(), "Usage: kyidentity accept-replica-config") || out.Len() != 0 {
			t.Fatalf("%v: usage %q, output %q", c.args, errOut.String(), out.String())
		}
		if took := time.Since(begun); took > 500*time.Millisecond {
			t.Fatalf("%v took %v: it reached for the database", c.args, took)
		}
	}
}

// With no earlier record, accept-replica-config says it recorded one rather than listing every
// field as changed.
func TestAcceptReplicaConfigWithNoRecordSaysRecorded(t *testing.T) {
	replicaEnv(t)
	s, err := startCheck(t)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSetting(config.ReplicaConfigSetting); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runAcceptReplicaConfig(nil, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "recorded (there was no readable earlier record)") || strings.Contains(out.String(), "Changed:") {
		t.Fatalf("output: %s", out.String())
	}
	if _, err := startCheck(t); err != nil {
		t.Fatal("the recorded configuration refused to start:", err)
	}
}

// A database records its tenancy mode when it is created, and a start configured for the
// other mode refuses before serving.
func TestStartRefusesTheOtherTenancyMode(t *testing.T) {
	cfg, _ := commandInstance(t, false)
	s := handles(t, cfg.DBPath, 1)[0]
	if cfg.Tenancy != "single" {
		t.Fatalf("default tenancy %q", cfg.Tenancy)
	}
	if err := checkTenancy(cfg, s); err != nil {
		t.Fatal("a single-tenant start on a single-tenant database:", err)
	}
	if err := s.SetSetting(store.TenancySetting, "multi"); err != nil {
		t.Fatal(err)
	}
	if err := checkTenancy(cfg, s); err == nil || !strings.Contains(err.Error(), "KYIDENTITY_TENANCY is single but this database was created multi-tenant") {
		t.Fatalf("a single-tenant start on a multi-tenant database: %v", err)
	}
}

func TestFreshDatabaseRecordsItsTenancyMode(t *testing.T) {
	multi := freshPostgresTenancy(t)
	open := func(cfg *config.Config) *store.Store {
		t.Helper()
		s, err := openStore(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	for range 2 {
		if err := checkTenancy(multi, open(multi)); err != nil {
			t.Fatalf("multi-tenant start refused: %v", err)
		}
	}
	single := *multi
	single.Tenancy = "single"
	if err := checkTenancy(&single, open(&single)); err == nil {
		t.Fatal("a single-tenant start on a multi-tenant database")
	}
	other := freshPostgresTenancy(t)
	single.DatabaseURL = other.DatabaseURL
	if err := checkTenancy(&single, open(&single)); err != nil {
		t.Fatalf("single-tenant start refused: %v", err)
	}
	if err := checkTenancy(other, open(other)); err == nil || !strings.Contains(err.Error(), "created single-tenant") {
		t.Fatalf("a multi-tenant start on a single-tenant database: %v", err)
	}
}

func freshPostgresTenancy(t *testing.T) *config.Config {
	t.Helper()
	if !store.OnPostgresTest() {
		t.Skip("needs PostgreSQL")
	}
	path := filepath.Join(t.TempDir(), "tenancy")
	rawURL, err := store.PostgresURLForTest(path)
	if err != nil {
		t.Fatal(err)
	}
	return &config.Config{Tenancy: "multi", DatabaseURL: rawURL, DBPath: path}
}

func TestInterruptedMultiTenantInitializationCanRetry(t *testing.T) {
	cfg := freshPostgresTenancy(t)
	raw, err := store.OpenRawForTest(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// Interrupt the first open after the baseline users table would have committed.
	if _, err := raw.Exec(`CREATE TABLE active_principals (blocker int)`); err != nil {
		t.Fatal(err)
	}
	if s, err := openStore(cfg); err == nil {
		s.Close()
		t.Fatal("first open succeeded despite the conflicting relation")
	} else if !strings.Contains(err.Error(), "active_principals") {
		t.Fatalf("first open failed at the wrong point: %v", err)
	}
	if _, err := raw.Exec(`DROP TABLE active_principals`); err != nil {
		t.Fatal(err)
	}
	s, err := openStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := checkTenancy(cfg, s); err != nil {
		t.Fatalf("retry could not start in multi mode: %v", err)
	}
}

func TestConcurrentFirstOpensRecordMultiTenantMode(t *testing.T) {
	cfg := freshPostgresTenancy(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			s, err := openStore(cfg)
			if err == nil {
				err = checkTenancy(cfg, s)
				s.Close()
			}
			results <- err
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
}
