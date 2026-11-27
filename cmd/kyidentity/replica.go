package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// errReplicaConfig is a PostgreSQL server whose shared settings differ from the recorded ones.
// A single server records too, so the wording names no other replicas.
var errReplicaConfig = errors.New("this server's configuration differs from the one recorded in the database by an earlier start")

// keyDiffers is never accepted: every sealed secret opens only under the recorded key, so a
// different one is the wrong file, not a rotation.
const keyDiffers = "KYIDENTITY_ENCRYPTION_KEY differs from the key recorded by an earlier start. Supply that key; accept-replica-config never changes it, because every sealed secret opens only under it"

// acceptSteps is the order that works: a start with the new values refuses until the record
// is rewritten.
const acceptSteps = "Use the same values on every server. After a deliberate change: stop every server, run `kyidentity accept-replica-config` once with the new values, then start them"

// loadSigningKeys loads the RSA and ML-DSA-65 OIDC signing keys. Replicated deployments
// never auto-generate a missing ML-DSA-65 key so replicas cannot diverge on separate keys;
// single-node deployments create both keys on first start.
func loadSigningKeys(cfg *config.Config) (*crypto.JWTKeyManager, error) {
	mldsaPath := cfg.MLDSAKeyPath
	if cfg.Replicated && mldsaPath != "" {
		if _, err := os.Stat(mldsaPath); errors.Is(err, os.ErrNotExist) {
			mldsaPath = ""
		} else if err != nil {
			return nil, fmt.Errorf("ML-DSA-65 signing key %s: %w", mldsaPath, err)
		}
	}
	return crypto.LoadOrCreateSigningKeys(cfg.RSAKeyPath, mldsaPath)
}

// replicaKeys reads the public halves of the signing and VAPID keys this process loaded.
func replicaKeys(km *crypto.JWTKeyManager, vapid *mfa.UnifiedPushSender) (config.ReplicaKeys, error) {
	spki, err := x509.MarshalPKIXPublicKey(km.PublicKey)
	if err != nil {
		return config.ReplicaKeys{}, err
	}
	keys := config.ReplicaKeys{RSAPublic: spki, VAPIDPublic: vapid.VAPIDPublicKey()}
	if km.MLDSAPublicKey != nil {
		keys.MLDSAPublic = km.MLDSAPublicKey.Bytes()
	}
	return keys, nil
}

// checkTenancy refuses a start whose KYIDENTITY_TENANCY differs from the mode the database
// recorded when it was created: the mode decides who an account belongs to.
func checkTenancy(cfg *config.Config, s *store.Store) error {
	mode, err := s.GetSetting(store.TenancySetting)
	if err != nil {
		return fmt.Errorf("reading the recorded tenancy mode: %w", err)
	}
	if mode != cfg.Tenancy {
		return fmt.Errorf("KYIDENTITY_TENANCY is %s but this database was created %s-tenant; the mode cannot change on an existing install", cfg.Tenancy, mode)
	}
	if mode == "multi" {
		// Staff sign in with a passkey (tenancy design, "Roles"), pinned on every start.
		if _, err := s.PinStaffPasskey(); err != nil {
			return fmt.Errorf("pinning the staff passkey policy: %w", err)
		}
	}
	return nil
}

// checkReplicaConfig records the shared-configuration fingerprint on the first start against
// a PostgreSQL database and refuses a later start that differs, naming fields only. SQLite
// is one server and records nothing.
func checkReplicaConfig(cfg *config.Config, s *store.Store, keys config.ReplicaKeys) error {
	if !s.Postgres() {
		return nil
	}
	current, err := config.ReplicaFingerprint(cfg, keys)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(current)
	if err != nil {
		return err
	}
	// A field this release added is recorded by the first start that knows it, by
	// compare-and-swap. A lost swap means another start changed the record first, perhaps
	// recording a different value for that field, so read and compare again.
	for range 5 {
		stored, err := s.RecordSetting(config.ReplicaConfigSetting, string(raw))
		if err != nil {
			return fmt.Errorf("reading the recorded replica configuration: %w", err)
		}
		var recorded map[string]string
		if err := json.Unmarshal([]byte(stored), &recorded); err != nil {
			return fmt.Errorf("%w: the record is unreadable; after checking every server's configuration, run accept-replica-config", errReplicaConfig)
		}
		switch diff := config.DiffFingerprint(recorded, current); {
		case slices.Equal(diff, []string{config.EncryptionKeyField}):
			return fmt.Errorf("%w: %s", errReplicaConfig, keyDiffers)
		case len(diff) > 0:
			return fmt.Errorf("%w: %s. %s", errReplicaConfig, strings.Join(diff, ", "), acceptSteps)
		}
		added := false
		for name, v := range current {
			if _, ok := recorded[name]; !ok {
				recorded[name], added = v, true
			}
		}
		if !added {
			return nil
		}
		merged, err := json.Marshal(recorded)
		if err != nil {
			return err
		}
		if swapped, err := s.SwapSetting(config.ReplicaConfigSetting, stored, string(merged)); err != nil || swapped {
			return err
		}
	}
	return errors.New("the recorded replica configuration kept changing while this server started; start it again")
}

// acceptReplicaConfig rewrites the record from this process's configuration after a
// deliberate change on every replica, with an audit row naming the changed fields only.
func acceptReplicaConfig(cfg *config.Config, s *store.Store, keys config.ReplicaKeys, out io.Writer) error {
	if !s.Postgres() {
		return errors.New("accept-replica-config applies to PostgreSQL replicas only; SQLite records no replica configuration")
	}
	current, err := config.ReplicaFingerprint(cfg, keys)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(current)
	if err != nil {
		return err
	}
	event := &store.AuditEvent{ID: uuid.NewString(), ActorUsername: "kyidentity-cli", Action: "admin.replica_config_accepted",
		TargetID: config.ReplicaConfigSetting, TargetType: "system_setting", IPAddress: "container-local", UserAgent: "kyidentity-cli",
		Outcome: "success", CreatedAt: time.Now().UTC()}
	var changed []string
	first := false // no earlier record, or one that cannot be read
	err = s.EditSettings(event, func(st store.Settings) error {
		changed, first = slices.Sorted(maps.Keys(current)), true
		stored, err := st.GetSetting(config.ReplicaConfigSetting)
		switch {
		case err == nil:
			var recorded map[string]string
			if json.Unmarshal([]byte(stored), &recorded) == nil {
				first = false
				if changed = config.DiffFingerprint(recorded, current); slices.Equal(changed, []string{config.EncryptionKeyField}) {
					return errors.New("refusing: " + keyDiffers)
				}
			}
		case !errors.Is(err, store.ErrNotFound):
			return err
		}
		details, err := json.Marshal(map[string]any{"fields": append([]string{}, changed...)})
		if err != nil {
			return err
		}
		event.DetailsJSON = string(details)
		return st.SetSetting(config.ReplicaConfigSetting, string(raw))
	})
	if err != nil {
		return err
	}
	switch {
	case first:
		fmt.Fprintln(out, "Replica configuration recorded (there was no readable earlier record).")
	case len(changed) == 0:
		fmt.Fprintln(out, "Replica configuration unchanged; record rewritten.")
	default:
		fmt.Fprintf(out, "Replica configuration accepted. Changed: %s\n", strings.Join(changed, ", "))
	}
	return nil
}

const acceptUsage = "Usage: kyidentity accept-replica-config\n\n" +
	"Records this process's configuration as the one every PostgreSQL server must share, after a\n" +
	"deliberate change: stop every server, change the setting everywhere, run this once with the\n" +
	"servers' full environment (keys, Secrets and variables), then start them. It writes an\n" +
	"admin.replica_config_accepted audit row naming the changed settings, prints no values, and\n" +
	"never accepts a different KYIDENTITY_ENCRYPTION_KEY. It takes no arguments.\n"

// runAcceptReplicaConfig loads the keys as a server start would and accepts its configuration.
// Its arguments are parsed before anything is loaded, so -h or a stray argument changes nothing.
func runAcceptReplicaConfig(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("accept-replica-config", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() { fmt.Fprint(errOut, acceptUsage) }
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return fmt.Errorf("accept-replica-config takes no arguments, got %q", fs.Args())
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	s, err := openStore(cfg)
	if err != nil {
		return fmt.Errorf("failed to open the database: %w", err)
	}
	defer s.Close()
	keys, err := loadReplicaKeys(cfg)
	if err != nil {
		return err
	}
	return acceptReplicaConfig(cfg, s, keys, out)
}

// loadReplicaKeys loads the signing and VAPID keys the way a server start does.
func loadReplicaKeys(cfg *config.Config) (config.ReplicaKeys, error) {
	km, err := loadSigningKeys(cfg)
	if err != nil {
		return config.ReplicaKeys{}, fmt.Errorf("signing key: %w", err)
	}
	origin, err := mfa.IssuerOrigin(cfg.IssuerURL)
	if err != nil {
		return config.ReplicaKeys{}, err
	}
	vapid, err := mfa.NewUnifiedPushSender(cfg.VAPIDKeyPath, origin, cfg.VAPIDKeyMounted)
	if err != nil {
		return config.ReplicaKeys{}, fmt.Errorf("VAPID key: %w", err)
	}
	return replicaKeys(km, vapid)
}
