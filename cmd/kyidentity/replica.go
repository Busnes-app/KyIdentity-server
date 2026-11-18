package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// errReplicaConfig is a PostgreSQL replica whose shared settings differ from the recorded ones.
var errReplicaConfig = errors.New("this replica's configuration differs from the one the other replicas recorded")

// keyDiffers is never accepted: every sealed secret opens only under the recorded key, so a
// different one is the wrong file, not a rotation.
const keyDiffers = "KYIDENTITY_ENCRYPTION_KEY differs from the key the other replicas use. Supply that key; accept-replica-config never changes it, because every sealed secret opens only under it"

// replicaKeys reads the public halves of the signing and VAPID keys this process loaded.
func replicaKeys(km *crypto.JWTKeyManager, vapid *mfa.UnifiedPushSender) (config.ReplicaKeys, error) {
	spki, err := x509.MarshalPKIXPublicKey(km.PublicKey)
	if err != nil {
		return config.ReplicaKeys{}, err
	}
	return config.ReplicaKeys{RSAPublic: spki, VAPIDPublic: vapid.VAPIDPublicKey()}, nil
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
	stored, err := s.RecordSetting(config.ReplicaConfigSetting, string(raw))
	if err != nil {
		return fmt.Errorf("reading the recorded replica configuration: %w", err)
	}
	var recorded map[string]string
	if err := json.Unmarshal([]byte(stored), &recorded); err != nil {
		return fmt.Errorf("%w: the record is unreadable; after checking every replica, run accept-replica-config", errReplicaConfig)
	}
	switch diff := config.DiffFingerprint(recorded, current); {
	case slices.Equal(diff, []string{config.EncryptionKeyField}):
		return fmt.Errorf("%w: %s", errReplicaConfig, keyDiffers)
	case len(diff) > 0:
		return fmt.Errorf("%w: %s. Use the same values on every replica; after a deliberate change, stop every replica, start them with the new values and run accept-replica-config once", errReplicaConfig, strings.Join(diff, ", "))
	}
	// A field this release added is recorded by the first start that knows it. A lost swap is
	// another replica recording the same thing.
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
	_, err = s.SwapSetting(config.ReplicaConfigSetting, stored, string(merged))
	return err
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
	err = s.EditSettings(event, func(st store.Settings) error {
		changed = slices.Sorted(maps.Keys(current))
		stored, err := st.GetSetting(config.ReplicaConfigSetting)
		switch {
		case err == nil:
			var recorded map[string]string
			if json.Unmarshal([]byte(stored), &recorded) == nil {
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
	if len(changed) == 0 {
		fmt.Fprintln(out, "Replica configuration unchanged; record rewritten.")
	} else {
		fmt.Fprintf(out, "Replica configuration accepted. Changed: %s\n", strings.Join(changed, ", "))
	}
	return nil
}

// runAcceptReplicaConfig loads the keys as a server start would and accepts its configuration.
func runAcceptReplicaConfig(out io.Writer) error {
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
	km, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath)
	if err != nil {
		return config.ReplicaKeys{}, fmt.Errorf("RSA signing key: %w", err)
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
