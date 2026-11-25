package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
)

// ReplicaConfigSetting is the system_settings row holding the shared-configuration
// fingerprint of PostgreSQL replicas. No API returns it, no log prints it, and a restore
// deletes it: each environment records its own on first start.
const ReplicaConfigSetting = "replica_config_fingerprint"

// EncryptionKeyField names the encryption key's check value. Every other value is keyed by a
// subkey of that key, so a different key is reported alone.
const EncryptionKeyField = "KYIDENTITY_ENCRYPTION_KEY"

// ReplicaKeys are the public halves of the key files every replica must hold the same:
// the RSA signing key (SPKI DER) and the VAPID key (uncompressed point). Paths differ per
// host; the keys may not.
type ReplicaKeys struct {
	RSAPublic, VAPIDPublic []byte
}

// replicaShared names, by Config field, every setting all replicas must agree on and the
// variable a refusal reports. replicaPerHost is every field that may differ between hosts.
// TestEveryConfigFieldIsClassified holds the two lists to the struct in both directions.
var replicaShared = map[string]string{
	"IssuerURL":                  "KYIDENTITY_ISSUER_URL",
	"SecretKey":                  "KYIDENTITY_SECRET_KEY",
	"EncryptionKey":              EncryptionKeyField,
	"Replicated":                 "KYIDENTITY_REPLICATED",
	"SecureCookies":              "KYIDENTITY_SECURE_COOKIES",
	"SessionTTL":                 "KYIDENTITY_SESSION_TTL",
	"SessionIdleTTL":             "KYIDENTITY_SESSION_IDLE_TTL",
	"RateLimitExemptCIDRs":       "RATE_LIMIT_EXEMPT_CIDRS",
	"AllowPrivateCallbacks":      "KYIDENTITY_ALLOW_PRIVATE_CALLBACKS",
	"PushRelayURL":               "PUSH_RELAY_URL",
	"PushRelayKey":               "PUSH_RELAY_KEY",
	"APNSRelayURL":               "APNS_RELAY_URL",
	"APNSRelayKey":               "APNS_RELAY_KEY",
	"UbuntuPushURL":              "KYIDENTITY_UBUNTU_PUSH_URL",
	"UbuntuPushAppID":            "KYIDENTITY_UBUNTU_PUSH_APPID",
	"AppName":                    "KYIDENTITY_APP_NAME",
	"BackupDepositInterval":      "KYIDENTITY_BACKUP_DEPOSIT_INTERVAL",
	"BackupAllowPrivateRecovery": "KYIDENTITY_BACKUP_ALLOW_PRIVATE_RECOVERY",
	"AttestationStatusURL":       "KYIDENTITY_ATTESTATION_STATUS_URL",
	"AttestationExtraRoots":      "KYIDENTITY_ATTESTATION_EXTRA_ROOTS",
	"KyAuthCertSHA256":           "KYIDENTITY_KYAUTH_CERT_SHA256",
	"AppAttestAppIDs":            "KYIDENTITY_APPATTEST_APP_IDS",
	"AppAttestAllowDevelopment":  "KYIDENTITY_APPATTEST_ALLOW_DEVELOPMENT",
	"Tenancy":                    "KYIDENTITY_TENANCY",
}

// RSAKeyPath and VAPIDKeyPath are paths, so per host; the keys they name are compared as
// RSAPublicKeyField and VAPIDPublicKeyField. RecoveryKeyID stays per host so the
// documented rolling recovery-key replacement keeps working. RPID and Origin derive from
// the issuer.
var replicaPerHost = []string{
	"Port", "ListenHost", "RPID", "Origin", "DBPath", "DatabaseURL", "DataDir",
	"RSAKeyPath", "VAPIDKeyPath", "VAPIDKeyMounted", "TrustedProxyCIDRs", "ForwardedHeader",
	"BootstrapUser", "BootstrapPass", "BackupDir", "BackupKeep", "RecoveryKeyID", "PlatformListen", "PlatformEventsURL",
}

// The key files' public halves, reported under the variables that name the files.
const (
	RSAPublicKeyField   = "KYIDENTITY_RSA_KEY_PATH"
	VAPIDPublicKeyField = "KYIDENTITY_VAPID_KEY_PATH"
)

// sharedValues is every shared field's canonical value under the name a refusal shows. The
// encryption key is absent: ReplicaFingerprint gives it a check value of its own.
func sharedValues(c *Config, k ReplicaKeys) ([][2]string, error) {
	b := strconv.FormatBool
	roots := ""
	if c.AttestationExtraRoots != "" {
		pem, err := os.ReadFile(c.AttestationExtraRoots)
		if err != nil {
			return nil, fmt.Errorf("KYIDENTITY_ATTESTATION_EXTRA_ROOTS: %w", err)
		}
		sum := sha256.Sum256(pem)
		roots = hex.EncodeToString(sum[:])
	}
	rsaSum := sha256.Sum256(k.RSAPublic)
	f := replicaShared
	return [][2]string{
		{f["IssuerURL"], c.IssuerURL},
		{f["SecretKey"], hex.EncodeToString(c.SecretKey)},
		{RSAPublicKeyField, hex.EncodeToString(rsaSum[:])},
		{VAPIDPublicKeyField, hex.EncodeToString(k.VAPIDPublic)},
		{f["Replicated"], b(c.Replicated)},
		{f["SecureCookies"], b(c.SecureCookies)},
		{f["SessionTTL"], c.SessionTTL.String()},
		{f["SessionIdleTTL"], c.SessionIdleTTL.String()},
		{f["RateLimitExemptCIDRs"], c.RateLimitExemptCIDRs},
		{f["AllowPrivateCallbacks"], b(c.AllowPrivateCallbacks)},
		{f["PushRelayURL"], c.PushRelayURL},
		{f["PushRelayKey"], c.PushRelayKey},
		{f["APNSRelayURL"], c.APNSRelayURL},
		{f["APNSRelayKey"], c.APNSRelayKey},
		{f["UbuntuPushURL"], c.UbuntuPushURL},
		{f["UbuntuPushAppID"], c.UbuntuPushAppID},
		{f["AppName"], c.AppName},
		{f["BackupDepositInterval"], c.BackupDepositInterval.String()},
		{f["BackupAllowPrivateRecovery"], b(c.BackupAllowPrivateRecovery)},
		{f["AttestationStatusURL"], c.AttestationStatusURL},
		{f["AttestationExtraRoots"], roots},
		{f["KyAuthCertSHA256"], strings.Join(c.KyAuthCertSHA256, ",")},
		{f["AppAttestAppIDs"], strings.Join(c.AppAttestAppIDs, ",")},
		{f["AppAttestAllowDevelopment"], b(c.AppAttestAllowDevelopment)},
		{f["Tenancy"], c.Tenancy},
	}, nil
}

// ReplicaFingerprint maps each shared field to HMAC-SHA256 under a subkey of the encryption
// key over its name and value, so a database reader cannot test guesses for an issuer, a
// network list or a relay URL. The encryption key itself is a check value keyed by itself.
func ReplicaFingerprint(c *Config, k ReplicaKeys) (map[string]string, error) {
	values, err := sharedValues(c, k)
	if err != nil {
		return nil, err
	}
	check := hmac.New(sha256.New, c.EncryptionKey)
	check.Write([]byte("kyidentity:replica-config:encryption-key-check"))
	out := map[string]string{EncryptionKeyField: hex.EncodeToString(check.Sum(nil))}
	sub := crypto.DeriveKey(c.EncryptionKey, "kyidentity:replica-config")
	for _, f := range values {
		m := hmac.New(sha256.New, sub)
		m.Write([]byte(f[0] + "\x00" + f[1]))
		out[f[0]] = hex.EncodeToString(m.Sum(nil))
	}
	return out, nil
}

// DiffFingerprint names the fields whose values differ, sorted, never the values. A
// different encryption key is reported alone, since every other value is keyed by it. A
// name only one side has is no difference: an upgrade that adds a field records it.
func DiffFingerprint(stored, current map[string]string) []string {
	if !hmac.Equal([]byte(stored[EncryptionKeyField]), []byte(current[EncryptionKeyField])) {
		return []string{EncryptionKeyField}
	}
	var diff []string
	for name, v := range current {
		if old, ok := stored[name]; ok && !hmac.Equal([]byte(old), []byte(v)) {
			diff = append(diff, name)
		}
	}
	slices.Sort(diff)
	return diff
}
