package config

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func replicaConfig(t *testing.T) (*Config, ReplicaKeys) {
	t.Helper()
	roots := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(roots, []byte("roots one"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := func(b byte) []byte { return slices.Repeat([]byte{b}, KeyLength) }
	return &Config{
		Port: "5867", ListenHost: "127.0.0.1", IssuerURL: "https://id.example", RPID: "id.example", Origin: "https://id.example",
		DBPath: "/data/kyidentity.db", DatabaseURL: "postgres://db/kyidentity", DataDir: "/data",
		SecretKey: key(1), EncryptionKey: key(2), RSAKeyPath: "/keys/rsa", VAPIDKeyPath: "/keys/vapid",
		Replicated: true, TrustedProxyCIDRs: []string{"10.0.0.1/32"}, ForwardedHeader: "X-Forwarded-For",
		RateLimitExemptCIDRs: "192.0.2.0/24", BootstrapUser: "admin", BootstrapPass: "first-password",
		SecureCookies: true, SessionTTL: 24 * time.Hour, SessionIdleTTL: 8 * time.Hour,
		PushRelayURL: "https://relay.example", PushRelayKey: "k1", APNSRelayURL: "https://apns.example", APNSRelayKey: "k2",
		UbuntuPushURL: "https://push.example/notify", UbuntuPushAppID: "kyauth.busnes_kyauth", AppName: "KySignOn",
		BackupDepositInterval: 24 * time.Hour, BackupDir: "/backups", BackupKeep: 7, RecoveryKeyID: "key-1",
		AttestationExtraRoots: roots, AttestationStatusURL: "https://status.example",
		KyAuthCertSHA256: []string{strings.Repeat("a", 64)}, AppAttestAppIDs: []string{"TEAM.app"},
		Tenancy: "single",
	}, ReplicaKeys{
		RSAPublic: []byte("rsa public"), MLDSAPublic: []byte("mldsa public"), VAPIDPublic: []byte("vapid public"),
	}
}

// changed returns a copy of c with one field set to a different value of its type.
func changed(t *testing.T, c *Config, field string) *Config {
	t.Helper()
	out := *c
	v := reflect.ValueOf(&out).Elem().FieldByName(field)
	switch v.Kind() {
	case reflect.String:
		if field == "AttestationExtraRoots" {
			other := filepath.Join(t.TempDir(), "other.pem")
			if err := os.WriteFile(other, []byte("roots two"), 0o600); err != nil {
				t.Fatal(err)
			}
			v.SetString(other)
		} else {
			v.SetString(v.String() + "-other")
		}
	case reflect.Bool:
		v.SetBool(!v.Bool())
	case reflect.Int, reflect.Int64:
		v.SetInt(v.Int() + 1)
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := slices.Clone(v.Bytes())
			b[0] ^= 0xff
			v.SetBytes(b)
		} else {
			v.Set(reflect.Append(reflect.MakeSlice(v.Type(), 0, 1), reflect.ValueOf("other")))
		}
	default:
		t.Fatalf("field %s has an unhandled kind %s", field, v.Kind())
	}
	return &out
}

func fingerprint(t *testing.T, c *Config, k ReplicaKeys) map[string]string {
	t.Helper()
	fp, err := ReplicaFingerprint(c, k)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

// Every Config field is shared or per host, and each list names only real fields. A field
// added to Config without a decision fails here.
func TestEveryConfigFieldIsClassified(t *testing.T) {
	typ := reflect.TypeFor[Config]()
	var fields []string
	for i := range typ.NumField() {
		fields = append(fields, typ.Field(i).Name)
	}
	for _, name := range fields {
		_, shared := replicaShared[name]
		if host := slices.Contains(replicaPerHost, name); shared == host {
			t.Errorf("Config.%s must be in exactly one of replicaShared and replicaPerHost", name)
		}
	}
	for name := range replicaShared {
		if !slices.Contains(fields, name) {
			t.Errorf("replicaShared names %s, which is not a Config field", name)
		}
	}
	for _, name := range replicaPerHost {
		if !slices.Contains(fields, name) {
			t.Errorf("replicaPerHost names %s, which is not a Config field", name)
		}
	}
}

// Changing a shared field changes exactly its own entry (the encryption key alone being
// reported for itself); changing a per-host field changes nothing. No value appears in
// the fingerprint.
func TestReplicaFingerprintFollowsTheClassification(t *testing.T) {
	c, k := replicaConfig(t)
	base := fingerprint(t, c, k)
	for field, env := range replicaShared {
		diff := DiffFingerprint(base, fingerprint(t, changed(t, c, field), k))
		if !slices.Equal(diff, []string{env}) {
			t.Errorf("changing %s reported %v, want [%s]", field, diff, env)
		}
	}
	for _, field := range replicaPerHost {
		if diff := DiffFingerprint(base, fingerprint(t, changed(t, c, field), k)); len(diff) != 0 {
			t.Errorf("changing per-host %s reported %v", field, diff)
		}
	}
	for name, other := range map[string]ReplicaKeys{
		RSAPublicKeyField:   {RSAPublic: []byte("another rsa"), MLDSAPublic: k.MLDSAPublic, VAPIDPublic: k.VAPIDPublic},
		MLDSAPublicKeyField: {RSAPublic: k.RSAPublic, MLDSAPublic: []byte("another mldsa"), VAPIDPublic: k.VAPIDPublic},
		VAPIDPublicKeyField: {RSAPublic: k.RSAPublic, MLDSAPublic: k.MLDSAPublic, VAPIDPublic: []byte("another vapid")},
	} {
		if diff := DiffFingerprint(base, fingerprint(t, c, other)); !slices.Equal(diff, []string{name}) {
			t.Errorf("a different key file reported %v, want [%s]", diff, name)
		}
	}
	for _, v := range base {
		for _, secret := range []string{"https://id.example", "192.0.2.0/24", "k1", "https://relay.example"} {
			if strings.Contains(v, secret) {
				t.Fatalf("the fingerprint holds a value: %s", v)
			}
		}
	}
	// A field only one side knows is no difference: an upgrade records it.
	delete(base, VAPIDPublicKeyField)
	if diff := DiffFingerprint(base, fingerprint(t, c, k)); len(diff) != 0 {
		t.Errorf("a field the record lacks reported %v", diff)
	}
}
