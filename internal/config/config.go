package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/webauthn"
)

// KeyLength is the required size, in bytes, of the secret and encryption keys.
const KeyLength = 32

// Browser session limits. Apps keep their own sessions and return here only to sign in,
// so the idle limit must outlast the gap between app sign-ins (issue #77).
const (
	DefaultSessionTTL     = 24 * time.Hour
	DefaultSessionIdleTTL = 8 * time.Hour
	// Bounds an administrator or environment cannot exceed.
	MinSessionTTL     = time.Hour
	MaxSessionTTL     = 7 * 24 * time.Hour
	MinSessionIdleTTL = 5 * time.Minute
	MaxSessionIdleTTL = 24 * time.Hour
)

// ValidSessionLimits reports whether absolute and idle are within bounds, idle no longer
// than absolute.
func ValidSessionLimits(absolute, idle time.Duration) bool {
	return absolute >= MinSessionTTL && absolute <= MaxSessionTTL && idle >= MinSessionIdleTTL && idle <= MaxSessionIdleTTL && idle <= absolute
}

// MinBackupDepositInterval is the shortest deposit schedule accepted: each run snapshots the
// whole database and uploads it, and KyRecovery admits 60 deposits per token per 15 minutes.
const MinBackupDepositInterval = 15 * time.Minute

// DefaultAppName is the stable KyRecovery pairing and capsule identity, not the product
// display name. Existing KySignOn pairings and capsule filenames must remain usable.
const DefaultAppName = "KySignOn"

// VAPIDKeyFile is the UnifiedPush VAPID private key, under the data directory.
const VAPIDKeyFile = "push-vapid-private.key"

// DefaultBackupKeep is how many sealed capsules a local backup directory retains.
const DefaultBackupKeep = 7

// Config represents runtime application configuration.
type Config struct {
	Port       string
	ListenHost string
	IssuerURL  string
	// RPID and Origin are the WebAuthn relying party identity, derived from IssuerURL at
	// load so a malformed issuer fails startup rather than the first passkey ceremony.
	RPID              string
	Origin            string
	DBPath            string
	DataDir           string
	SecretKey         []byte
	EncryptionKey     []byte
	RSAKeyPath        string
	TrustedProxyCIDRs []string
	// ForwardedHeader names the single header a trusted proxy uses to report the client
	// address. Exactly one header is honoured per deployment: trying several in turn means
	// the one the edge does not overwrite is the one an attacker gets to choose.
	ForwardedHeader string
	BootstrapUser   string
	BootstrapPass   string
	// SecureCookies forces the Secure flag on session cookies. Needed when TLS terminates
	// at a proxy that does not forward X-Forwarded-Proto.
	SecureCookies bool
	// SessionTTL caps a browser login even if it remains active.
	SessionTTL time.Duration
	// SessionIdleTTL requires a fresh login after inactivity anywhere in the suite.
	SessionIdleTTL time.Duration
	// AllowPrivateCallbacks permits operator-supplied URLs on private LAN ranges (never
	// loopback, link-local or metadata). Needed for single-host deployments where every
	// service shares a container network; it widens an attacker-chosen callback into a
	// request forgery primitive aimed at the internal network, so it is off by default.
	AllowPrivateCallbacks bool
	PushRelayURL          string
	PushRelayKey          string
	APNSRelayURL          string
	APNSRelayKey          string
	// UbuntuPushURL is the Lomiri push service notify endpoint; UbuntuPushAppID is KyAuth's
	// click app id there. Configuration only, never device input.
	UbuntuPushURL   string
	UbuntuPushAppID string
	// AppName is the service name KyRecovery knows this instance by.
	AppName string
	// BackupDepositInterval is the default backup schedule when the admin has not set one in
	// the UI. Zero disables the schedule; backups then happen only on request.
	BackupDepositInterval time.Duration
	// BackupDir, when set, receives a copy of every sealed capsule. It is how an instance with
	// no KyRecovery keeps backups at all, and a second copy for one that has.
	BackupDir string
	// BackupKeep is how many local capsules BackupDir retains; older ones are pruned.
	BackupKeep int
	// BackupAllowPrivateRecovery lets the KyRecovery URL resolve to a private or carrier-grade
	// NAT address: a KyRecovery on the operator's own LAN behind a TLS proxy with split DNS.
	// HTTPS stays mandatory; only the address rule is relaxed. Off by default because it turns
	// every scheduled deposit into an unattended request into the internal network.
	BackupAllowPrivateRecovery bool
	// AttestationExtraRoots is an optional PEM file of extra attestation roots.
	AttestationExtraRoots string
	// AttestationStatusURL is Google's revocation list; empty disables the check.
	AttestationStatusURL string
	// KyAuthCertSHA256 lists accepted KyAuth signing-certificate digests (lowercase hex).
	KyAuthCertSHA256 []string
	// AppAttestAppIDs lists `<TeamID>.<bundleID>` values accepted for iOS App Attest; empty disables grading.
	AppAttestAppIDs []string
	// AppAttestAllowDevelopment also accepts the development App Attest environment.
	AppAttestAllowDevelopment bool
}

var certDigestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// DefaultKyAuthCertSHA256 is every key that signs a KyAuth release. Play re-signs uploads with its
// own keys, and Android 17+ installs carry the v3.2 hybrid signer, so Play needs all three.
var DefaultKyAuthCertSHA256 = []string{
	"52f61684029401fcb0137b334ad41907f83948fa1ec1377834f3b4291765fd7b", // release key (GitHub builds)
	"d419c37003033b87630a67f0f27f2295546ebd134956d3f37b20282964317f41", // Play App Signing
	"c3b2a095228c2b80d4646b162dc3478542ff36c692619c0da6a8aa49f8fb11e5", // Play v3.2, classical
	"293d7cd424179eed61003a2d4e1f21f1fb9e41faafc666837c5bf1fab330bc7f", // Play v3.2, ML-DSA
	// F-Droid: add its digest once F-Droid has built and signed KyAuth.
}

// DefaultAppAttestAppIDs is KyAuth iOS, so App Attest grading is on unless an operator turns it off.
var DefaultAppAttestAppIDs = []string{"TATYN4X57D.org.kysecurity.authenticator"}

var ubuntuAppIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*_[a-z0-9][a-z0-9+.-]*$`)

// appIDRE is an Apple App ID: a ten-character Team ID, a dot, and a bundle ID.
var appIDRE = regexp.MustCompile(`^[A-Z0-9]{10}\.[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$`)

// Load loads configuration from environment variables. Anything malformed is an error:
// a server that silently downgrades a misconfigured key is worse than one that will not start.
func Load() (*Config, error) {
	if err := rejectLegacyEnvironment(); err != nil {
		return nil, err
	}
	dataDir := getEnv("KYIDENTITY_DATA_DIR", "./data")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}

	dbPath := databasePath(dataDir)
	rsaKeyPath := getEnv("KYIDENTITY_RSA_KEY_PATH", filepath.Join(dataDir, "jwt_rs256.key"))

	port := getEnv("KYIDENTITY_PORT", "5867")
	listenHost := os.Getenv("KYIDENTITY_LISTEN_HOST")
	if listenHost != "" && net.ParseIP(listenHost) == nil {
		return nil, errors.New("KYIDENTITY_LISTEN_HOST must be a literal IP address")
	}
	issuerURL := strings.TrimRight(getEnv("KYIDENTITY_ISSUER_URL", "http://localhost:"+port), "/")
	issuer, err := url.Parse(issuerURL)
	if err != nil || issuer.Hostname() == "" || (issuer.Scheme != "https" && !issuerIsLocal(issuer)) {
		return nil, fmt.Errorf("KYIDENTITY_ISSUER_URL must be an https URL (http is allowed only on loopback)")
	}
	rpID, rpOrigin, err := webauthn.RPIDFromIssuer(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("KYIDENTITY_ISSUER_URL cannot be used as a WebAuthn relying party: %w", err)
	}

	secretKey, err := loadKey("KYIDENTITY_SECRET_KEY", filepath.Join(dataDir, "secret.key"))
	if err != nil {
		return nil, err
	}

	encKey, err := loadKey("KYIDENTITY_ENCRYPTION_KEY", filepath.Join(dataDir, "encryption.key"))
	if err != nil {
		return nil, err
	}

	trustedCIDRs, err := loadTrustedProxies()
	if err != nil {
		return nil, err
	}
	forwardedHeader, err := loadForwardedHeader()
	if err != nil {
		return nil, err
	}
	sessionTTL, err := loadPositiveDuration("KYIDENTITY_SESSION_TTL", DefaultSessionTTL)
	if err != nil {
		return nil, err
	}
	sessionIdleTTL, err := loadPositiveDuration("KYIDENTITY_SESSION_IDLE_TTL", DefaultSessionIdleTTL)
	if err != nil {
		return nil, err
	}
	if sessionIdleTTL > sessionTTL {
		return nil, fmt.Errorf("KYIDENTITY_SESSION_IDLE_TTL must not exceed KYIDENTITY_SESSION_TTL")
	}
	if !ValidSessionLimits(sessionTTL, sessionIdleTTL) {
		return nil, fmt.Errorf("KYIDENTITY_SESSION_TTL must be %v to %v and KYIDENTITY_SESSION_IDLE_TTL %v to %v", MinSessionTTL, MaxSessionTTL, MinSessionIdleTTL, MaxSessionIdleTTL)
	}
	pushRelayURL, err := loadRelayURL("PUSH_RELAY_URL")
	if err != nil {
		return nil, err
	}
	apnsRelayURL, err := loadRelayURL("APNS_RELAY_URL")
	if err != nil {
		return nil, err
	}
	ubuntuPushURL := strings.TrimSpace(getEnv("KYIDENTITY_UBUNTU_PUSH_URL", "https://push.ubports.com/notify"))
	if u, err := url.Parse(ubuntuPushURL); err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return nil, errors.New("KYIDENTITY_UBUNTU_PUSH_URL must be an https URL")
	}
	ubuntuPushAppID := strings.TrimSpace(getEnv("KYIDENTITY_UBUNTU_PUSH_APPID", "kyauth.busnes_kyauth"))
	if !ubuntuAppIDRE.MatchString(ubuntuPushAppID) {
		return nil, fmt.Errorf("KYIDENTITY_UBUNTU_PUSH_APPID %q is not a package_app id", ubuntuPushAppID)
	}
	depositInterval, err := loadDepositInterval()
	if err != nil {
		return nil, err
	}
	backupDir, backupKeep, err := loadBackupDir()
	if err != nil {
		return nil, err
	}

	attestationExtraRoots := strings.TrimSpace(os.Getenv("KYIDENTITY_ATTESTATION_EXTRA_ROOTS"))
	attestationStatusURL := "https://android.googleapis.com/attestation/status"
	if v, ok := os.LookupEnv("KYIDENTITY_ATTESTATION_STATUS_URL"); ok {
		attestationStatusURL = strings.TrimSpace(v)
	}
	if attestationStatusURL != "" && !strings.HasPrefix(attestationStatusURL, "https://") {
		return nil, errors.New("KYIDENTITY_ATTESTATION_STATUS_URL must be https")
	}
	kyAuthCertSHA256 := DefaultKyAuthCertSHA256
	if v := strings.TrimSpace(os.Getenv("KYIDENTITY_KYAUTH_CERT_SHA256")); v != "" {
		kyAuthCertSHA256 = nil
		for _, d := range strings.Split(v, ",") {
			d = strings.ToLower(strings.TrimSpace(d))
			if !certDigestRE.MatchString(d) {
				return nil, fmt.Errorf("KYIDENTITY_KYAUTH_CERT_SHA256: %q is not a 64-hex digest", d)
			}
			kyAuthCertSHA256 = append(kyAuthCertSHA256, d)
		}
	}

	appAttestAppIDs, appAttestAllowDevelopment, err := loadAppAttest()
	if err != nil {
		return nil, err
	}

	return &Config{
		Port:                       port,
		ListenHost:                 listenHost,
		IssuerURL:                  issuerURL,
		RPID:                       rpID,
		Origin:                     rpOrigin,
		DBPath:                     dbPath,
		DataDir:                    dataDir,
		SecretKey:                  secretKey,
		EncryptionKey:              encKey,
		RSAKeyPath:                 rsaKeyPath,
		TrustedProxyCIDRs:          trustedCIDRs,
		ForwardedHeader:            forwardedHeader,
		BootstrapUser:              getEnv("BOOTSTRAP_ADMIN_USER", "admin"),
		BootstrapPass:              os.Getenv("BOOTSTRAP_ADMIN_PASS"),
		SecureCookies:              issuer.Scheme == "https" || strings.EqualFold(os.Getenv("KYIDENTITY_SECURE_COOKIES"), "true"),
		SessionTTL:                 sessionTTL,
		SessionIdleTTL:             sessionIdleTTL,
		AllowPrivateCallbacks:      strings.EqualFold(os.Getenv("KYIDENTITY_ALLOW_PRIVATE_CALLBACKS"), "true"),
		PushRelayURL:               pushRelayURL,
		PushRelayKey:               strings.TrimSpace(os.Getenv("PUSH_RELAY_KEY")),
		APNSRelayURL:               apnsRelayURL,
		APNSRelayKey:               strings.TrimSpace(os.Getenv("APNS_RELAY_KEY")),
		UbuntuPushURL:              ubuntuPushURL,
		UbuntuPushAppID:            ubuntuPushAppID,
		AppName:                    getEnv("KYIDENTITY_APP_NAME", DefaultAppName),
		BackupDepositInterval:      depositInterval,
		BackupDir:                  backupDir,
		BackupKeep:                 backupKeep,
		BackupAllowPrivateRecovery: strings.EqualFold(os.Getenv("KYIDENTITY_BACKUP_ALLOW_PRIVATE_RECOVERY"), "true"),
		AttestationExtraRoots:      attestationExtraRoots,
		AttestationStatusURL:       attestationStatusURL,
		KyAuthCertSHA256:           kyAuthCertSHA256,
		AppAttestAppIDs:            appAttestAppIDs,
		AppAttestAllowDevelopment:  appAttestAllowDevelopment,
	}, nil
}

func loadAppAttest() ([]string, bool, error) {
	// Unset keeps the default; set but empty turns grading off.
	ids := DefaultAppAttestAppIDs
	if v, ok := os.LookupEnv("KYIDENTITY_APPATTEST_APP_IDS"); ok {
		ids = nil
		if v = strings.TrimSpace(v); v != "" {
			for _, id := range strings.Split(v, ",") {
				id = strings.TrimSpace(id)
				if len(id) > 255 || !appIDRE.MatchString(id) {
					return nil, false, fmt.Errorf("KYIDENTITY_APPATTEST_APP_IDS: %q is not <TeamID>.<bundleID>", id)
				}
				ids = append(ids, id)
			}
		}
	}
	var dev bool
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv("KYIDENTITY_APPATTEST_ALLOW_DEVELOPMENT"))); v {
	case "", "false":
	case "true":
		dev = true
	default:
		return nil, false, fmt.Errorf("KYIDENTITY_APPATTEST_ALLOW_DEVELOPMENT: %q is not true or false", v)
	}
	return ids, dev, nil
}

func rejectLegacyEnvironment() error {
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "KYSIGNON_") && strings.TrimSpace(strings.TrimPrefix(entry, name+"=")) != "" {
			return fmt.Errorf("legacy environment variable %s is set; use %s instead", name, "KYIDENTITY_"+strings.TrimPrefix(name, "KYSIGNON_"))
		}
	}
	return nil
}

func databasePath(dataDir string) string {
	if path := strings.TrimSpace(os.Getenv("KYIDENTITY_DB_PATH")); path != "" {
		return path
	}
	// Prefer an existing legacy database during an in-place upgrade; fresh installs and
	// restored capsules use the current filename.
	current := filepath.Join(dataDir, "kyidentity.db")
	legacy := filepath.Join(dataDir, "kysignon.db")
	if _, err := os.Stat(current); os.IsNotExist(err) {
		if _, legacyErr := os.Stat(legacy); legacyErr == nil {
			return legacy
		}
	}
	return current
}

// loadDepositInterval reads KYIDENTITY_BACKUP_DEPOSIT_INTERVAL: a Go duration, default 24h,
// "0" disables, anything else below the minimum or negative fails startup.
func loadDepositInterval() (time.Duration, error) {
	const name = "KYIDENTITY_BACKUP_DEPOSIT_INTERVAL"
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("%s must be a non-negative Go duration (for example 24h; 0 disables)", name)
	}
	if d != 0 && d < MinBackupDepositInterval {
		return 0, fmt.Errorf("%s %s is below the %s minimum (0 disables)", name, d, MinBackupDepositInterval)
	}
	return d, nil
}

// loadBackupDir reads KYIDENTITY_BACKUP_DIR (absolute path, off when empty) and
// KYIDENTITY_BACKUP_KEEP (default 7, at least 1).
func loadBackupDir() (string, int, error) {
	dir := strings.TrimSpace(os.Getenv("KYIDENTITY_BACKUP_DIR"))
	if dir != "" {
		if !filepath.IsAbs(dir) {
			return "", 0, fmt.Errorf("KYIDENTITY_BACKUP_DIR must be an absolute path, got %q", dir)
		}
		dir = filepath.Clean(dir)
	}
	keep := DefaultBackupKeep
	if raw := strings.TrimSpace(os.Getenv("KYIDENTITY_BACKUP_KEEP")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return "", 0, fmt.Errorf("KYIDENTITY_BACKUP_KEEP must be a positive integer, got %q", raw)
		}
		keep = n
	}
	return dir, keep, nil
}

func loadRelayURL(name string) (string, error) {
	raw := strings.TrimRight(strings.TrimSpace(os.Getenv(name)), "/")
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.Scheme != "https" {
		return "", fmt.Errorf("%s must be an https URL", name)
	}
	return raw, nil
}

func loadPositiveDuration(name string, defaultValue time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return defaultValue, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration (for example 24h or 30m)", name)
	}
	return value, nil
}

func issuerIsLocal(u *url.URL) bool {
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// loadKey reads a 32-byte key from the environment as hex, falling back to a generated
// file. Both paths are strict; there is no shortening, padding, or silent regeneration.
func loadKey(envName, path string) ([]byte, error) {
	if raw := os.Getenv(envName); raw != "" {
		key, err := hex.DecodeString(strings.TrimSpace(raw))
		if err != nil || len(key) != KeyLength {
			return nil, fmt.Errorf(
				"%s must be exactly %d hex characters (%d bytes); generate one with: openssl rand -hex %d",
				envName, KeyLength*2, KeyLength, KeyLength)
		}
		return key, nil
	}
	return loadOrGenerateKeyFile(path)
}

func loadOrGenerateKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(data) != KeyLength {
			return nil, fmt.Errorf(
				"key file %s holds %d bytes, expected %d; refusing to overwrite it, "+
					"since data encrypted under the original key would become unrecoverable",
				path, len(data), KeyLength)
		}
		return data, nil
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("failed to read key file %s: %w", path, err)
	}

	key := make([]byte, KeyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("random source failed while generating %s: %w", path, err)
	}
	if err := crypto.CreateKeyFile(path, key); errors.Is(err, os.ErrExist) {
		return loadOrGenerateKeyFile(path) // a concurrent first start won; use its key
	} else if err != nil {
		return nil, fmt.Errorf("failed to persist generated key to %s: %w", path, err)
	}
	return key, nil
}

// DefaultForwardedHeader is the forwarding contract assumed when the operator names none.
const DefaultForwardedHeader = "X-Forwarded-For"

// loadForwardedHeader picks the one header a trusted proxy is believed on. Behind
// Cloudflare set KYIDENTITY_FORWARDED_HEADER=CF-Connecting-IP; behind most other proxies the
// default is correct.
func loadForwardedHeader() (string, error) {
	raw := strings.TrimSpace(os.Getenv("KYIDENTITY_FORWARDED_HEADER"))
	if raw == "" {
		return DefaultForwardedHeader, nil
	}
	// A header name with spaces or separators is a typo, and a typo here silently attributes
	// every request to the proxy instead of the client.
	if strings.ContainsAny(raw, " \t:,;\r\n") {
		return "", fmt.Errorf("KYIDENTITY_FORWARDED_HEADER %q is not a valid header name", raw)
	}
	return http.CanonicalHeaderKey(raw), nil
}

// loadTrustedProxies parses TRUSTED_PROXY_CIDRS. It defaults to empty: forwarding headers
// are only believed from peers an operator has explicitly named. Bare IPs are accepted
// and treated as single-host ranges.
func loadTrustedProxies() ([]string, error) {
	raw := os.Getenv("TRUSTED_PROXY_CIDRS")
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	var cidrs []string
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("TRUSTED_PROXY_CIDRS entry %q is not a valid IP or CIDR", entry)
			}
			if ip.To4() != nil {
				entry += "/32"
			} else {
				entry += "/128"
			}
		}
		if _, _, err := net.ParseCIDR(entry); err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXY_CIDRS entry %q is not a valid CIDR: %w", entry, err)
		}
		cidrs = append(cidrs, entry)
	}
	return cidrs, nil
}
