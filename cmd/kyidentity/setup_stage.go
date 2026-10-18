package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"

	"github.com/Busnes-app/ky-primitives/keyfile"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

const setupBundleLimit = 128 * 1024

// Protected ancestry keeps pathname publication safe from other local users.
// Sticky shared ancestors (such as /tmp) are allowed; the owned anchor is not shared.
func openSetupParent(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsFunc(path, unicode.IsControl) {
		return -1, errors.New("setup files require clean absolute container-local paths")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, errors.New("cannot open protected setup directory")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, err := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			return -1, errors.New("cannot open protected setup directory")
		}
		fd = next
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (st.Mode&0022 != 0 && st.Mode&syscall.S_ISVTX == 0) {
			syscall.Close(fd)
			return -1, errors.New("setup directories require protected ownership and permissions")
		}
	}
	return fd, nil
}

func requireSetupDirectory(dir string, private bool) error {
	fd, err := openSetupParent(filepath.Join(dir, "setup.json"))
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	mask := uint32(0022)
	if private {
		mask = 0077
	}
	if syscall.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&mask != 0 {
		return errors.New("setup directory must belong to the container user and be protected")
	}
	return nil
}

func setupDataDirectory() (string, error) {
	dir := strings.TrimSpace(os.Getenv("KYIDENTITY_DATA_DIR"))
	if dir == "" {
		dir = "data"
	}
	return filepath.Abs(dir)
}

func setupDatabasePath(path string) string {
	if path != "" {
		return path
	}
	if path = strings.TrimSpace(os.Getenv("KYIDENTITY_DB_PATH")); path != "" {
		return path
	}
	dir := strings.TrimSpace(os.Getenv("KYIDENTITY_DATA_DIR"))
	if dir == "" {
		dir = "data"
	}
	path = filepath.Join(dir, "kyidentity.db")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		legacy := filepath.Join(dir, "kysignon.db")
		if _, err := os.Stat(legacy); err == nil {
			return legacy
		}
	}
	return path
}

func preparationPath(file string) bool {
	id, err := uuid.Parse(filepath.Base(filepath.Dir(file)))
	return err == nil && id.String() == filepath.Base(filepath.Dir(file)) && filepath.Base(file) == "setup.json" && filepath.Base(filepath.Dir(filepath.Dir(file))) == "installer"
}

func publishSetupFile(file string, raw []byte) (bool, error) {
	if err := keyfile.Store(file, raw, keyfile.Raw); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return false, errors.New("cannot publish protected setup file")
		}
		existing, err := readSetupFile(file, setupBundleLimit)
		if err != nil || !bytes.Equal(existing, raw) {
			return false, errors.New("retained preparation differs or is unsafe; files preserved")
		}
		return false, nil
	}
	return true, nil
}

func setupFilePresent(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("cannot inspect preparation state")
	}
	return true, nil
}

// stageSetup creates target-held credentials and an immutable preparation receipt.
// It never creates accounts, runs migrations, or replaces an existing file.
func stageSetup(file, db string, raw []byte, check bool) (string, error) {
	if len(raw) > setupBundleLimit {
		return "", errors.New("preparation metadata is too large")
	}
	var b setupBundle
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || d.Decode(new(any)) != io.EOF {
		return "", errors.New("invalid preparation metadata")
	}
	id, err := uuid.Parse(b.ID)
	if err != nil || id.String() != b.ID {
		return "", errors.New("setupId must be a canonical UUID")
	}
	data, err := setupDataDirectory()
	if err != nil {
		return "", errors.New("invalid product data directory")
	}
	scope := filepath.Join(data, "installer", b.ID)
	if file != filepath.Join(scope, "setup.json") {
		return "", errors.New("preparation requires the product-owned setup UUID directory")
	}
	generated := []string{}
	bind := func(field *string, name string) error {
		path := filepath.Join(scope, name)
		if *field != "" && *field != path {
			return errors.New("generated credential paths must match their setup-owned location")
		}
		*field = path
		generated = append(generated, path)
		return nil
	}
	// An amendment holds no account blocks, so it never generates passwords.
	if b.Extends == "" && (bind(&b.Admin.PasswordFile, "admin.password") != nil || bind(&b.Everyday.PasswordFile, "everyday.password") != nil) {
		return "", errors.New("invalid account credential preparation paths")
	}
	for i := range b.Clients {
		c := &b.Clients[i]
		if !setupName.MatchString(c.ID) {
			return "", errors.New("invalid preparation client identifier")
		}
		if err := bind(&c.SecretFile, "client-"+c.ID+".secret"); err != nil {
			return "", err
		}
		if c.SuiteWebhook != nil {
			if err := bind(&c.SuiteWebhook.SigningSecretFile, "client-"+c.ID+".webhook"); err != nil {
				return "", err
			}
		}
	}
	canonical, err := json.Marshal(b)
	if err != nil || len(canonical) > setupBundleLimit {
		return "", errors.New("invalid preparation size")
	}
	if _, _, err := setupMetadata(canonical); err != nil {
		return "", err
	}
	digests := map[string]string{}
	digest := func(name string, value []byte) {
		sum := sha256.Sum256(value)
		digests[name] = hex.EncodeToString(sum[:])
	}
	// Destination-issued SCIM tokens and the existing encryption key are never generated.
	needsKey := false
	for _, c := range b.Clients {
		if c.SCIM != nil {
			if err := scimTokenAllowed(c.SCIM.TokenFile, append(append([]string{file}, generated...), setupCredentialFiles(b)...)); err != nil {
				return "", err
			}
			token, err := readSetupFile(c.SCIM.TokenFile, 8193)
			if err != nil {
				return "", errors.New("destination-issued SCIM token is unavailable")
			}
			value := strings.TrimSuffix(string(token), "\n")
			if len(value) < 32 || len(value) > 8192 || strings.IndexFunc(value, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
				return "", errors.New("invalid destination-issued SCIM token")
			}
			digest(c.SCIM.TokenFile, token)
			needsKey = true
		}
		needsKey = needsKey || c.SuiteWebhook != nil
	}
	if needsKey {
		key, err := existingSetupEncryptionKey()
		if err != nil {
			return "", err
		}
		digest("product-encryption-key", key)
	}
	if requireSetupDirectory(data, false) != nil {
		return "", errors.New("preparation requires an owned protected product data directory")
	}
	db = setupDatabasePath(db)
	s, err := store.OpenInstallerStore(db, check)
	if err != nil {
		return "", errors.New("preparation requires an initialized product database")
	}
	defer s.Close()
	applied, err := s.InstallerSetupExists(b.ID)
	if err != nil {
		return "", errors.New("cannot inspect native setup ownership")
	}
	if b.Extends != "" {
		// Mint nothing for a parent that was never applied; apply inspects it fully.
		parent, err := s.InstallerSetupExists(b.Extends)
		if err != nil || !parent {
			return "", errors.New("amendment requires its applied parent setup")
		}
	}
	for _, dir := range []string{filepath.Dir(scope), scope} {
		if !check && !applied {
			if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return "", errors.New("cannot create private preparation directory")
			}
		}
		if requireSetupDirectory(dir, true) != nil {
			return "", errors.New("preparation directory is missing, shared or unsafe")
		}
	}
	intent := filepath.Join(scope, "intent.json")
	receipt := filepath.Join(scope, "credentials.json")
	intentExists, err := setupFilePresent(intent)
	if err != nil {
		return "", err
	}
	if !intentExists {
		if check || applied {
			return "", errors.New("preparation intent is missing; files preserved")
		}
		directory, err := os.Open(scope)
		if err != nil {
			return "", errors.New("cannot inspect unclaimed preparation directory")
		}
		entries, readErr := directory.ReadDir(16)
		closeErr := directory.Close()
		if (readErr != nil && readErr != io.EOF) || closeErr != nil || len(entries) == 16 {
			return "", errors.New("unclaimed preparation directory is not empty; files preserved")
		}
		// An interrupted intent publication leaves only keyfile's private temp files.
		for _, e := range entries {
			if stray, _ := filepath.Match(".keyfile-*.tmp", e.Name()); !stray || !e.Type().IsRegular() {
				return "", errors.New("unclaimed preparation directory is not empty; files preserved")
			}
		}
		for _, e := range entries {
			if err := os.Remove(filepath.Join(scope, e.Name())); err != nil {
				return "", errors.New("cannot clear interrupted preparation; files preserved")
			}
		}
		if _, err := publishSetupFile(intent, canonical); err != nil {
			return "", err
		}
	} else {
		retained, err := readSetupFile(intent, setupBundleLimit)
		if err != nil || !bytes.Equal(retained, canonical) {
			return "", errors.New("preparation intent changed or is unsafe; files preserved")
		}
	}
	complete, err := setupFilePresent(receipt)
	if err != nil {
		return "", err
	}
	bundleExists, err := setupFilePresent(file)
	if err != nil {
		return "", err
	}
	if !complete && (check || applied || bundleExists) {
		return "", errors.New("credential receipt is missing; files preserved")
	}
	for _, path := range generated {
		exists, err := setupFilePresent(path)
		if err != nil {
			return "", err
		}
		if !exists {
			if check || applied || complete {
				return "", errors.New("prepared credential is missing; replacement refused")
			}
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return "", errors.New("target credential generation failed")
			}
			encoded := []byte(base64.RawURLEncoding.EncodeToString(key))
			if err := keyfile.Store(path, encoded, keyfile.Raw); err != nil && !errors.Is(err, os.ErrExist) {
				return "", errors.New("cannot publish target credential")
			}
		}
		value, err := readSetupFile(path, 43)
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(string(value))
		if err != nil || decodeErr != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != string(value) {
			return "", errors.New("prepared credential is unsafe or malformed; files preserved")
		}
		digest(path, value)
	}
	sum := sha256.Sum256(canonical)
	sealed, err := json.Marshal(struct {
		Schema       string            `json:"schema"`
		BundleDigest string            `json:"bundleDigest"`
		Credentials  map[string]string `json:"credentials"`
	}{"kyidentity.prepared-credentials/1", hex.EncodeToString(sum[:]), digests})
	if err != nil || len(sealed) > setupBundleLimit {
		return "", errors.New("cannot encode bounded preparation receipt")
	}
	if complete {
		retained, err := readSetupFile(receipt, setupBundleLimit)
		if err != nil || !bytes.Equal(retained, sealed) {
			return "", errors.New("prepared credentials changed or receipt is unsafe; files preserved")
		}
	} else if _, err := publishSetupFile(receipt, sealed); err != nil {
		return "", err
	}
	// Commit a credential digest to native ownership before publishing the usable bundle.
	// It prevents replacement even if every filesystem completion marker is lost.
	receiptSum := sha256.Sum256(sealed)
	if err := s.RecordInstallerPreparation(b.ID, hex.EncodeToString(receiptSum[:]), check); err != nil {
		return "", errors.New("native preparation receipt is missing, changed or could not be audited")
	}
	if check {
		retained, err := readSetupFile(file, setupBundleLimit)
		if err != nil || !bytes.Equal(retained, canonical) {
			return "", errors.New("prepared bundle is missing, changed or unsafe")
		}
		return "present", nil
	}
	created, err := publishSetupFile(file, canonical)
	if err != nil {
		return "", err
	}
	if created {
		return "created", nil
	}
	return "present", nil
}
