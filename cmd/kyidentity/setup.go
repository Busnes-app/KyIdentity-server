package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

type setupAccount struct {
	Username     string `json:"username"`
	Email        string `json:"email"`
	PasswordFile string `json:"passwordFile"`
}
type setupClient struct {
	ID                string             `json:"id"`
	Name              string             `json:"name"`
	SecretFile        string             `json:"secretFile"`
	RedirectURIs      []string           `json:"redirectUris"`
	PostLogoutURIs    []string           `json:"postLogoutUris"`
	AdministratorRole string             `json:"administratorRole,omitempty"`
	EverydayRole      string             `json:"everydayRole,omitempty"`
	SCIM              *setupSCIM         `json:"scim,omitempty"`
	SuiteWebhook      *setupSuiteWebhook `json:"suiteWebhook,omitempty"`
	Groups            []string           `json:"groups,omitempty"`
}
type setupSCIM struct {
	URL       string `json:"url"`
	TokenFile string `json:"tokenFile"`
	Groups    bool   `json:"groups,omitempty"`
}
type setupSuiteWebhook struct {
	URL               string `json:"url"`
	SigningSecretFile string `json:"signingSecretFile"`
}
type setupGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members"`
}
type setupBundle struct {
	Schema   string        `json:"schema"`
	ID       string        `json:"setupId"`
	Admin    setupAccount  `json:"admin"`
	Everyday setupAccount  `json:"everyday"`
	Clients  []setupClient `json:"clients"`
	Groups   []setupGroup  `json:"groups,omitempty"`
}

var setupName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
var setupRoleName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
var setupGroupName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$`)

// readSetupFile refuses symlinks, unsafe ancestry and shared credential files.
func readSetupFile(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("setup files require absolute container-local paths")
	}
	parent, err := openSetupParent(path)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(parent)
	fd, err := syscall.Openat(parent, filepath.Base(path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("cannot open protected setup file")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > limit {
		return nil, errors.New("setup files must be regular, private and within the size limit")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("setup files must belong to the container user")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("cannot read bounded setup file")
	}
	return b, nil
}

// scimTokenAllowed refuses setup credentials, preparation directories and product
// secrets as a SCIM token: the worker would send that file to the connector URL.
func scimTokenAllowed(path string, own []string) error {
	path = filepath.Clean(path)
	data, err := setupDataDirectory()
	if err != nil {
		return err
	}
	refused := append(append([]string{}, own...), setupDatabasePath(""))
	roots := []string{data}
	if real, err := filepath.EvalSymlinks(data); err == nil {
		roots = append(roots, real)
	}
	for _, root := range roots {
		if rel, err := filepath.Rel(filepath.Join(root, "installer"), path); err == nil && strings.Contains(rel, string(filepath.Separator)) && !strings.HasPrefix(rel, "..") {
			return errors.New("SCIM token cannot use a preparation-owned directory")
		}
		refused = append(refused, filepath.Join(root, "encryption.key"))
	}
	for _, p := range refused {
		if abs, err := filepath.Abs(p); err == nil && p != "" && abs == path {
			return errors.New("SCIM tokens must be destination-issued protected files")
		}
	}
	return nil
}

func setupCredentialFiles(b setupBundle) []string {
	files := []string{b.Admin.PasswordFile, b.Everyday.PasswordFile}
	for _, c := range b.Clients {
		files = append(files, c.SecretFile)
		if c.SuiteWebhook != nil {
			files = append(files, c.SuiteWebhook.SigningSecretFile)
		}
	}
	return files
}

func setupURI(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && !strings.ContainsAny(s, "\r\n\t ")
}
func setupMetadata(b []byte) (setupBundle, store.InstallerSetup, error) {
	var bundle setupBundle
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&bundle); err != nil {
		return bundle, store.InstallerSetup{}, errors.New("invalid setup bundle")
	}
	if d.Decode(new(any)) != io.EOF {
		return bundle, store.InstallerSetup{}, errors.New("setup bundle must contain one JSON object")
	}
	if bundle.Schema != "kyidentity.setup/1" || len(bundle.Clients) > 32 || len(bundle.Groups) > 32 {
		return bundle, store.InstallerSetup{}, errors.New("unsupported setup schema or client count")
	}
	id, err := uuid.Parse(bundle.ID)
	if err != nil || id.String() != bundle.ID {
		return bundle, store.InstallerSetup{}, errors.New("setupId must be a canonical UUID")
	}
	if strings.EqualFold(bundle.Admin.Username, bundle.Everyday.Username) || strings.EqualFold(bundle.Admin.Email, bundle.Everyday.Email) {
		return bundle, store.InstallerSetup{}, errors.New("administrator and everyday identities must be distinct")
	}
	p := store.InstallerSetup{ID: bundle.ID}
	// Validate the whole bundle before opening credentials or mutating the database.
	for _, u := range []setupAccount{bundle.Admin, bundle.Everyday} {
		addr, err := mail.ParseAddress(u.Email)
		if !setupName.MatchString(u.Username) || err != nil || addr.Address != u.Email || len(u.Email) > 254 {
			return bundle, p, errors.New("invalid setup account name or email")
		}
	}
	ids := map[string]bool{}
	groups := map[string]bool{}
	groupNames := map[string]bool{}
	for _, g := range bundle.Groups {
		if !setupGroupName.MatchString(g.Name) || strings.TrimSpace(g.Name) != g.Name || groupNames[strings.ToLower(g.Name)] || len(g.Description) > 1024 || strings.ContainsAny(g.Description, "\x00\r\n") || len(g.Members) > 1 || len(g.Members) == 1 && g.Members[0] != bundle.Everyday.Username {
			return bundle, p, errors.New("invalid group, duplicate name or non-everyday member")
		}
		groups[g.Name], groupNames[strings.ToLower(g.Name)] = true, true
		p.Groups = append(p.Groups, store.InstallerGroup{Name: g.Name, Description: g.Description, IncludeEveryday: len(g.Members) == 1})
	}
	for _, c := range bundle.Clients {
		if c.SCIM != nil && c.SuiteWebhook != nil {
			return bundle, p, errors.New("choose one SCIM or signed suite connector per client")
		}
		if c.SuiteWebhook != nil {
			u, err := url.Parse(c.SuiteWebhook.URL)
			if err != nil || !setupURI(c.SuiteWebhook.URL) || len(c.SuiteWebhook.URL) > 2048 || u.RawQuery != "" || u.ForceQuery || strings.Contains(c.SuiteWebhook.URL, "#") || !filepath.IsAbs(c.SuiteWebhook.SigningSecretFile) {
				return bundle, p, errors.New("suite webhook requires an HTTPS endpoint and absolute protected signing secret file")
			}
		}
		if len(c.Groups) > 32 || len(c.Groups) > 0 && c.AdministratorRole != "" && c.EverydayRole == "" {
			return bundle, p, errors.New("management-only clients cannot grant ordinary directory groups")
		}
		seenGroups := map[string]bool{}
		for _, group := range c.Groups {
			if !groups[group] || seenGroups[group] {
				return bundle, p, errors.New("client group must name a distinct bundle-owned group")
			}
			seenGroups[group] = true
		}
		if c.SCIM != nil {
			if c.SCIM.Groups && len(c.Groups) == 0 {
				return bundle, p, errors.New("SCIM group delivery requires assigned bundle groups")
			}
			u, err := url.Parse(c.SCIM.URL)
			if err != nil || !setupURI(c.SCIM.URL) || len(c.SCIM.URL) > 2048 || u.RawQuery != "" || u.ForceQuery || strings.Contains(c.SCIM.URL, "#") ||
				!filepath.IsAbs(c.SCIM.TokenFile) {
				return bundle, p, errors.New("SCIM requires an HTTPS base URL and absolute protected token file")
			}
		}
		if (c.AdministratorRole != "" && !setupRoleName.MatchString(c.AdministratorRole)) ||
			(c.EverydayRole != "" && !setupRoleName.MatchString(c.EverydayRole)) ||
			(c.AdministratorRole != "" && strings.EqualFold(c.AdministratorRole, c.EverydayRole)) {
			return bundle, p, errors.New("app administrator and everyday roles must be valid and distinct")
		}
		if !setupName.MatchString(c.ID) || ids[strings.ToLower(c.ID)] || len(c.Name) < 1 || len(c.Name) > 128 || strings.ContainsAny(c.Name, "\r\n\t") || len(c.RedirectURIs) == 0 || len(c.RedirectURIs) > 16 || len(c.PostLogoutURIs) > 16 {
			return bundle, p, errors.New("invalid or duplicate setup client")
		}
		ids[strings.ToLower(c.ID)] = true
		for _, u := range append(append([]string{}, c.RedirectURIs...), c.PostLogoutURIs...) {
			if len(u) > 2048 || !setupURI(u) {
				return bundle, p, errors.New("setup redirects require HTTPS without credentials or fragments")
			}
		}
	}
	return bundle, p, nil
}

func prepareSetup(raw []byte) (store.InstallerSetup, error) {
	bundle, p, err := setupMetadata(raw)
	if err != nil {
		return p, err
	}
	for i, u := range []setupAccount{bundle.Admin, bundle.Everyday} {
		raw, err := readSetupFile(u.PasswordFile, 1024)
		if err != nil {
			return p, err
		}
		password := strings.TrimSuffix(string(raw), "\n")
		if strings.ContainsAny(password, "\r\n\x00") {
			return p, errors.New("invalid password file")
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			return p, errors.New("password must contain 12 to 1024 bytes")
		}
		account := store.InstallerUser{Username: u.Username, Email: u.Email, Role: "user", PasswordHash: hash}
		if i == 0 {
			account.Role = "admin"
			p.Admin = account
		} else {
			p.Everyday = account
		}
	}
	for _, c := range bundle.Clients {
		raw, err := readSetupFile(c.SecretFile, 1024)
		if err != nil {
			return p, err
		}
		secret := strings.TrimSuffix(string(raw), "\n")
		if len(secret) < 32 || strings.ContainsAny(secret, "\r\n\x00") {
			return p, errors.New("client secret requires at least 32 bytes without newlines")
		}
		logout := c.PostLogoutURIs
		if logout == nil {
			logout = []string{}
		}
		client := store.InstallerClient{ID: c.ID, Name: c.Name, SecretHash: crypto.HashSHA256(secret), RedirectURIs: c.RedirectURIs, PostLogoutURIs: logout,
			AdministratorRole: c.AdministratorRole, EverydayRole: c.EverydayRole}
		client.Groups = append([]string(nil), c.Groups...)
		sort.Strings(client.Groups)
		if c.SCIM != nil {
			if err := scimTokenAllowed(c.SCIM.TokenFile, setupCredentialFiles(bundle)); err != nil {
				return p, err
			}
			raw, err := readSetupFile(c.SCIM.TokenFile, 8193)
			if err != nil {
				return p, err
			}
			token := strings.TrimSuffix(string(raw), "\n")
			if len(token) < 32 || len(token) > 8192 || strings.IndexFunc(token, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
				return p, errors.New("SCIM token requires 32 to 8192 visible ASCII bytes without spaces")
			}
			if p.EncryptionKey == nil {
				p.EncryptionKey, err = existingSetupEncryptionKey()
				if err != nil {
					return p, err
				}
			}
			client.SCIM = &store.InstallerSCIM{URL: c.SCIM.URL, Token: token, Groups: c.SCIM.Groups}
		}
		if c.SuiteWebhook != nil {
			raw, err := readSetupFile(c.SuiteWebhook.SigningSecretFile, 1025)
			if err != nil {
				return p, err
			}
			secret := strings.TrimSuffix(string(raw), "\n")
			if len(secret) < 32 || len(secret) > 1024 || strings.IndexFunc(secret, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
				return p, errors.New("suite signing secret requires 32 to 1024 visible ASCII bytes without spaces")
			}
			if p.EncryptionKey == nil {
				p.EncryptionKey, err = existingSetupEncryptionKey()
				if err != nil {
					return p, err
				}
			}
			client.SuiteWebhook = &store.InstallerSuiteWebhook{URL: c.SuiteWebhook.URL, SigningSecret: secret}
		}
		p.Clients = append(p.Clients, client)
	}
	return p, nil
}

// Inspection and setup reuse the running product's key; neither may generate one.
func existingSetupEncryptionKey() ([]byte, error) {
	if raw := os.Getenv("KYIDENTITY_ENCRYPTION_KEY"); raw != "" {
		key, err := hex.DecodeString(strings.TrimSpace(raw))
		if err != nil || len(key) != 32 {
			return nil, errors.New("existing encryption key is invalid")
		}
		return key, nil
	}
	dir := os.Getenv("KYIDENTITY_DATA_DIR")
	if dir == "" {
		dir = "data"
	}
	path, err := filepath.Abs(filepath.Join(dir, "encryption.key"))
	if err != nil {
		return nil, errors.New("existing encryption key is unavailable")
	}
	key, err := readSetupFile(path, 32)
	if err != nil || len(key) != 32 {
		return nil, errors.New("existing protected encryption key is unavailable or invalid")
	}
	return key, nil
}
func runSetup(args []string, out io.Writer) error {
	return runSetupInput(args, os.Stdin, out)
}

func runSetupInput(args []string, input io.Reader, out io.Writer) error {
	flags := flag.NewFlagSet("apply-setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	file := flags.String("file", "", "protected container-local JSON bundle")
	db := flags.String("db", "", "existing database path; default KYIDENTITY_DB_PATH or data/kyidentity.db")
	check := flags.Bool("check", false, "verify without applying the bundle")
	stage := flags.Bool("stage", false, "prepare secret-free metadata and target credentials from stdin")
	exportClient := flags.String("export-client", "", "private machine-only export of one owned client")
	caps := flags.Bool("capabilities", false, "report supported setup features without opening the database")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return errors.New("invalid apply-setup arguments")
	}
	if *caps {
		if *file != "" || *db != "" || *check || *stage || *exportClient != "" {
			return errors.New("capabilities cannot be combined with setup arguments")
		}
		return json.NewEncoder(out).Encode(map[string]any{"schema": "ky.setup-capabilities/1", "service": "kyidentity", "bundleSchema": "kyidentity.setup/1", "features": []string{"local-accounts", "confidential-oidc-clients", "assigned-only", "everyday-assignment", "app-role-assignments", "scim-connectors", "suite-webhook-connectors", "directory-groups", "app-group-assignments", "scim-groups", "check", "protected-setup-files", "bundle-preparation", "target-credentials", "client-credential-export", "disable-user"}})
	}
	if *exportClient != "" {
		if *stage || *check {
			return errors.New("credential export cannot be combined with preparation or inspection flags")
		}
		return exportSetupClient(*file, *db, *exportClient, out)
	}
	if *stage {
		raw, err := io.ReadAll(io.LimitReader(input, setupBundleLimit+1))
		if err != nil {
			return errors.New("cannot read bounded preparation metadata")
		}
		status, err := stageSetup(*file, *db, raw, *check)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{"schema": "kyidentity.setup-preparation/1", "status": status})
	}
	raw, err := readSetupFile(*file, 128*1024)
	if err != nil {
		return err
	}
	if preparationPath(*file) {
		if _, err := stageSetup(*file, *db, raw, true); err != nil {
			return err
		}
	}
	p, err := prepareSetup(raw)
	if err != nil {
		return err
	}
	*db = setupDatabasePath(*db)
	// Setup is deliberately limited to an initialized product, never an accidental new DB.
	st, err := os.Stat(*db)
	if err != nil || !st.Mode().IsRegular() {
		return errors.New("apply-setup requires an initialized KyIdentity database")
	}
	s, err := store.OpenInstallerStore(*db, *check)
	if err != nil {
		return errors.New("cannot open KyIdentity setup database")
	}
	defer s.Close()
	report, err := s.ApplyInstallerSetup(p, *check)
	if err != nil {
		return fmt.Errorf("setup refused: %w", err)
	}
	return json.NewEncoder(out).Encode(report)
}
