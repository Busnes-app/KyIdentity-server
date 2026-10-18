package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// This private wire frame is consumed in memory by the installer, never rendered
// as an ordinary setup report or written to workstation state.
type clientCredentials struct {
	Schema          string   `json:"schema"`
	SetupID         string   `json:"setupId"`
	IssuerURL       string   `json:"issuerUrl"`
	ClientID        string   `json:"clientId"`
	RedirectURIs    []string `json:"redirectUris"`
	DirectoryURL    string   `json:"directoryUrl,omitempty"`
	ClientSecret    string   `json:"clientSecret"`
	DirectorySecret string   `json:"directorySecret,omitempty"`
	Administrator   struct {
		Subject  string `json:"subject"`
		Username string `json:"username"`
		Role     string `json:"role"`
	} `json:"administrator"`
}

func exportSetupClient(file, db, clientID string, out io.Writer) error {
	if !preparationPath(file) || !setupName.MatchString(clientID) {
		return errors.New("credential export requires an owned prepared bundle and exact client identifier")
	}
	issuer := strings.TrimRight(os.Getenv("KYIDENTITY_ISSUER_URL"), "/")
	u, err := url.Parse(issuer)
	if err != nil || !setupURI(issuer) || u.RawQuery != "" || u.ForceQuery || strings.Contains(issuer, "#") || len(issuer) > 2048 {
		return errors.New("credential export requires the product's configured HTTPS issuer")
	}
	raw, err := readSetupFile(file, setupBundleLimit)
	if err != nil {
		return err
	}
	if _, err := stageSetup(file, db, raw, true); err != nil {
		return err
	}
	b, _, err := setupMetadata(raw)
	if err != nil {
		return err
	}
	selected := -1
	for i, c := range b.Clients {
		if c.ID == clientID {
			selected = i
		}
	}
	if selected < 0 {
		return errors.New("credential export client is not owned by this prepared setup")
	}
	p, err := prepareSetup(raw)
	if err != nil {
		return err
	}
	s, err := store.OpenInstallerStore(setupDatabasePath(db), true)
	if err != nil {
		return errors.New("cannot inspect credential export ownership")
	}
	defer s.Close()
	if _, err := s.ApplyInstallerSetup(p, true); err != nil {
		return errors.New("credential export requires verified applied native ownership")
	}
	// By owned ID, never by username: a rename after inspection must not hand the
	// installer another account as this client's administrator. An amendment's
	// administrator is its parent's; the method itself checks the owned username.
	owner := b.ID
	if b.Extends != "" {
		owner = b.Extends
	}
	admin, err := s.InstallerSetupAdministrator(owner)
	if err != nil || b.Extends == "" && !strings.EqualFold(admin.Username, b.Admin.Username) {
		return errors.New("credential export owner no longer matches setup ownership")
	}
	c := b.Clients[selected]
	secret, err := readSetupFile(c.SecretFile, 43)
	if err != nil {
		return err
	}
	frame := clientCredentials{Schema: "kyidentity.client-credentials/1", SetupID: b.ID, IssuerURL: issuer, ClientID: c.ID, RedirectURIs: c.RedirectURIs, ClientSecret: string(secret)}
	frame.Administrator.Subject, frame.Administrator.Username, frame.Administrator.Role = admin.ID, admin.Username, c.AdministratorRole
	if c.SuiteWebhook != nil {
		secret, err := readSetupFile(c.SuiteWebhook.SigningSecretFile, 43)
		if err != nil {
			return err
		}
		frame.DirectoryURL, frame.DirectorySecret = c.SuiteWebhook.URL, string(secret)
	}
	payload, err := json.Marshal(frame)
	if err != nil || len(payload) > 64<<10 {
		return errors.New("credential export exceeds private wire limit")
	}
	_, err = out.Write(payload)
	return err
}
