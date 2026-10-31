package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// setSetupLauncher sets one launcher setting of a client an applied prepared setup owns,
// from --launch-url, --launcher-name or --launcher-audience CLIENT=VALUE. Settings are
// outside the bundle, whose staged intent never changes, so an installer can add them to a
// setup applied before it knew them. Each is written only while unset.
func setSetupLauncher(file, db, flag, arg string, out io.Writer) error {
	clientID, value, _ := strings.Cut(arg, "=")
	valid := preparationPath(file) && setupName.MatchString(clientID)
	switch flag {
	case "launch-url":
		valid = valid && len(value) <= 2048 && setupURI(value)
	case "launcher-name":
		valid = valid && value != "" && store.ValidLauncherName(value)
	case "launcher-audience":
		valid = valid && (value == store.LauncherEveryone || value == store.LauncherAdmins)
	}
	if !valid {
		return fmt.Errorf("--%s requires an owned prepared bundle and CLIENT=VALUE: an HTTPS URL without credentials or fragments, a card name of at most 128 characters, or everyone|admins", flag)
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
	i := slices.IndexFunc(b.Clients, func(c setupClient) bool { return c.ID == clientID })
	if i < 0 {
		return fmt.Errorf("--%s client is not owned by this prepared setup", flag)
	}
	p, err := prepareSetup(raw)
	if err != nil {
		return err
	}
	s, err := store.OpenInstallerStore(setupDatabasePath(db), false)
	if err != nil {
		return errors.New("cannot open KyIdentity database")
	}
	defer s.Close()
	if _, err := s.ApplyInstallerSetup(p, true); err != nil {
		return fmt.Errorf("--%s requires verified applied native ownership", flag)
	}
	event := &store.AuditEvent{ID: uuid.NewString(), ActorUsername: "kyidentity-cli", Action: "admin.client_launcher_updated", TargetType: "client", IPAddress: "container-local", UserAgent: "kyidentity-cli", Outcome: "success", CreatedAt: time.Now().UTC()}
	var changed bool
	switch flag {
	case "launch-url":
		changed, err = s.SetInstallerLaunchURL(b.ID, clientID, value, event)
	case "launcher-name":
		changed, err = s.SetInstallerLauncherName(b.ID, clientID, value, event)
	default:
		adminRole := ""
		if value == store.LauncherAdmins {
			adminRole = b.Clients[i].AdministratorRole
		}
		changed, err = s.SetInstallerLauncherAudience(b.ID, clientID, value, adminRole, event)
	}
	if err != nil {
		return fmt.Errorf("--%s failed; nothing was changed", flag)
	}
	status := "unchanged"
	if changed {
		status = "set"
	}
	return json.NewEncoder(out).Encode(map[string]string{"schema": "kyidentity." + flag + "/1", "client": clientID, "status": status})
}
