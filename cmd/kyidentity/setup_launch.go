package main

import (
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// setSetupLaunchURL gives one client of an applied prepared setup its launcher link, from
// --launch-url CLIENT=URL. It is outside the bundle, whose staged intent never changes, so
// an installer can add the link to a setup applied before it knew one.
func setSetupLaunchURL(file, db, arg string, out io.Writer) error {
	clientID, launch, _ := strings.Cut(arg, "=")
	if !preparationPath(file) || !setupName.MatchString(clientID) || len(launch) > 2048 || !setupURI(launch) {
		return errors.New("launch URL requires an owned prepared bundle and CLIENT=URL, the URL HTTPS without credentials or fragments")
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
	if !slices.ContainsFunc(b.Clients, func(c setupClient) bool { return c.ID == clientID }) {
		return errors.New("launch URL client is not owned by this prepared setup")
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
		return errors.New("launch URL requires verified applied native ownership")
	}
	event := &store.AuditEvent{ID: uuid.NewString(), ActorUsername: "kyidentity-cli", Action: "admin.client_launcher_updated", TargetType: "client", IPAddress: "container-local", UserAgent: "kyidentity-cli", Outcome: "success", CreatedAt: time.Now().UTC()}
	changed, err := s.SetInstallerLaunchURL(b.ID, clientID, launch, event)
	if err != nil {
		return errors.New("launch URL failed; nothing was changed")
	}
	status := "unchanged"
	if changed {
		status = "set"
	}
	return json.NewEncoder(out).Encode(map[string]string{"schema": "kyidentity.launch-url/1", "client": clientID, "status": status})
}
