package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// runDisableUser retires one account from inside the container, without a person:
// installers use it for the bootstrap administrator once setup has created the owner's.
func runDisableUser(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("disable-user", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	username := flags.String("username", "", "account to disable")
	guard := flags.String("require-active-admin", "", "another active administrator with no end date that must remain")
	db := flags.String("db", "", "existing database path; default KYIDENTITY_DB_PATH or data/kyidentity.db")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !setupName.MatchString(*username) || !setupName.MatchString(*guard) {
		return errors.New("usage: kyidentity disable-user --username NAME --require-active-admin OTHER")
	}
	path := setupDatabasePath(*db)
	// Never create a database: this acts on an initialized, possibly running, product.
	if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
		return errors.New("disable-user requires an initialized KyIdentity database")
	}
	s, err := store.OpenInstallerStore(path, false)
	if err != nil {
		return errors.New("cannot open KyIdentity database")
	}
	defer s.Close()
	// A durable row only: an audit console copy on stdout would corrupt the JSON result.
	event := &store.AuditEvent{ID: uuid.NewString(), ActorUsername: "kyidentity-cli", Action: "admin.user_updated", TargetType: "user", IPAddress: "container-local", UserAgent: "kyidentity-cli", Outcome: "success", CreatedAt: time.Now().UTC()}
	changed, err := s.DisableUserByName(*username, *guard, event)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return errors.New("disable-user refused: no such account")
	case errors.Is(err, store.ErrGuardAdministrator):
		return errors.New("disable-user refused: --require-active-admin must name another active administrator with no end date")
	case err != nil:
		return errors.New("disable-user failed; nothing was changed")
	}
	status := "unchanged"
	if changed {
		status = "disabled"
	}
	if err := removeFirstRunPassword(*username); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]string{"schema": "kyidentity.disable-user/1", "username": *username, "status": status})
}

// removeFirstRunPassword deletes the generated credentials file only when it names the
// disabled account, so a retired bootstrap password does not stay on disk.
func removeFirstRunPassword(username string) error {
	dir, err := setupDataDirectory()
	if err != nil {
		return nil
	}
	path := filepath.Join(dir, "first-run-password.txt")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("account disabled, but the first-run password file could not be read")
	}
	first, _, _ := strings.Cut(string(raw), "\n")
	if first != "User: "+username {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("account disabled, but the first-run password file could not be removed")
	}
	return nil
}
