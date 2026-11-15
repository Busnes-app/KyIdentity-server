package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

type bypassFlags []string

func (b *bypassFlags) String() string     { return strings.Join(*b, ",") }
func (b *bypassFlags) Set(v string) error { *b = append(*b, v); return nil }

// runProxyApp is the installer's container-local channel for a forward-auth proxy app
// (docs/FORWARD-AUTH.md). It never creates a second app or secret for a host: the edge
// secret is printed only when the app is created or --rotate-secret replaces it.
func runProxyApp(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("proxy-app", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	owner := flags.String("owner", "", "installer identity that owns the app (installation ID)")
	host := flags.String("host", "", "exact host the edge protects")
	name := flags.String("name", "", "launcher card name, used when the app is created")
	header := flags.String("login-header", "X-Ky-User", "header the app reads the user name from")
	hours := flags.Float64("session-hours", 12, "forward session length in hours")
	rotate := flags.Bool("rotate-secret", false, "replace the edge secret and print the new one")
	db := flags.String("db", "", "existing database path; default KYIDENTITY_DB_PATH or data/kyidentity.db")
	var bypass bypassFlags
	flags.Var(&bypass, "bypass", "path prefix the edge does not check (repeatable)")
	usage := errors.New("usage: kyidentity proxy-app --owner ID --host HOST --name NAME [--login-header H] [--bypass /p]... [--session-hours N] [--rotate-secret]")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !setupName.MatchString(*owner) || *name == "" || len(*name) > 100 {
		return usage
	}
	seconds := int64(*hours * 3600)
	switch {
	case !store.ValidProxyHost(*host):
		return errors.New("proxy-app refused: --host must be an exact lowercase host name")
	case !store.ValidLoginHeader(*header):
		return errors.New("proxy-app refused: --login-header is not an allowed header name")
	case seconds < store.MinForwardSession || seconds > store.MaxForwardSession:
		return errors.New("proxy-app refused: --session-hours must be between 5 minutes and 7 days")
	case len(bypass) > 20:
		return errors.New("proxy-app refused: at most 20 --bypass paths")
	}
	for _, p := range bypass {
		if !store.ValidBypassPrefix(p) {
			return errors.New("proxy-app refused: a --bypass path is not a plain absolute path prefix")
		}
	}
	if bypass == nil {
		bypass = bypassFlags{}
	}
	path := setupDatabasePath(*db)
	if sqliteFileMissing(path) {
		return errors.New("proxy-app requires an initialized KyIdentity database")
	}
	s, err := store.OpenInstallerStore(path, false)
	if err != nil {
		return errors.New("cannot open KyIdentity database")
	}
	defer s.Close()
	secret, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return err
	}
	// A durable row only: an audit console copy on stdout would corrupt the JSON result.
	event := &store.AuditEvent{ID: uuid.NewString(), ActorUsername: "kyidentity-cli", Action: "admin.proxy_app_ensured", TargetType: "application", IPAddress: "container-local", UserAgent: "kyidentity-cli", Outcome: "success", CreatedAt: time.Now().UTC()}
	p := &store.ProxyApp{Host: *host, LoginHeader: *header, Bypass: bypass, SessionSeconds: seconds}
	status, id, issued, err := s.EnsureInstallerProxyApp(*owner, *name, p, crypto.HashSHA256(secret), *rotate, event)
	switch {
	case errors.Is(err, store.ErrProxyAppForeign):
		return errors.New("proxy-app refused: a proxy app for this host exists and this owner did not create it")
	case errors.Is(err, store.ErrProxyHostUsed):
		return errors.New("proxy-app refused: the host is in use")
	case err != nil:
		return errors.New("proxy-app failed; nothing was changed")
	}
	result := map[string]string{"schema": "kyidentity.proxy-app/1", "host": *host, "id": id, "status": status}
	if issued {
		result["edgeSecret"] = secret
	}
	return json.NewEncoder(out).Encode(result)
}
