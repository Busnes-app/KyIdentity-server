package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

const platformTokenUsage = `usage:
  kyidentity platform-token create --name NAME --scopes SCOPE[,SCOPE] [--days N]
  kyidentity platform-token revoke --id ID
  kyidentity platform-token list
Scopes: orgs:read, orgs:write, orgs:delete (billing) or members:read, members:write (portal), never both kinds.
The token is printed once.
`

// runPlatformToken manages platform provisioning API tokens on a multi-tenant install.
// Each action writes a platform audit row; the token itself is printed once, never logged.
func runPlatformToken(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(platformTokenUsage)
	}
	fs := flag.NewFlagSet("platform-token "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	name := fs.String("name", "", "")
	scopes := fs.String("scopes", "", "")
	days := fs.Int("days", 365, "")
	id := fs.String("id", "", "")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return errors.New(platformTokenUsage)
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	return platformToken(cfg, args[0], *name, *scopes, *days, *id, out)
}

func platformToken(cfg *config.Config, action, name, scopes string, days int, id string, out io.Writer) error {
	if cfg.Tenancy != "multi" {
		return errors.New("platform-token needs KYIDENTITY_TENANCY=multi")
	}
	s, err := openStore(cfg)
	if err != nil {
		return fmt.Errorf("failed to open the database: %w", err)
	}
	defer s.Close()
	audit := &store.AuditEvent{ID: uuid.NewString(), ActorUsername: "kyidentity-cli", IPAddress: "container-local", UserAgent: "kyidentity-cli", Outcome: "success", CreatedAt: time.Now().UTC()}
	enc := json.NewEncoder(out)
	switch action {
	case "create":
		if days < 1 || time.Duration(days)*24*time.Hour > store.MaxPlatformTokenTTL {
			return errors.New("--days must be 1 to 730")
		}
		raw, t, err := s.Platform().CreatePlatformToken(name, strings.Split(scopes, ","), time.Duration(days)*24*time.Hour, audit)
		if err != nil {
			return err
		}
		return enc.Encode(map[string]any{"id": t.ID, "name": t.Name, "scopes": t.Scopes, "expiresAt": t.ExpiresAt, "token": raw})
	case "revoke":
		if err := s.Platform().RevokePlatformToken(id, audit); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return errors.New("no live token with that id")
			}
			return err
		}
		return enc.Encode(map[string]string{"id": id, "status": "revoked"})
	case "list":
		tokens, err := s.Platform().ListPlatformTokens()
		if err != nil {
			return err
		}
		audit.Action = "platform.token_listed"
		if err := s.Platform().RecordPlatformAudit("", audit); err != nil {
			return err
		}
		if tokens == nil {
			tokens = []store.PlatformToken{}
		}
		return enc.Encode(tokens)
	}
	return errors.New(platformTokenUsage)
}
