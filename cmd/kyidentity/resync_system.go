package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// resyncPoll is how often --wait reads the outbox; tests shorten it.
var resyncPoll = time.Second

type resyncResult struct {
	Schema   string `json:"schema"`
	ClientID string `json:"clientId"`
	SystemID string `json:"systemId"`
	// queued (no --wait), delivered, failed, blocked or timeout.
	Status  string `json:"status"`
	Pending int    `json:"pending"`
	Failed  int    `json:"failed"`
	Blocked string `json:"blocked,omitempty"`
}

// runResyncSystem re-sends a connector's whole desired state, removals included, from
// inside the container: installers run it after a downstream app restores a backup.
// The running server's worker delivers; --wait watches the outbox drain.
func runResyncSystem(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("resync-system", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	client := flags.String("client", "", "OAuth client ID whose app owns the connector")
	wait := flags.Duration("wait", 0, "wait up to this long for delivery; 0 returns once queued")
	db := flags.String("db", "", "existing database path; default KYIDENTITY_DB_PATH or data/kyidentity.db")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !setupName.MatchString(*client) || *wait < 0 || *wait > 24*time.Hour {
		return errors.New("usage: kyidentity resync-system --client CLIENT_ID [--wait DURATION (max 24h)]")
	}
	path := setupDatabasePath(*db)
	// Never create a database: this acts on an initialized, possibly running, product.
	if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
		return errors.New("resync-system requires an initialized KyIdentity database")
	}
	s, err := store.OpenInstallerStore(path, false)
	if err != nil {
		return errors.New("cannot open KyIdentity database")
	}
	defer s.Close()
	systemID, err := s.SystemForClient(*client)
	if errors.Is(err, store.ErrNotFound) {
		return errors.New("resync-system refused: no connector shares an app with that client")
	}
	if err != nil {
		return errors.New("resync-system failed; nothing was queued")
	}
	details, _ := json.Marshal(map[string]string{"clientId": *client, "via": "cli"})
	// A durable row only: an audit console copy on stdout would corrupt the JSON result.
	event := &store.AuditEvent{ID: uuid.NewString(), ActorUsername: "kyidentity-cli", Action: "admin.system_resynced", TargetID: systemID, TargetType: "system", IPAddress: "container-local", UserAgent: "kyidentity-cli", Outcome: "success", DetailsJSON: string(details), CreatedAt: time.Now().UTC()}
	if err := s.ResyncSystem(systemID, event); err != nil {
		return errors.New("resync-system failed; nothing was queued")
	}
	r := resyncResult{Schema: "kyidentity.resync-system/1", ClientID: *client, SystemID: systemID, Status: "queued"}
	deadline := time.Now().Add(*wait)
	for {
		b, err := s.SyncBacklog(systemID)
		if err != nil {
			return errors.New("resync queued, but its delivery could not be read")
		}
		r.Pending, r.Failed, r.Blocked = b.Pending, b.Failed, b.Blocked
		switch {
		case *wait == 0:
		case b.Failed > 0:
			r.Status = "failed"
		case b.Blocked != "":
			r.Status = "blocked"
		case b.Pending == 0:
			r.Status = "delivered"
		case time.Now().After(deadline):
			r.Status = "timeout"
		default:
			time.Sleep(resyncPoll)
			continue
		}
		break
	}
	if err := json.NewEncoder(out).Encode(r); err != nil {
		return err
	}
	if r.Status != "queued" && r.Status != "delivered" {
		return errors.New("resync-system: " + r.Status)
	}
	return nil
}
