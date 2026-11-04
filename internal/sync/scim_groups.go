package sync

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	stdsync "sync"
	"time"

	"github.com/Busnes-app/ky-primitives/scim"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

const scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"

// The shared primitive is Users-only. Group writes are a full PUT of the membership the
// directory holds right now, keyed by the group's local ID as externalId, so retries and
// stale queued events converge on the same remote state.
type scimGroup struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id,omitempty"`
	ExternalID  string            `json:"externalId,omitempty"`
	DisplayName string            `json:"displayName"`
	Members     []scim.MultiValue `json:"members"`
}

func (e *Engine) deliverSCIMGroup(parent context.Context, sys *store.PairedSystem, secret, eventType, groupID string) error {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	if groupID == "" {
		return errors.New("missing local group ID")
	}
	c := e.scimClient(sys, secret)
	if err := validateSCIMConfig(c.BaseURL, secret); err != nil {
		return err
	}
	remoteID, started, err := e.store.SCIMLink(sys.ID, "group", groupID)
	if err != nil {
		return err
	}
	verifyMapping := remoteID != ""
	var current scimGroup
	if remoteID == "" {
		found, lookupErr := e.findSCIMResource(ctx, c, "Groups", groupID)
		switch {
		case lookupErr == nil:
			remoteID = found
			if err = e.store.SaveSCIMLink(sys.ID, "group", groupID, remoteID); err != nil {
				return err
			}
		case !errors.Is(lookupErr, scim.ErrNotFound):
			return lookupErr
		case started:
			return errCreateUncertain
		}
	}
	base, _ := url.Parse(c.BaseURL)
	// A stored mapping may outlive a target restore or ID reuse; IDs established by this
	// call's externalId lookup have already been checked.
	if verifyMapping {
		status, raw, err := e.scimRequest(ctx, c, http.MethodGet, base.JoinPath("Groups", url.PathEscape(remoteID)).String(), nil)
		if errors.Is(err, scim.ErrNotFound) && eventType == "group.deleted" {
			return e.store.DeleteSCIMLink(sys.ID, "group", groupID)
		}
		if err != nil {
			return err
		}
		if status != http.StatusOK || json.Unmarshal(raw, &current) != nil || current.ID != remoteID || current.ExternalID != groupID {
			return scim.ErrMalformedResponse
		}
	}
	switch eventType {
	case "group.deleted":
		if remoteID == "" {
			return nil
		}
		status, _, err := e.scimRequest(ctx, c, http.MethodDelete, base.JoinPath("Groups", url.PathEscape(remoteID)).String(), nil)
		if err != nil && !errors.Is(err, scim.ErrNotFound) {
			return err
		}
		if err == nil && status != http.StatusOK && status != http.StatusNoContent {
			return scim.ErrMalformedResponse
		}
		return e.store.DeleteSCIMLink(sys.ID, "group", groupID)
	case "group.updated":
	default:
		return errors.New("unsupported group event")
	}
	name, exists, members, err := e.store.SCIMGroupMembers(sys.ID, groupID)
	if err != nil {
		return err
	}
	if !exists {
		// Deleted locally; the queued group.deleted follows this event.
		return nil
	}
	desired := scimGroup{Schemas: []string{scimGroupSchema}, ExternalID: groupID, DisplayName: name, Members: []scim.MultiValue{}}
	held := map[string]bool{}
	for _, m := range current.Members {
		held[m.Value] = true
	}
	var added []store.SCIMMember
	for _, m := range members {
		if !held[m.RemoteID] {
			added = append(added, m)
		}
	}
	owned, err := e.ownedMembers(parent, c, added)
	if err != nil {
		return err
	}
	for _, m := range members {
		if held[m.RemoteID] || owned[m.RemoteID] {
			desired.Members = append(desired.Members, scim.MultiValue{Value: m.RemoteID})
		}
	}
	// The write gets its own budget, whatever the checks took.
	ctx, cancelWrite := context.WithTimeout(parent, 20*time.Second)
	defer cancelWrite()
	body, err := json.Marshal(desired)
	if err != nil {
		return err
	}
	if remoteID == "" {
		won, err := e.store.StartSCIMCreate(sys.ID, "group", groupID)
		if err != nil {
			return err
		}
		if !won {
			return errCreateUncertain
		}
		status, raw, err := e.scimRequest(ctx, c, http.MethodPost, base.JoinPath("Groups").String(), body)
		if err != nil {
			if e.createRefused(err) {
				if clearErr := e.store.RejectSCIMCreate(sys.ID, "group", groupID); clearErr != nil {
					return clearErr
				}
			}
			return err
		}
		var created scimGroup
		if status != http.StatusCreated && status != http.StatusOK || json.Unmarshal(raw, &created) != nil || created.ID == "" || created.ID == "." || created.ID == ".." || (created.ExternalID != "" && created.ExternalID != groupID) {
			return scim.ErrMalformedResponse
		}
		return e.store.SaveSCIMLink(sys.ID, "group", groupID, created.ID)
	}
	// Only a completion status proves the member list was applied; 202 stays blocked.
	status, _, err := e.scimRequest(ctx, c, http.MethodPut, base.JoinPath("Groups", url.PathEscape(remoteID)).String(), body)
	if err == nil && status != http.StatusOK && status != http.StatusNoContent {
		return scim.ErrMalformedResponse
	}
	return err
}

// ownedMembers reads back each member a group write would add and returns the remote IDs
// that still carry their local ID as externalId. A stored user mapping may outlive a target
// wipe that handed its ID to someone else, so a member is never granted the group in another
// person's place. A member whose ID is gone or reassigned is left out of the write (it
// rejoins once its own delivery or a repair fixes the mapping), so it never blocks the rest
// of the group, removals included. Eight reads run at once, with time for each, so a large
// first delivery still completes; any other error fails the write for a retry.
func (e *Engine) ownedMembers(parent context.Context, c *scim.Client, added []store.SCIMMember) (map[string]bool, error) {
	owned := map[string]bool{}
	if len(added) == 0 {
		return owned, nil
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second+time.Duration(len(added))*time.Second/2)
	defer cancel()
	var mu stdsync.Mutex
	var firstErr error
	slots := make(chan struct{}, 8)
	var wg stdsync.WaitGroup
	for _, m := range added {
		slots <- struct{}{}
		wg.Go(func() {
			defer func() { <-slots }()
			u, err := c.GetUser(ctx, m.RemoteID)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && u.ID == m.RemoteID && u.ExternalID == m.LocalID:
				owned[m.RemoteID] = true
			case err == nil || errors.Is(err, scim.ErrNotFound):
				log.Printf("[SYNC] group member %s left out: remote user %s is gone or belongs to someone else; repair the connector", m.LocalID, m.RemoteID)
			case firstErr == nil:
				firstErr = err
			}
		})
	}
	wg.Wait()
	return owned, firstErr
}
