package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/Busness-app/ky-primitives/scim"
	"github.com/Busness-app/kysignon-server/internal/store"
)

const (
	reconcileLease = 10 * time.Minute
	listingPage    = 100
	listingMax     = 20000
	// A listing gets a wall-clock budget and a page budget of its own, so a slow target
	// makes a run incomplete rather than holding the worker for the whole lease.
	listingBudget = 2 * time.Minute
	listingPages  = listingMax/listingPage + 10
)

type listedResource struct {
	ID          string            `json:"id"`
	ExternalID  string            `json:"externalId"`
	UserName    string            `json:"userName"`
	DisplayName string            `json:"displayName"`
	Emails      []scim.MultiValue `json:"emails"`
	Active      *bool             `json:"active"`
}

// listSCIMCollection reads a whole collection page by page. Any page that fails, a total
// that changes underneath the walk, a short page, or a duplicate or overlong ID makes
// the listing incomplete; the caller then records what it saw and infers nothing destructive.
func (e *Engine) listSCIMCollection(ctx context.Context, c *scim.Client, collection string) ([]listedResource, error) {
	if err := validateSCIMConfig(c.BaseURL, c.Token); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, listingBudget)
	defer cancel()
	base, _ := url.Parse(c.BaseURL)
	var out []listedResource
	seen := map[string]bool{}
	start, total := 1, -1
	for pages := 0; ; pages++ {
		if pages >= listingPages {
			return out, fmt.Errorf("%w: page budget exhausted", scim.ErrMalformedResponse)
		}
		u := base.JoinPath(collection)
		u.RawQuery = url.Values{"startIndex": {strconv.Itoa(start)}, "count": {strconv.Itoa(listingPage)}}.Encode()
		status, raw, err := e.scimRequest(ctx, c, http.MethodGet, u.String(), nil)
		if err != nil {
			return out, err
		}
		if status != http.StatusOK {
			return out, scim.ErrMalformedResponse
		}
		var page struct {
			Total     *int             `json:"totalResults"`
			Start     *int             `json:"startIndex"`
			Resources []listedResource `json:"Resources"`
		}
		if json.Unmarshal(raw, &page) != nil || page.Total == nil || *page.Total < 0 || (page.Start != nil && *page.Start != start) {
			return out, scim.ErrMalformedResponse
		}
		if total == -1 {
			total = *page.Total
		} else if *page.Total != total {
			return out, fmt.Errorf("%w: collection changed during listing", scim.ErrMalformedResponse)
		}
		if total > listingMax {
			return out, fmt.Errorf("%w: collection exceeds %d resources", scim.ErrMalformedResponse, listingMax)
		}
		for _, r := range page.Resources {
			if r.ID == "" || seen[r.ID] || utf8.RuneCountInString(r.ID) > store.RemoteTextLimit || utf8.RuneCountInString(r.ExternalID) > store.RemoteTextLimit {
				return out, scim.ErrMalformedResponse
			}
			seen[r.ID] = true
			out = append(out, r)
		}
		if len(out) >= total {
			break
		}
		if len(page.Resources) == 0 {
			return out, fmt.Errorf("%w: short listing", scim.ErrMalformedResponse)
		}
		start += len(page.Resources)
	}
	if len(out) != total {
		return out, scim.ErrMalformedResponse
	}
	return out, nil
}

// listRemote reads what a generic SCIM target holds. Suite webhooks have no read
// contract, so their listing is reported as unsupported rather than empty.
func (e *Engine) listRemote(ctx context.Context, sys *store.PairedSystem) (store.RemoteListing, error) {
	listing := store.RemoteListing{}
	if sys.SystemType != "scim" {
		return listing, nil
	}
	secret, err := e.SigningSecret(sys)
	if err != nil {
		return listing, err
	}
	listing.Supported = true
	c := e.scimClient(sys, secret)
	users, err := e.listSCIMCollection(ctx, c, "Users")
	for _, r := range users {
		account := store.RemoteAccount{ID: r.ID, ExternalID: r.ExternalID, UserName: r.UserName, DisplayName: r.DisplayName, Active: r.Active == nil || *r.Active}
		for _, m := range r.Emails {
			if m.Primary || account.Email == "" {
				account.Email = m.Value
			}
		}
		listing.Users = append(listing.Users, account.Bounded())
	}
	if err != nil {
		return listing, err
	}
	listing.Complete = true
	if sys.GroupsEnabled {
		groups, err := e.listSCIMCollection(ctx, c, "Groups")
		for _, r := range groups {
			listing.Groups = append(listing.Groups, store.RemoteGroup{ID: r.ID, ExternalID: r.ExternalID, DisplayName: r.DisplayName}.Bounded())
		}
		if err != nil {
			listing.Complete = false
			return listing, err
		}
		listing.GroupsListed = true
	}
	return listing, nil
}

// RunReconcileJob claims one queued job, lists the target and applies the comparison.
// It reports whether a job ran. A listing failure is a result, not a job failure: the
// report says what was seen and that nothing destructive was inferred.
func (e *Engine) RunReconcileJob(ctx context.Context) (bool, error) {
	job, err := e.store.ClaimReconcileJob(reconcileLease)
	if err != nil || job == nil {
		return false, err
	}
	sys, err := e.store.GetPairedSystemByID(job.SystemID)
	if err != nil {
		return true, e.store.FinishReconcileJob(job, nil, err)
	}
	if sys == nil {
		return true, e.store.FinishReconcileJob(job, nil, errors.New("paired system no longer exists"))
	}
	ctx, cancel := context.WithTimeout(ctx, reconcileLease/2)
	defer cancel()
	listing, listErr := e.listRemote(ctx, sys)
	report, err := e.store.ReconcileDrift(sys.ID, listing, job.Kind == "repair")
	if err != nil {
		return true, e.store.FinishReconcileJob(job, nil, err)
	}
	if listErr != nil {
		report.ListingError = deliveryError(listErr)
	}
	return true, e.store.FinishReconcileJob(job, report, nil)
}

func (e *Engine) runReconcileJobs(ctx context.Context) {
	for i := 0; i < 4; i++ {
		ran, err := e.RunReconcileJob(ctx)
		if err != nil && ctx.Err() == nil {
			log.Printf("reconciliation job failed: %v", err)
		}
		if !ran {
			return
		}
	}
}

// reconcileWorker runs listings on their own goroutine so a slow or hostile target can
// never delay outbound delivery, in particular deprovisioning, to any connector.
func (e *Engine) reconcileWorker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.runReconcileJobs(ctx)
		}
	}
}
