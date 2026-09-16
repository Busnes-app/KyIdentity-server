package sync

import (
	"context"
	"errors"
	"github.com/Busnes-app/ky-primitives/scim"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
)

// A transport error, server error, or asynchronous acceptance of a mutation may
// mean the server is still writing. A successful read does not settle that write.
// The tracker belongs to one synchronous delivery, including its cloned SCIM client.
type deliveryTransport struct {
	base      http.RoundTripper
	uncertain atomic.Bool
}

func (t *deliveryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	mutation := req.Method != http.MethodGet && req.Method != http.MethodHead
	if mutation {
		// Preserve the wire idempotency key, but do not let net/http replay a
		// mutation internally after a lost response on a reused connection.
		// The persisted delivery attempt must see that uncertainty first.
		req = req.Clone(req.Context())
		req.GetBody = nil
		if req.Body == nil || req.Body == http.NoBody {
			req.Body = io.NopCloser(http.NoBody)
		}
		t.uncertain.Store(true)
	}
	resp, err := t.base.RoundTrip(req)
	if mutation && err == nil {
		code := resp.StatusCode
		if code == 200 || code == 201 || code == 204 || (code >= 400 && code < 500 && code != 408) {
			t.uncertain.Store(false)
		}
	}
	return resp, err
}

// ReadBackSyncResource reports observation only. It cannot prove a remote write has
// finished and deliberately does not release a delivery fence or create marker. The
// collection follows the attempt's event type, so a group attempt never reads Users.
func (e *Engine) ReadBackSyncResource(ctx context.Context, sys *store.PairedSystem, eventType, resourceID string) (map[string]any, error) {
	if sys.SystemType != "scim" {
		return map[string]any{"state": "unsupported"}, nil
	}
	secret, err := e.SigningSecret(sys)
	if err != nil {
		return nil, err
	}
	collection := "Users"
	if strings.HasPrefix(eventType, "group.") {
		collection = "Groups"
	}
	remoteID, err := e.findSCIMResource(ctx, e.scimClient(sys, secret), collection, resourceID)
	if errors.Is(err, scim.ErrNotFound) {
		return map[string]any{"state": "absent"}, nil
	}
	if err != nil {
		return nil, errors.New("read-back failed; verify endpoint, credentials and externalId filtering")
	}
	return map[string]any{"state": "present", "remoteId": remoteID}, nil
}
