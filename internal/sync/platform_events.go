package sync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// Events back to billing (tenancy design): platform_events are POSTed to
// KYIDENTITY_PLATFORM_EVENTS_URL, signed with syncauth under the sealed secret, at least
// once and unordered. The URL is the operator's, not a caller's, so it may be private.

// SetPlatformEventsURL turns on delivery (multi-tenant only). Call it before the worker.
func (e *Engine) SetPlatformEventsURL(u string) {
	e.platformEventsURL = u
	e.platformClient = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

const platformEventLease = time.Minute

// DeliverPlatformEvents sends every due event once, until none is left or ctx ends. With no
// secret set yet nothing is claimed: the events wait.
func (e *Engine) DeliverPlatformEvents(ctx context.Context) error {
	secret, err := e.store.PlatformEventsSecret(e.encryptionKey)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	for ctx.Err() == nil {
		ev, err := e.store.Platform().ClaimPlatformEvent(platformEventLease)
		if err != nil || ev == nil {
			return err
		}
		sendErr := e.postPlatformEvent(ctx, secret, ev)
		if sendErr != nil {
			log.Printf("platform event %s (%s): delivery failed: %v", ev.ID, ev.Type, sendErr)
		}
		if err := e.store.Platform().FinishPlatformEvent(ev, sendErr); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) postPlatformEvent(ctx context.Context, secret []byte, ev *store.PlatformEvent) error {
	body := []byte(ev.Payload)
	signed, err := syncauth.Sign(secret, time.Now().UTC(), ev.Type, ev.ID, body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.platformEventsURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	signed.Apply(req)
	resp, err := e.platformClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("billing answered %d", resp.StatusCode)
	}
	return nil
}

// platformEventsWorker delivers events every few seconds, each pass bounded.
func (e *Engine) platformEventsWorker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pass, cancel := context.WithTimeout(ctx, time.Minute)
			if err := e.DeliverPlatformEvents(pass); err != nil && ctx.Err() == nil {
				log.Printf("platform events: %v", err)
			}
			cancel()
		}
	}
}
