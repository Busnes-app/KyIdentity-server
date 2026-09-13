package oauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Busness-app/kysignon-server/internal/netguard"
	"github.com/google/uuid"
)

// LogoutTokenTTL bounds how long a logout token is accepted by receivers. Each attempt
// mints a fresh one, so a short life costs nothing.
const LogoutTokenTTL = 2 * time.Minute

const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// SignLogoutToken mints an OpenID Connect Back-Channel Logout token for one client and
// one login. The `logout+jwt` type, the events claim and the absence of both `nonce` and
// `token_use` keep it from ever passing as an ID or access token here or downstream.
func (e *Engine) SignLogoutToken(clientID, subject, sid string) (string, error) {
	now := time.Now().UTC()
	return e.keyManager.SignJWTWithType("logout+jwt", map[string]any{
		"iss":    e.issuerURL,
		"sub":    subject,
		"aud":    clientID,
		"iat":    now.Unix(),
		"exp":    now.Add(LogoutTokenTTL).Unix(),
		"jti":    uuid.NewString(),
		"sid":    sid,
		"events": map[string]any{backchannelLogoutEvent: map[string]any{}},
	})
}

// deliveryLease bounds one attempt. The HTTP timeout is shorter, so a lapsed lease means
// the worker died, not that the receiver is slow.
const deliveryLease = 60 * time.Second

// DeliverPendingLogout performs one queued back-channel logout and records the outcome.
// It reports whether there was anything to do.
func (e *Engine) DeliverPendingLogout(ctx context.Context) (bool, error) {
	d, err := e.store.ClaimLogoutDelivery(deliveryLease)
	if err != nil || d == nil {
		return false, err
	}
	attemptErr := e.postLogout(ctx, d.BackchannelLogoutURI, d.ClientID, d.UserID, d.SID)
	if err := e.store.FinishLogoutDelivery(d, attemptErr); err != nil {
		return true, err
	}
	return true, nil
}

func (e *Engine) postLogout(ctx context.Context, target, clientID, subject, sid string) error {
	if err := netguard.ValidateURL(target, "backchannel_logout_uri"); err != nil {
		return err
	}
	token, err := e.SignLogoutToken(clientID, subject, sid)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cache-Control", "no-store")
	resp, err := netguard.Client(10 * time.Second).Do(req)
	if err != nil {
		return fmt.Errorf("delivery failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return errors.New("receiver answered " + resp.Status)
}

// StartLogoutWorker delivers queued logouts until ctx ends.
func (e *Engine) StartLogoutWorker(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				did, err := e.DeliverPendingLogout(ctx)
				if err != nil {
					log.Printf("back-channel logout: %v", err)
				}
				if !did || ctx.Err() != nil {
					break
				}
			}
		}
	}
}
