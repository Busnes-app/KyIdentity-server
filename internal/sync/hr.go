package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/netguard"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// ConfigureHR uses the existing source connector/token management and the
// paired KyPost credential. Only the writeback credential is additional.
func (e *Engine) ConfigureHR(c store.HRConnection, token string, audit *store.AuditEvent) error {
	if err := netguard.ValidateURL(c.WritebackURL, "writebackUrl"); err != nil {
		return err
	}
	u, _ := url.Parse(c.WritebackURL)
	if u.Scheme != "https" || u.RawQuery != "" {
		return errors.New("writebackUrl must be HTTPS without a query")
	}
	if c.Domain != strings.ToLower(c.Domain) || len(c.Domain) > 253 || !strings.Contains(c.Domain, ".") {
		return errors.New("domain must be a lowercase DNS name")
	}
	for _, part := range strings.Split(c.Domain, ".") {
		if part == "" || len(part) > 63 || strings.Trim(part, "-") != part {
			return errors.New("invalid domain")
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return errors.New("invalid domain")
			}
		}
	}
	if token == "" || len(token) > 4096 || strings.ContainsAny(token, "\r\n") {
		return errors.New("writebackToken is required")
	}
	var err error
	c.WritebackSecret, err = crypto.Seal(e.encryptionKey, store.SealHRWriteback, c.ConnectorID, []byte(token))
	if err != nil {
		return err
	}
	return e.store.ConfigureHR(c, audit)
}

// hrRequest never returns response text or transport errors to logs/status:
// HR servers may put credentials and personal information in either.
func (e *Engine) hrRequest(ctx context.Context, method, target string, body []byte, authorize func(*http.Request)) ([]byte, error) {
	if err := netguard.ValidateURL(target, "HR endpoint"); err != nil {
		return nil, errors.New("endpoint_invalid")
	}
	u, _ := url.Parse(target)
	if u.Scheme != "https" {
		return nil, errors.New("endpoint_requires_https")
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("request_invalid")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	authorize(req)
	req.GetBody = nil // never transparently replay a mutation
	client := *e.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return netguard.ErrRedirect }
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.New("endpoint_unavailable")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4097))
	if err != nil || len(raw) > 4096 {
		return nil, errors.New("response_invalid")
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusNoContent {
		return nil, errors.New("endpoint_refused")
	}
	return raw, nil
}

func (e *Engine) runHRJob(ctx context.Context, w *store.HRWorker) (string, error) {
	c, err := e.store.HRConnection(w.ConnectorID)
	if err != nil || c.Held {
		return "", errors.New("connection_unavailable")
	}
	if w.State == "mailbox_pending" {
		sys, err := e.store.GetPairedSystemByID(c.SystemID)
		if err != nil || sys == nil || sys.SystemType != "kypost" || sys.Status == "disabled" || sys.ProvisioningHold {
			return "", errors.New("kypost_unavailable")
		}
		secret, err := e.SigningSecret(sys)
		if err != nil {
			return "", errors.New("credential_unavailable")
		}
		endpoint, err := url.Parse(sys.CallbackURL)
		if err != nil || endpoint.Path != "/api/sync/webhook" || endpoint.RawQuery != "" {
			return "", errors.New("kypost_callback_invalid")
		}
		endpoint.Path = "/api/sync/hr-mailbox"
		body, _ := json.Marshal(map[string]string{"userId": w.ID, "preferredName": w.PreferredName, "domain": c.Domain})
		headers, err := syncauth.Sign([]byte(secret), time.Now().UTC(), "hr.mailbox.reserve", w.ID, body)
		if err != nil {
			return "", errors.New("credential_invalid")
		}
		raw, err := e.hrRequest(ctx, http.MethodPost, endpoint.String(), body, func(r *http.Request) { headers.Apply(r); r.Header.Set("Idempotency-Key", w.ID) })
		if err != nil {
			return "", err
		}
		var result struct {
			UserID string `json:"userId"`
			Email  string `json:"email"`
		}
		if json.Unmarshal(raw, &result) != nil || result.UserID != w.ID || result.Email != strings.ToLower(result.Email) {
			return "", errors.New("mailbox_response_invalid")
		}
		a, err := mail.ParseAddress(result.Email)
		local, domain, ok := strings.Cut(result.Email, "@")
		if err != nil || a.Address != result.Email || !ok || local == "" || domain != c.Domain || len(result.Email) > 254 {
			return "", errors.New("mailbox_response_invalid")
		}
		return result.Email, nil
	}
	token, err := crypto.Open(e.encryptionKey, store.SealHRWriteback, c.ConnectorID, c.WritebackSecret)
	if err != nil {
		return "", errors.New("credential_unavailable")
	}
	body, _ := json.Marshal(map[string]any{"sourceUid": w.SourceUID, "sourceVersion": w.SourceVersion, "userId": w.ID, "email": w.Email})
	_, err = e.hrRequest(ctx, http.MethodPut, c.WritebackURL, body, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+string(token))
		r.Header.Set("Idempotency-Key", w.ID+":"+strconv.FormatInt(w.SourceVersion, 10))
	})
	return w.Email, err
}

// DispatchHR processes at most one job per tick, independently from directory
// delivery. The stored lease and idempotent destination contracts survive restarts.
func (e *Engine) DispatchHR(ctx context.Context) error {
	w, err := e.store.ClaimHR()
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	email, err := e.runHRJob(ctx, w)
	safeError := ""
	if err != nil {
		safeError = err.Error()
	}
	if err = e.store.FinishHR(w, email, safeError); err != nil {
		// Local uniqueness or deleted-user conflicts remain visible and retryable.
		if saveErr := e.store.FinishHR(w, "", "identity_update_refused"); saveErr != nil {
			return saveErr
		}
	}
	return nil
}

func (e *Engine) hrWorker(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.DispatchHR(ctx); err != nil && ctx.Err() == nil {
				log.Printf("HR provisioning persistence failed")
			}
		}
	}
}
