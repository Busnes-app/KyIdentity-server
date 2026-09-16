package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/netguard"
	"github.com/Busness-app/kyidentity-server/internal/store"
)

func jwtHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestLogoutTokenShapeAndSeparationFromLoginTokens(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	u := testUser(t, db)
	testClient(t, db, "app", "public", []string{"https://app/cb"}, []string{"openid"})

	token, err := e.SignLogoutToken("app", u.ID, "sid-1")
	if err != nil {
		t.Fatal(err)
	}
	if h := jwtHeader(t, token); h["typ"] != "logout+jwt" || h["alg"] != "RS256" {
		t.Fatalf("header = %v", h)
	}
	claims, err := e.keyManager.VerifyJWT(token)
	if err != nil {
		t.Fatal(err)
	}
	events, _ := claims["events"].(map[string]any)
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Fatalf("events = %v", claims["events"])
	}
	if claims["iss"] != e.issuerURL || claims["aud"] != "app" || claims["sub"] != u.ID || claims["sid"] != "sid-1" || claims["jti"] == "" {
		t.Fatalf("claims = %v", claims)
	}
	if _, ok := claims["nonce"]; ok {
		t.Fatal("logout tokens must not carry a nonce")
	}
	if exp, _ := claims["exp"].(float64); exp-float64(time.Now().Unix()) > 5*60 {
		t.Fatalf("logout token lives too long: %v", exp)
	}

	if _, err := e.ParseIDTokenHint(token); err == nil {
		t.Fatal("a logout token was accepted as an ID token hint")
	}
	if _, err := e.verifyAccessToken(token); err == nil {
		t.Fatal("a logout token was accepted as an access token")
	}
}

func TestDiscoveryAdvertisesBackchannelLogout(t *testing.T) {
	e, _, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	cfg := e.GetOIDCConfiguration()
	if !cfg.BackchannelLogoutSupported || !cfg.BackchannelLogoutSessionSupported {
		t.Fatalf("discovery = %+v", cfg)
	}
}

type receiver struct {
	status int32
	calls  int32
	last   atomic.Value // url.Values
}

func (r *receiver) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&r.calls, 1)
		if err := req.ParseForm(); err != nil {
			t.Error(err)
		}
		r.last.Store(req.PostForm)
		if ct := req.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			t.Errorf("content type %q", ct)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(int(atomic.LoadInt32(&r.status)))
	})
}

func queuedLogout(t *testing.T, e *Engine, db *store.Store, backchannel string) (*store.User, string) {
	t.Helper()
	u := testUser(t, db)
	c := testClient(t, db, "app", "public", []string{"https://app/cb"}, []string{"openid"})
	c.BackchannelLogoutURI = backchannel
	if err := db.UpdateOAuthClient(c); err != nil {
		t.Fatal(err)
	}
	sess := oauthSession(t, db, u.ID)
	sid, err := db.EnsureClientSession("app", sess, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeSession(u.ID, sess, nil); err != nil {
		t.Fatal(err)
	}
	return u, sid
}

func TestBackchannelDeliveryPostsASignedLogoutTokenAndRecordsTheOutcome(t *testing.T) {
	netguard.AllowPrivate = true
	t.Cleanup(func() { netguard.AllowPrivate = false })
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	rcv := &receiver{status: http.StatusOK}
	srv := httptest.NewServer(rcv.handler(t))
	defer srv.Close()
	u, sid := queuedLogout(t, e, db, srv.URL+"/backchannel")

	did, err := e.DeliverPendingLogout(context.Background())
	if err != nil || !did {
		t.Fatalf("deliver: %v %v", did, err)
	}
	form := rcv.last.Load().(interface{ Get(string) string })
	claims, err := e.keyManager.VerifyJWT(form.Get("logout_token"))
	if err != nil || claims["sid"] != sid || claims["sub"] != u.ID || claims["aud"] != "app" {
		t.Fatalf("posted token: %v %v", claims, err)
	}
	rows, _ := db.ListLogoutDeliveries(u.ID, 10)
	if len(rows) != 1 || rows[0].Status != "delivered" {
		t.Fatalf("rows = %+v", rows)
	}
	if did, _ := e.DeliverPendingLogout(context.Background()); did {
		t.Fatal("nothing should remain to deliver")
	}
}

func TestBackchannelDeliveryRetriesServerErrorsWithAFreshToken(t *testing.T) {
	netguard.AllowPrivate = true
	t.Cleanup(func() { netguard.AllowPrivate = false })
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	rcv := &receiver{status: http.StatusServiceUnavailable}
	srv := httptest.NewServer(rcv.handler(t))
	defer srv.Close()
	u, _ := queuedLogout(t, e, db, srv.URL+"/backchannel")

	if did, err := e.DeliverPendingLogout(context.Background()); err != nil || !did {
		t.Fatalf("first attempt: %v %v", did, err)
	}
	first := rcv.last.Load().(interface{ Get(string) string }).Get("logout_token")
	rows, _ := db.ListLogoutDeliveries(u.ID, 10)
	if rows[0].Status != "queued" || rows[0].Attempts != 1 || rows[0].LastError == "" {
		t.Fatalf("after 503: %+v", rows[0])
	}
	if _, err := db.RetryLogoutDeliveryNow(u.ID, rows[0].ID, nil); err != nil {
		t.Fatal(err)
	}
	atomic.StoreInt32(&rcv.status, http.StatusOK)
	if did, err := e.DeliverPendingLogout(context.Background()); err != nil || !did {
		t.Fatalf("second attempt: %v %v", did, err)
	}
	second := rcv.last.Load().(interface{ Get(string) string }).Get("logout_token")
	if first == second {
		t.Fatal("a retry must mint a fresh token, not replay the old one")
	}
	rows, _ = db.ListLogoutDeliveries(u.ID, 10)
	if rows[0].Status != "delivered" || rows[0].Attempts != 1 { // a manual retry restores the attempt budget
		t.Fatalf("after retry: %+v", rows[0])
	}
}

func TestBackchannelDeliveryNeverFollowsRedirects(t *testing.T) {
	netguard.AllowPrivate = true
	t.Cleanup(func() { netguard.AllowPrivate = false })
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	var followed int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			atomic.AddInt32(&followed, 1)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	u, _ := queuedLogout(t, e, db, srv.URL+"/backchannel")

	if _, err := e.DeliverPendingLogout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&followed) != 0 {
		t.Fatal("the delivery client followed a redirect")
	}
	rows, _ := db.ListLogoutDeliveries(u.ID, 10)
	if rows[0].Status != "queued" || rows[0].LastError == "" {
		t.Fatalf("a redirect is not an acknowledgement: %+v", rows[0])
	}
}

// A receiver that accepts the connection and never answers holds one worker, not the
// queue: the healthy app queued behind two of its rows is still told promptly.
func TestATarpittedReceiverDoesNotBlockOtherApps(t *testing.T) {
	netguard.AllowPrivate = true
	t.Cleanup(func() { netguard.AllowPrivate = false })
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer fast.Close()

	u := testUser(t, db)
	for _, c := range []struct{ id, url string }{{"slow", slow.URL}, {"fast", fast.URL}} {
		client := testClient(t, db, c.id, "public", []string{"https://app/cb"}, []string{"openid"})
		client.BackchannelLogoutURI = c.url + "/backchannel"
		if err := db.UpdateOAuthClient(client); err != nil {
			t.Fatal(err)
		}
	}
	queue := func(clientID string) {
		sess := oauthSession(t, db, u.ID)
		if _, err := db.EnsureClientSession(clientID, sess, u.ID); err != nil {
			t.Fatal(err)
		}
		if err := db.RevokeSession(u.ID, sess, nil); err != nil {
			t.Fatal(err)
		}
	}
	queue("slow")
	queue("slow")
	queue("fast")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logoutPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { logoutPollInterval = 3 * time.Second })
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		e.StartLogoutWorker(ctx)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rows, _ := db.ListLogoutDeliveries(u.ID, 10)
		fastDone := false
		for _, r := range rows {
			fastDone = fastDone || (r.ClientID == "fast" && r.Status == "delivered")
		}
		if fastDone {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fast app not told while slow app tarpits: %+v", rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	close(release)
	<-stopped
	slow.Close()
}
