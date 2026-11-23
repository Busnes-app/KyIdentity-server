package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func suiteStoragePost(t *testing.T, srv *Server, user, pass, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/suite/storage", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr.Code, strings.TrimSpace(rr.Body.String())
}

// POST /api/suite/storage: the caller's app reports per org and gets its grant; another
// app's org reads as unknown; one bad entry refuses the whole request.
func TestSuiteStorage(t *testing.T) {
	srv, db, orgA, orgB, cleanup := multiSuite(t)
	defer cleanup()
	gib := int64(1) << 30
	for _, org := range []store.OrgID{orgA, orgB} {
		if err := db.Platform().SetOrgLimits(org, store.OrgLimits{MaxSeats: 1, StorageBytes: 20 * gib}, false, &store.AuditEvent{}); err != nil {
			t.Fatal(err)
		}
	}
	code, body := suiteStoragePost(t, srv, "kypost", "post-secret", fmt.Sprintf(`{"reports":[{"org_id":%q,"used_bytes":%d,"seq":1,"want_bytes":%d},{"org_id":%q,"used_bytes":1,"seq":1,"want_bytes":0}]}`, orgB, gib, gib, orgA))
	want := fmt.Sprintf(`{"results":[{"org_id":%q,"result":"ok","seq":1,"ceiling_bytes":%d,"ttl_seconds":900,"pool_bytes":%d,"org_used_bytes":%d,"over_since":null},{"org_id":%q,"result":"unknown_org"}]}`, orgB, 2*gib, 20*gib, gib, orgA)
	if code != http.StatusOK || body != want {
		t.Fatalf("report: %d %s\nwant %s", code, body, want)
	}
	// The listing carries the pool on the poll apps already make.
	if code, body := suiteBody(t, srv, "/api/suite/orgs", ""); code != http.StatusOK || !strings.Contains(body, fmt.Sprintf(`"storage":{"pool_bytes":%d,"over_since":null}`, 20*gib)) {
		t.Fatalf("orgs: %d %s", code, body)
	}
	entry := func(org string) string {
		return fmt.Sprintf(`{"org_id":%q,"used_bytes":0,"seq":1,"want_bytes":0}`, org)
	}
	many := make([]string, 501)
	for i := range many {
		many[i] = entry(uuid.NewString())
	}
	org := orgB.String()
	for name, b := range map[string]string{
		"empty":         `{"reports":[]}`,
		"no reports":    `{}`,
		"501 entries":   `{"reports":[` + strings.Join(many, ",") + `]}`,
		"repeated org":  `{"reports":[` + entry(org) + `,` + entry(org) + `]}`,
		"upper case id": `{"reports":[` + entry(strings.ToUpper(org)) + `]}`,
		"braced id":     `{"reports":[` + entry("{"+org+"}") + `]}`,
		"not a uuid":    `{"reports":[` + entry("org-1") + `]}`,
		"seq 0":         `{"reports":[{"org_id":"` + org + `","used_bytes":0,"seq":0,"want_bytes":0}]}`,
		"seq overflow":  `{"reports":[{"org_id":"` + org + `","used_bytes":0,"seq":9223372036854775808,"want_bytes":0}]}`,
		"negative used": `{"reports":[{"org_id":"` + org + `","used_bytes":-1,"seq":2,"want_bytes":0}]}`,
		"used > 2^53":   `{"reports":[{"org_id":"` + org + `","used_bytes":9007199254740993,"seq":2,"want_bytes":0}]}`,
		"want > 2^53":   `{"reports":[{"org_id":"` + org + `","used_bytes":0,"seq":2,"want_bytes":9007199254740993}]}`,
		"fractional":    `{"reports":[{"org_id":"` + org + `","used_bytes":1.5,"seq":2,"want_bytes":0}]}`,
		"app in body":   `{"reports":[{"org_id":"` + org + `","app_id":"kydrive","used_bytes":0,"seq":2,"want_bytes":0}]}`,
		"trailing":      `{"reports":[` + entry(org) + `]} {}`,
		"oversize":      `{"reports":[` + entry(org) + `],"pad":"` + strings.Repeat("x", 64<<10) + `"}`,
	} {
		if code, body := suiteStoragePost(t, srv, "kypost", "post-secret", b); code != http.StatusBadRequest || body != `{"error":"invalid_request"}` {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	// Nothing in a refused request was applied: seq 2 is still new.
	if code, body := suiteStoragePost(t, srv, "kypost", "post-secret", fmt.Sprintf(`{"reports":[{"org_id":%q,"used_bytes":0,"seq":2,"want_bytes":0}]}`, org)); code != http.StatusOK || !strings.Contains(body, `"result":"ok","seq":2,`) {
		t.Fatalf("after refusals: %d %s", code, body)
	}
	if code, _ := suiteStoragePost(t, srv, "kypost", "wrong", `{"reports":[`+entry(org)+`]}`); code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", code)
	}
	if code, _ := suiteStoragePost(t, srv, "", "", `{"reports":[`+entry(org)+`]}`); code != http.StatusUnauthorized {
		t.Fatalf("no credentials: %d", code)
	}
	var out struct {
		Results []json.RawMessage `json:"results"`
	}
	_, body = suiteStoragePost(t, srv, "kycalendar", "cal-secret", `{"reports":[`+entry(org)+`]}`)
	if json.Unmarshal([]byte(body), &out) != nil || len(out.Results) != 1 || !strings.Contains(string(out.Results[0]), `"result":"ok"`) {
		t.Fatalf("a second app keeps its own sequence: %s", body)
	}
}

// A single-tenant install has no pool: 404, the same as an unknown route.
func TestSingleTenantHasNoSuiteStorage(t *testing.T) {
	srv, _, cleanup := suiteFixture(t)
	defer cleanup()
	code, body := suiteStoragePost(t, srv, "kycalendar", "cal-secret", `{"reports":[{"org_id":"`+store.DefaultOrgID+`","used_bytes":0,"seq":1,"want_bytes":0}]}`)
	if code != http.StatusNotFound || body != `{"error":"not_found"}` {
		t.Fatalf("storage: %d %s", code, body)
	}
}
