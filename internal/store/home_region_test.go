package store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The home region: a slug the Go check and the column CHECK agree on, local for the default
// org and by default, set once, never changed.
func TestHomeRegion(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	if r, err := s.DefaultOrg().HomeRegion(); err != nil || r != HomeRegionLocal {
		t.Fatalf("default org region %q %v", r, err)
	}
	for _, c := range []struct {
		region string
		ok     bool
	}{
		{"local", true}, {"us", true}, {"eu-central", true}, {"ap-2", true}, {"a1234567890123456789012345678901", true},
		{"", false}, {"u", false}, {"US", false}, {"1us", false}, {"-us", false}, {"us_east", false}, {"us east", false},
		{"a12345678901234567890123456789012", false}, {"ü", false}, {"us.east", false},
	} {
		if ValidHomeRegion(c.region) != c.ok {
			t.Errorf("ValidHomeRegion(%q) = %v", c.region, !c.ok)
		}
		org, err := CreateOrgInRegionForTest(s, "customer", c.region)
		if (err == nil) != c.ok {
			t.Errorf("insert %q: %v, want ok=%v", c.region, err, c.ok)
		}
		if err == nil {
			if r, _ := s.Org(org).HomeRegion(); r != c.region {
				t.Errorf("stored %q, want %q", r, c.region)
			}
		}
	}
	org, err := CreateOrgInRegionForTest(s, "customer", "eu")
	if err != nil {
		t.Fatal(err)
	}
	refused(t, s, msgHomeRegionChanged, `UPDATE orgs SET home_region='us' WHERE id='`+org.id+`'`)
	refused(t, s, msgHomeRegionChanged, `UPDATE orgs SET home_region='us' WHERE id='`+DefaultOrgID+`'`)
	// Other org writes leave it alone.
	tenancyExec(t, s, `UPDATE orgs SET name='renamed', home_region='eu' WHERE id='`+org.id+`'`)
	// Postgres (the multi-tenant backend) has no default: provisioning must name the region.
	missing := `INSERT INTO orgs(id,name,kind,status,created_at,updated_at) VALUES('org-nr','n','customer','active',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`
	if OnPostgresTest() {
		refused(t, s, "home_region", missing)
	} else {
		tenancyExec(t, s, missing)
		if r, _ := s.Org(OrgID{"org-nr"}).HomeRegion(); r != HomeRegionLocal {
			t.Fatalf("SQLite default %q", r)
		}
	}
}

// Platform events and the suite org list carry the region.
func TestHomeRegionIsPublished(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	org, err := CreateOrgInRegionForTest(s, "customer", "eu")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := queuePlatformEventTx(tx, org.id, "org.created", "", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := s.db.QueryRow(`SELECT payload_json FROM platform_events WHERE org_id=?`, org.id).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(payload), &body); err != nil || body["home_region"] != "eu" {
		t.Fatalf("event body %s", payload)
	}
	if err := s.CreateOAuthClient(&OAuthClient{ID: "kychat", ClientName: "c", ClientType: "confidential", RedirectURIsJSON: `["https://eu.chat.test/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	var app string
	if err := s.db.QueryRow(`SELECT id FROM app_registry WHERE client_id='kychat'`).Scan(&app); err != nil {
		t.Fatal(err)
	}
	if err := EnableOrgAppForTest(s, org, app, `{}`); err != nil {
		t.Fatal(err)
	}
	orgs, err := s.Platform().SuiteOrgs("kychat", 0, "", 10)
	if err != nil || len(orgs) != 1 || orgs[0].HomeRegion != "eu" {
		t.Fatalf("suite orgs %+v %v", orgs, err)
	}
}

// A client's region map is replaced whole, read per org, and goes with the client.
func TestClientRegionOrigins(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	if err := s.CreateOAuthClient(&OAuthClient{ID: "kychat", ClientName: "c", ClientType: "confidential", RedirectURIsJSON: `["https://eu.chat.test/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	ev := func() *AuditEvent {
		return &AuditEvent{ID: uuid.NewString(), Action: "admin.client_regions_changed", Outcome: "success", CreatedAt: time.Now().UTC()}
	}
	if err := s.SetClientRegionOrigins("kychat", map[string]string{"US": "https://x"}, ev()); err == nil {
		t.Fatal("bad region accepted")
	}
	if err := s.SetClientRegionOrigins("nope", map[string]string{}, ev()); err != ErrNotFound {
		t.Fatalf("unknown client: %v", err)
	}
	if err := s.SetClientRegionOrigins("kychat", map[string]string{"us": "https://us.chat.test", "eu": "https://eu.chat.test"}, ev()); err != nil {
		t.Fatal(err)
	}
	if err := s.SetClientRegionOrigins("kychat", map[string]string{"eu": "https://eu.chat.test"}, ev()); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ClientRegionOrigins("kychat"); len(got) != 1 || got["eu"] != "https://eu.chat.test" {
		t.Fatalf("replaced map %v", got)
	}
	eu, _ := CreateOrgInRegionForTest(s, "customer", "eu")
	us, _ := CreateOrgInRegionForTest(s, "customer", "us")
	if got, _ := s.OrgRegionOrigins(eu); got["kychat"] != "https://eu.chat.test" {
		t.Fatalf("eu %v", got)
	}
	if got, _ := s.OrgRegionOrigins(us); len(got) != 1 || got["kychat"] != "" {
		t.Fatalf("us must see kychat as regioned with no origin: %v", got)
	}
	if _, err := s.DeleteOAuthClient("kychat", nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.OrgRegionOrigins(eu); len(got) != 0 {
		t.Fatalf("rows outlived the client: %v", got)
	}
}
