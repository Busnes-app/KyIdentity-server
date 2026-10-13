package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSetupGroupIntentBeforeSecretReads(t *testing.T) {
	for _, cause := range []string{"admin member", "foreign member", "duplicate name", "unknown group", "management only", "unassigned delivery"} {
		t.Run(cause, func(t *testing.T) {
			b := setupBundle{Schema: "kyidentity.setup/1", ID: uuid.NewString(), Admin: setupAccount{"owner-admin", "admin@example.test", "/missing"}, Everyday: setupAccount{"owner", "owner@example.test", "/missing"}, Groups: []setupGroup{{Name: "Suite users", Members: []string{"owner"}}}, Clients: []setupClient{{ID: "drive", Name: "Drive", SecretFile: "/missing", RedirectURIs: []string{"https://drive.test/callback"}, Groups: []string{"Suite users"}}}}
			switch cause {
			case "admin member":
				b.Groups[0].Members = []string{"owner-admin"}
			case "foreign member":
				b.Groups[0].Members = []string{"foreign"}
			case "duplicate name":
				b.Groups = append(b.Groups, setupGroup{Name: "suite users"})
			case "unknown group":
				b.Clients[0].Groups = []string{"foreign"}
			case "management only":
				b.Clients[0].AdministratorRole = "admin"
			case "unassigned delivery":
				b.Clients[0].Groups = nil
				b.Clients[0].SCIM = &setupSCIM{URL: "https://drive.test/scim/v2", TokenFile: "/missing", Groups: true}
			}
			raw, _ := json.Marshal(b)
			if _, err := prepareSetup(raw); err == nil || strings.Contains(err.Error(), "protected setup file") {
				t.Fatal("invalid group intent reached credential files", err)
			}
		})
	}
}
