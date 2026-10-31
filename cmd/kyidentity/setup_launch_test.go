package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func TestSetupLaunchURL(t *testing.T) {
	b, file, db := stageFixture(t)
	b.Clients = append(b.Clients, setupClient{ID: "chat", Name: "Chat", RedirectURIs: []string{"https://auth.example.test/callback"}})
	if _, err := stageCommand(t, b, file, db, false); err != nil {
		t.Fatal(err)
	}
	launch := func(arg string) (string, error) {
		var out bytes.Buffer
		err := runSetup([]string{"--file", file, "--db", db, "--launch-url", arg}, &out)
		var r struct{ Schema, Client, Status string }
		if err == nil && (json.Unmarshal(out.Bytes(), &r) != nil || r.Schema != "kyidentity.launch-url/1") {
			t.Fatalf("launch URL output %q", out.String())
		}
		return r.Status, err
	}
	if _, err := launch("chat=https://chat.example.test/"); err == nil {
		t.Fatal("launch URL accepted an unapplied setup")
	}
	if err := runSetup([]string{"--file", file, "--db", db}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"chat=http://chat.example.test/", "chat=https://u@chat.example.test/", "chat=https://chat.example.test/#x", "chat=javascript:alert(1)", "chat", "chat=https://chat.example.test/" + strings.Repeat("x", 2048), "other=https://chat.example.test/"} {
		if _, err := launch(bad); err == nil {
			t.Fatalf("launch URL accepted %q", bad)
		}
	}
	stored := func() string {
		s, err := store.OpenInstallerStore(db, true)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		c, err := s.GetOAuthClientByID("chat")
		if err != nil || c == nil {
			t.Fatal(err)
		}
		return c.LaunchURL
	}
	for _, want := range []string{"set", "unchanged"} {
		if status, err := launch("chat=https://chat.example.test/"); err != nil || status != want || stored() != "https://chat.example.test/" {
			t.Fatalf("launch URL status %q, stored %q: %v", status, stored(), err)
		}
	}
	// A link an admin set stays.
	if status, err := launch("chat=https://element.example.test/"); err != nil || status != "unchanged" || stored() != "https://chat.example.test/" {
		t.Fatalf("launch URL replaced an existing link: %q %q %v", status, stored(), err)
	}
	for _, extra := range [][]string{{"--stage"}, {"--check"}, {"--export-client", "chat"}} {
		if err := runSetup(append([]string{"--file", file, "--db", db, "--launch-url", "chat=https://chat.example.test/"}, extra...), &bytes.Buffer{}); err == nil {
			t.Fatalf("launch URL combined with %v", extra)
		}
	}
	var out bytes.Buffer
	if err := runSetup([]string{"--capabilities"}, &out); err != nil || !strings.Contains(out.String(), `"client-launch-urls"`) {
		t.Fatalf("capabilities %s: %v", out.String(), err)
	}
}

func TestSetupLauncherNameAndAudience(t *testing.T) {
	b, file, db := stageFixture(t)
	b.Clients = append(b.Clients, setupClient{ID: "chat", Name: "Chat", RedirectURIs: []string{"https://auth.example.test/callback"}, AdministratorRole: "chat.admin", EverydayRole: "chat.user"})
	if _, err := stageCommand(t, b, file, db, false); err != nil {
		t.Fatal(err)
	}
	set := func(flag, arg string) (string, error) {
		var out bytes.Buffer
		err := runSetup([]string{"--file", file, "--db", db, "--" + flag, arg}, &out)
		var r struct{ Schema, Client, Status string }
		if err == nil && (json.Unmarshal(out.Bytes(), &r) != nil || r.Schema != "kyidentity."+flag+"/1" || r.Client != "chat") {
			t.Fatalf("%s output %q", flag, out.String())
		}
		return r.Status, err
	}
	if _, err := set("launcher-name", "chat=KyMessages"); err == nil {
		t.Fatal("launcher name accepted an unapplied setup")
	}
	if err := runSetup([]string{"--file", file, "--db", db}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][2]string{{"launcher-name", "chat="}, {"launcher-name", "chat= padded"}, {"launcher-name", "chat=a\nb"}, {"launcher-name", "chat=" + strings.Repeat("x", 129)}, {"launcher-name", "other=Name"}, {"launcher-audience", "chat=staff"}, {"launcher-audience", "chat="}, {"launcher-audience", "other=admins"}} {
		if _, err := set(bad[0], bad[1]); err == nil {
			t.Fatalf("%s accepted %q", bad[0], bad[1])
		}
	}
	stored := func() *store.OAuthClient {
		s, err := store.OpenInstallerStore(db, true)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		c, err := s.GetOAuthClientByID("chat")
		if err != nil || c == nil {
			t.Fatal(err)
		}
		return c
	}
	for _, want := range []string{"set", "unchanged"} {
		if status, err := set("launcher-name", "chat=KyMessages"); err != nil || status != want {
			t.Fatalf("launcher name status %q: %v", status, err)
		}
		if status, err := set("launcher-audience", "chat=admins"); err != nil || status != want {
			t.Fatalf("launcher audience status %q: %v", status, err)
		}
	}
	// A value already set stays.
	if status, err := set("launcher-audience", "chat=everyone"); err != nil || status != "unchanged" {
		t.Fatalf("launcher audience replaced: %q %v", status, err)
	}
	if c := stored(); c.LauncherName != "KyMessages" || c.LauncherAudience != "admins" {
		t.Fatalf("stored %q %q", c.LauncherName, c.LauncherAudience)
	}
	// The bundle's administrator role now decides who counts as the app's administrator.
	s, err := store.OpenInstallerStore(db, true)
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := s.GetUserByUsername(b.Admin.Username)
	everyday, _ := s.GetUserByUsername(b.Everyday.Username)
	adminApps, _ := s.LauncherAdminClients(admin.ID)
	everydayApps, _ := s.LauncherAdminClients(everyday.ID)
	s.Close()
	if !adminApps["chat"] || everydayApps["chat"] {
		t.Fatalf("app admins: admin %v, everyday %v", adminApps, everydayApps)
	}
	// Intent is unchanged: the ordinary check still passes.
	if err := runSetup([]string{"--file", file, "--db", db, "--check"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{{"--stage"}, {"--check"}, {"--export-client", "chat"}, {"--launch-url", "chat=https://chat.example.test/"}} {
		if err := runSetup(append([]string{"--file", file, "--db", db, "--launcher-name", "chat=KyMessages"}, extra...), &bytes.Buffer{}); err == nil {
			t.Fatalf("launcher name combined with %v", extra)
		}
	}
	var out bytes.Buffer
	if err := runSetup([]string{"--capabilities"}, &out); err != nil || !strings.Contains(out.String(), `"client-launcher-display"`) {
		t.Fatalf("capabilities %s: %v", out.String(), err)
	}
	if err := runSetup([]string{"--capabilities", "--launcher-audience", "chat=admins"}, &bytes.Buffer{}); err == nil {
		t.Fatal("capabilities combined with a launcher setting")
	}
}
