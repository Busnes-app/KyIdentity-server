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
