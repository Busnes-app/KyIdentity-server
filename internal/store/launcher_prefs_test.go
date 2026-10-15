package store

import (
	"errors"
	"strings"
	"testing"
)

func TestLauncherPrefsValidate(t *testing.T) {
	many := func(n int, prefix string) []string {
		keys := make([]string, n)
		for i := range keys {
			keys[i] = prefix + strings.Repeat("x", i%50+1) + string(rune('a'+i/50))
		}
		return keys
	}
	groups := func(n int) []LauncherGroup {
		g := make([]LauncherGroup, n)
		for i := range g {
			g[i] = LauncherGroup{Name: "g"}
		}
		return g
	}
	cases := []struct {
		name string
		p    LauncherPrefs
		ok   bool
	}{
		{"minimal", LauncherPrefs{Layout: "tiles"}, true},
		{"dock with groups", LauncherPrefs{Layout: "dock", Groups: []LauncherGroup{{Name: "Daily", Apps: []string{"client:kypost", "custom:3f2a"}}}, Hidden: []string{"client:kyrecovery"}}, true},
		{"free-form client id", LauncherPrefs{Layout: "tiles", Hidden: []string{"client:my app/v2"}}, true},
		{"unknown layout", LauncherPrefs{Layout: "grid"}, false},
		{"empty layout", LauncherPrefs{}, false},
		{"blank group name", LauncherPrefs{Layout: "tiles", Groups: []LauncherGroup{{Name: "  "}}}, false},
		{"long group name", LauncherPrefs{Layout: "tiles", Groups: []LauncherGroup{{Name: strings.Repeat("é", 41)}}}, false},
		{"too many groups", LauncherPrefs{Layout: "tiles", Groups: groups(21)}, false},
		{"unknown key kind", LauncherPrefs{Layout: "tiles", Hidden: []string{"system:x"}}, false},
		{"empty id", LauncherPrefs{Layout: "tiles", Hidden: []string{"client:"}}, false},
		{"control character", LauncherPrefs{Layout: "tiles", Hidden: []string{"client:a\nb"}}, false},
		{"overlong key", LauncherPrefs{Layout: "tiles", Hidden: []string{"client:" + strings.Repeat("a", 250)}}, false},
		{"duplicate across group and hidden", LauncherPrefs{Layout: "tiles", Groups: []LauncherGroup{{Name: "g", Apps: []string{"client:a"}}}, Hidden: []string{"client:a"}}, false},
		{"too many keys", LauncherPrefs{Layout: "tiles", Hidden: many(501, "client:")}, false},
	}
	for _, c := range cases {
		err := c.p.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: unexpected %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrInvalidLauncherPrefs) {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

func TestLauncherPrefsRoundTripTrimAndCascade(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	if p, err := s.GetLauncherPrefs(u.ID); err != nil || p != nil {
		t.Fatalf("fresh user prefs = %v, %v; want nil", p, err)
	}
	in := LauncherPrefs{Layout: "dock", Groups: []LauncherGroup{{Name: "  Daily ", Apps: []string{"client:kypost"}}}}
	if err := s.SetLauncherPrefs(u.ID, in); err != nil {
		t.Fatal(err)
	}
	// Saving twice is an update, not a second row.
	in.Layout = "tiles"
	if err := s.SetLauncherPrefs(u.ID, in); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetLauncherPrefs(u.ID)
	if err != nil || got == nil || got.Layout != "tiles" || got.Groups[0].Name != "Daily" {
		t.Fatalf("round trip = %+v, %v", got, err)
	}

	if err := s.DeleteUserWithSyncEvents(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM launcher_prefs`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("prefs rows after user deletion = %d, %v", n, err)
	}
}
