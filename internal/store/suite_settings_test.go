package store

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeEmailDomains(t *testing.T) {
	good := map[string]string{
		"example.com":           "example.com",
		"  Mail.Example.COM ":   "mail.example.com",
		"bücher.example":        "xn--bcher-kva.example",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
		"a-b.co.uk":             "a-b.co.uk",
	}
	for in, want := range good {
		if got, err := NormalizeEmailDomain(in); err != nil || got != want {
			t.Errorf("%q = %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", "com", "https://example.com", "example.com:25", "example.com/mail", "*.example.com",
		"user@example.com", "192.168.1.10", "[::1]", "-bad.example", "bad-.example", "ex ample.com",
		"example..com", "example.com.", "under_score.example", strings.Repeat("a", 64) + ".example",
		strings.Repeat("abcdefghi.", 26) + "com", "exa\u202emple.com",
	} {
		if got, err := NormalizeEmailDomain(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		} else if _, ok := err.(InputError); !ok {
			t.Errorf("%q: %T is not an InputError", bad, err)
		}
	}
	if _, err := NormalizeEmailDomains([]string{"example.com", "EXAMPLE.com"}); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate after normalisation: %v", err)
	}
	if _, err := NormalizeEmailDomains([]string{"bücher.example", "xn--bcher-kva.example"}); err == nil {
		t.Error("Unicode and punycode spellings of one domain both accepted")
	}
	many := make([]string, MaxSuiteEmailDomains+1)
	for i := range many {
		many[i] = "d" + strings.Repeat("x", i%5) + uuid.NewString()[:8] + ".example"
	}
	if _, err := NormalizeEmailDomains(many); err == nil {
		t.Errorf("%d domains accepted", len(many))
	}
	if got, err := NormalizeEmailDomains(many[:MaxSuiteEmailDomains]); err != nil || len(got) != MaxSuiteEmailDomains {
		t.Errorf("the maximum was refused: %v", err)
	}
}

func TestSuiteSettingsRoundTrip(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	if d, err := s.SuiteEmailDomains(); err != nil || d == nil || len(d) != 0 {
		t.Fatalf("fresh domains = %#v %v, want empty list", d, err)
	}
	if th, err := s.SuiteDefaultTheme(); err != nil || th != "system" {
		t.Fatalf("fresh theme = %q %v", th, err)
	}
	ev := func(a string) *AuditEvent { return &AuditEvent{ID: uuid.NewString(), Action: a, Outcome: "success"} }
	if _, err := s.SetSuiteEmailDomains([]string{"https://evil.example"}, ev("x")); err == nil {
		t.Fatal("bad domain stored")
	}
	if got, err := s.SetSuiteEmailDomains([]string{"Example.com", "bücher.example"}, ev("admin.suite_email_domains_changed")); err != nil || !slices.Equal(got, []string{"example.com", "xn--bcher-kva.example"}) {
		t.Fatalf("set domains = %v %v", got, err)
	}
	if d, _ := s.SuiteEmailDomains(); !slices.Equal(d, []string{"example.com", "xn--bcher-kva.example"}) {
		t.Fatalf("read back %v", d)
	}
	if err := s.SetSuiteDefaultTheme("sky", ev("x")); err == nil {
		t.Fatal("removed theme ID stored")
	}
	if err := s.SetSuiteDefaultTheme("ocean-pair", ev("admin.suite_default_theme_changed")); err != nil {
		t.Fatal(err)
	}
	if th, _ := s.SuiteDefaultTheme(); th != "ocean-pair" {
		t.Fatalf("theme = %q", th)
	}
	rows, _, err := s.DefaultOrg().SearchAuditEvents(AuditFilter{Action: "admin.suite_", Limit: 10})
	if err != nil || len(rows) != 2 {
		t.Fatalf("audit rows = %d %v, want 2 (refusals write none)", len(rows), err)
	}
	// Clearing removes the rows, and a value a later catalog dropped reads as system.
	if _, err := s.SetSuiteEmailDomains([]string{}, ev("admin.suite_email_domains_changed")); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.SuiteEmailDomains(); len(d) != 0 {
		t.Fatalf("cleared domains = %v", d)
	}
	if err := s.SetSetting(SuiteDefaultThemeSetting, "retired-theme"); err != nil {
		t.Fatal(err)
	}
	if th, _ := s.SuiteDefaultTheme(); th != "system" {
		t.Fatalf("retired stored theme read as %q", th)
	}
}

// The allowlist must be exactly what the vendored ky-ui catalog defines.
func TestSuiteThemeIDsMatchVendoredCatalog(t *testing.T) {
	src, err := os.ReadFile("../../web/src/ky-ui/themes.js")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"system"}
	for _, m := range regexp.MustCompile(`(?m)^\s*(?:entry|pair)\('([a-z-]+)'`).FindAllStringSubmatch(string(src), -1) {
		want = append(want, m[1])
	}
	if len(want) < 19 || !slices.Equal(slices.Sorted(slices.Values(want)), slices.Sorted(slices.Values(SuiteThemeIDs))) {
		t.Fatalf("SuiteThemeIDs = %v\nvendored catalog = %v", SuiteThemeIDs, want)
	}
}
