package store

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
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
	if _, _, err := s.SetSuiteEmailDomains([]string{"https://evil.example"}, ev("x")); err == nil {
		t.Fatal("bad domain stored")
	}
	if got, _, err := s.SetSuiteEmailDomains([]string{"Example.com", "bücher.example"}, ev("admin.suite_email_domains_changed")); err != nil || !slices.Equal(got, []string{"example.com", "xn--bcher-kva.example"}) {
		t.Fatalf("set domains = %v %v", got, err)
	}
	if d, _ := s.SuiteEmailDomains(); !slices.Equal(d, []string{"example.com", "xn--bcher-kva.example"}) {
		t.Fatalf("read back %v", d)
	}
	if _, err := s.SetSuiteDefaultTheme("sky", ev("x")); err == nil {
		t.Fatal("removed theme ID stored")
	}
	if _, err := s.SetSuiteDefaultTheme("ocean-pair", ev("admin.suite_default_theme_changed")); err != nil {
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
	if _, _, err := s.SetSuiteEmailDomains([]string{}, ev("admin.suite_email_domains_changed")); err != nil {
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

// Concurrent saves each audit the value they actually replaced: the rows chain from the
// first value to the last with no gap or repeat, and an unchanged save writes no row.
func TestSuiteSettingsAuditChainsUnderConcurrentSaves(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	ev := func() *AuditEvent {
		return &AuditEvent{ID: uuid.NewString(), Action: "admin.suite_email_domains_changed", Outcome: "success"}
	}
	if _, _, err := s.SetSuiteEmailDomains([]string{"a.example"}, ev()); err != nil {
		t.Fatal(err)
	}
	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, changed, err := s.SetSuiteEmailDomains([]string{fmt.Sprintf("d%d.example", i)}, ev()); err != nil || !changed {
				errs <- fmt.Errorf("save %d: changed=%v err=%v", i, changed, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	rows, _, err := s.DefaultOrg().SearchAuditEvents(AuditFilter{Action: "admin.suite_email_domains_changed", Limit: 50})
	if err != nil || len(rows) != n+1 {
		t.Fatalf("audit rows = %d %v, want %d", len(rows), err, n+1)
	}
	next := map[string]string{} // old -> new
	for _, r := range rows {
		var d struct{ Old, New []string }
		if err := json.Unmarshal([]byte(r.DetailsJSON), &d); err != nil || len(d.New) != 1 {
			t.Fatalf("details %q: %v", r.DetailsJSON, err)
		}
		old := strings.Join(d.Old, ",")
		if _, dup := next[old]; dup {
			t.Fatalf("two rows record old=%q: one of them did not replace it", old)
		}
		next[old] = d.New[0]
	}
	at, seen := "", 0
	for ; seen <= n; seen++ {
		nv, ok := next[at]
		if !ok {
			break
		}
		at = nv
	}
	if seen != n+1 {
		t.Fatalf("audit chain covers %d of %d saves: %v", seen, n+1, next)
	}
	if cur, _ := s.SuiteEmailDomains(); cur[0] != at {
		t.Fatalf("chain ends at %q, stored %v", at, cur)
	}
	if _, changed, err := s.SetSuiteEmailDomains([]string{at}, ev()); err != nil || changed {
		t.Fatalf("unchanged save: changed=%v err=%v", changed, err)
	}
	if changed, err := s.SetSuiteDefaultTheme("system", &AuditEvent{ID: uuid.NewString(), Action: "admin.suite_default_theme_changed", Outcome: "success"}); err != nil || changed {
		t.Fatalf("unchanged theme save: changed=%v err=%v", changed, err)
	}
	if rows, _, _ := s.DefaultOrg().SearchAuditEvents(AuditFilter{Action: "admin.suite_", Limit: 50}); len(rows) != n+1 {
		t.Fatalf("unchanged saves wrote audit rows: %d", len(rows))
	}
}
