package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/net/idna"
)

// Platform-wide suite settings (docs/SUITE-DIRECTORY.md), set by the install administrator
// (staff on the hosted platform) and read by every suite app. Both are system_settings keys,
// so they are platform data under the tenancy design; there is no per-org copy.
const (
	// SuiteEmailDomainsSetting is a JSON array of ASCII (punycode) mail domains.
	SuiteEmailDomainsSetting = "suite_email_domains"
	// SuiteDefaultThemeSetting is a ky-ui theme choice ID; absent means "system".
	SuiteDefaultThemeSetting = "suite_default_theme"

	MaxSuiteEmailDomains = 50
)

// SuiteThemeIDs are the choices ky-ui's catalog defines (web/src/ky-ui/themes.js): Match
// system, the six pairs (follow the OS) and the twelve halves (a fixed mode).
// TestSuiteThemeIDsMatchVendoredCatalog keeps the list in step with the vendored copy.
var SuiteThemeIDs = []string{
	"system",
	"busnes-pair", "matter-pair", "ocean-pair", "forest-pair", "ky-pair", "nord-pair",
	"busnes-light", "busnes-dark", "light-matter", "dark-matter", "white-cliffs", "ocean",
	"forest-light", "forest", "polished-ky", "patina-ky", "paper", "nord",
}

// ValidSuiteTheme reports whether id is a ky-ui theme choice ID.
func ValidSuiteTheme(id string) bool { return slices.Contains(SuiteThemeIDs, id) }

// domainProfile maps (lowercase, width) and converts to punycode, then insists on a DNS
// name of letters, digits and hyphens: no scheme, port, path, wildcard or address.
var domainProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.ValidateLabels(true),
	idna.StrictDomainName(true), idna.VerifyDNSLength(true), idna.Transitional(false))

// NormalizeEmailDomain returns the ASCII form of a mail domain, or an InputError.
func NormalizeEmailDomain(raw string) (string, error) {
	d := strings.TrimSpace(raw)
	bad := InputError(fmt.Sprintf("%q is not a mail domain (a name such as example.com, without scheme, port, path or wildcard)", truncateRunes(d, 64)))
	if d == "" || strings.ContainsAny(d, "@:/*?#[] ") {
		return "", bad
	}
	ascii, err := domainProfile.ToASCII(d)
	if err != nil {
		return "", bad
	}
	labels := strings.Split(ascii, ".")
	tld := labels[len(labels)-1]
	// Two labels at least, and a top-level label that is not all digits (not an IPv4 address).
	if len(labels) < 2 || strings.Trim(tld, "0123456789") == "" {
		return "", bad
	}
	return ascii, nil
}

// NormalizeEmailDomains normalises each domain, refusing duplicates (after normalisation)
// and more than MaxSuiteEmailDomains. Order is kept.
func NormalizeEmailDomains(in []string) ([]string, error) {
	if len(in) > MaxSuiteEmailDomains {
		return nil, InputError(fmt.Sprintf("At most %d mail domains", MaxSuiteEmailDomains))
	}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		d, err := NormalizeEmailDomain(raw)
		if err != nil {
			return nil, err
		}
		if slices.Contains(out, d) {
			return nil, InputError(fmt.Sprintf("%s is listed twice", d))
		}
		out = append(out, d)
	}
	return out, nil
}

func truncateRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// SuiteEmailDomains reads the suite's mail domains; none set is an empty list.
func (s *Store) SuiteEmailDomains() ([]string, error) { return suiteEmailDomains(s) }

func suiteEmailDomains(st Settings) ([]string, error) {
	raw, err := st.GetSetting(SuiteEmailDomainsSetting)
	if errors.Is(err, ErrNotFound) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []string{}
	return out, json.Unmarshal([]byte(raw), &out)
}

// errSettingUnchanged rolls back an edit that would store the value already there, so it
// writes no audit row.
var errSettingUnchanged = errors.New("setting unchanged")

// setSettingAuditDetails records the old and new values, read under the edit's writer lock
// so concurrent saves each record the value they actually replaced.
func setSettingAuditDetails(audit *AuditEvent, old, new any) {
	if audit != nil {
		b, _ := json.Marshal(map[string]any{"old": old, "new": new}) // strings and string slices
		audit.DetailsJSON = string(b)
	}
}

// SetSuiteEmailDomains validates and stores the list (empty clears it) with its audit row.
// It returns what was stored and whether it changed; an unchanged save writes nothing.
func (s *Store) SetSuiteEmailDomains(domains []string, audit *AuditEvent) ([]string, bool, error) {
	clean, err := NormalizeEmailDomains(domains)
	if err != nil {
		return nil, false, err
	}
	raw, _ := json.Marshal(clean)
	err = s.EditSettings(audit, func(st Settings) error {
		old, err := suiteEmailDomains(st)
		if err != nil {
			return err
		}
		if slices.Equal(old, clean) {
			return errSettingUnchanged
		}
		setSettingAuditDetails(audit, old, clean)
		if len(clean) == 0 {
			return st.DeleteSetting(SuiteEmailDomainsSetting)
		}
		return st.SetSetting(SuiteEmailDomainsSetting, string(raw))
	})
	if errors.Is(err, errSettingUnchanged) {
		return clean, false, nil
	}
	return clean, err == nil, err
}

// SuiteDefaultTheme reads the suite default theme; unset (or a value a later catalog
// dropped) is "system".
func (s *Store) SuiteDefaultTheme() (string, error) { return suiteDefaultTheme(s) }

func suiteDefaultTheme(st Settings) (string, error) {
	id, err := st.GetSetting(SuiteDefaultThemeSetting)
	if errors.Is(err, ErrNotFound) || err == nil && !ValidSuiteTheme(id) {
		return "system", nil
	}
	return id, err
}

// SetSuiteDefaultTheme stores a ky-ui choice ID with its audit row; "system" clears it. It
// reports whether the value changed; an unchanged save writes nothing.
func (s *Store) SetSuiteDefaultTheme(id string, audit *AuditEvent) (bool, error) {
	if !ValidSuiteTheme(id) {
		return false, InputError("Unknown theme")
	}
	err := s.EditSettings(audit, func(st Settings) error {
		old, err := suiteDefaultTheme(st)
		if err != nil {
			return err
		}
		if old == id {
			return errSettingUnchanged
		}
		setSettingAuditDetails(audit, old, id)
		if id == "system" {
			return st.DeleteSetting(SuiteDefaultThemeSetting)
		}
		return st.SetSetting(SuiteDefaultThemeSetting, id)
	})
	if errors.Is(err, errSettingUnchanged) {
		return false, nil
	}
	return err == nil, err
}
