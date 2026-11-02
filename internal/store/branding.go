package store

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// Branding rows in system_settings. The logo row is "<content type>;base64,<bytes>": the
// bytes the upload handler re-encoded, never what the browser sent.
const (
	BrandingNameSetting = "branding_org_name"
	BrandingLogoSetting = "branding_logo"
)

// Branding is the organisation's display identity: a name and a raster logo shown on the
// sign-in page and in the app shell. It is display only and grants nothing.
type Branding struct {
	Name     string
	LogoType string
	Logo     []byte
}

// LogoVersion names the stored logo bytes, so a URL carrying it can be cached for good.
func (b Branding) LogoVersion() string {
	if len(b.Logo) == 0 {
		return ""
	}
	sum := sha256.Sum256(b.Logo)
	return hex.EncodeToString(sum[:8])
}

// Branding reads the organisation branding; unset fields are empty.
func (s *Store) Branding() (Branding, error) {
	var b Branding
	name, err := s.GetSetting(BrandingNameSetting)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return b, err
	}
	b.Name = name
	logo, err := s.GetSetting(BrandingLogoSetting)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return b, err
	}
	if contentType, encoded, ok := strings.Cut(logo, ";base64,"); ok {
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return b, err
		}
		b.LogoType, b.Logo = contentType, data
	}
	return b, nil
}

// SetBrandingName stores the organisation name, or clears it when empty, with its audit row.
func (s *Store) SetBrandingName(name string, audit *AuditEvent) error {
	return s.EditSettings(audit, func(st Settings) error {
		if name == "" {
			return st.DeleteSetting(BrandingNameSetting)
		}
		return st.SetSetting(BrandingNameSetting, name)
	})
}

// SetBrandingLogo stores the logo, or clears it when data is empty, with its audit row.
func (s *Store) SetBrandingLogo(contentType string, data []byte, audit *AuditEvent) error {
	return s.EditSettings(audit, func(st Settings) error {
		if len(data) == 0 {
			return st.DeleteSetting(BrandingLogoSetting)
		}
		return st.SetSetting(BrandingLogoSetting, contentType+";base64,"+base64.StdEncoding.EncodeToString(data))
	})
}
