package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// Organisation branding (issue #145): a name and a raster logo an administrator sets, shown
// on the sign-in page and in the shell. Display only: no CSS, no script, no SVG, no URL the
// server or browser fetches elsewhere.
const (
	maxBrandingNameRunes = 64
	maxLogoBytes         = 128 << 10
	// maxLogoSide bounds decoded pixels (a 1 MiB RGBA buffer at most), checked from the
	// header before the full decode, so a small file cannot claim a huge canvas.
	maxLogoSide = 512
)

type BrandingHandler struct {
	store      *store.Store
	audit      *audit.Logger
	middleware *MiddlewareManager
}

// Get is public: the sign-in page shows the branding before anyone signs in.
func (h *BrandingHandler) Get(w http.ResponseWriter, r *http.Request) {
	b, err := h.store.Branding()
	if err != nil {
		log.Printf("branding read failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	logoURL := ""
	if v := b.LogoVersion(); v != "" {
		logoURL = "/api/branding/logo?v=" + v
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": b.Name, "logoUrl": logoURL})
}

// Logo serves the stored logo. A request naming the current version may be cached for good;
// any other is revalidated, so a replaced logo shows at once.
func (h *BrandingHandler) Logo(w http.ResponseWriter, r *http.Request) {
	b, err := h.store.Branding()
	if err != nil {
		log.Printf("branding read failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	if len(b.Logo) == 0 {
		writeAPIError(w, http.StatusNotFound, "not_found", "")
		return
	}
	if r.URL.Query().Get("v") == b.LogoVersion() {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("Content-Type", b.LogoType)
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	_, _ = w.Write(b.Logo)
}

// validBrandingName: visible characters and ordinary spaces, as group names, so the sign-in
// page cannot carry bidi overrides, invisible marks or line breaks.
func validBrandingName(name string) bool {
	return utf8.ValidString(name) && utf8.RuneCountInString(name) <= maxBrandingNameRunes && !strings.ContainsFunc(name, func(r rune) bool {
		return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Cs, unicode.Co) || (unicode.IsSpace(r) && r != ' ')
	})
}

// PutName sets the organisation name; an empty name clears it.
func (h *BrandingHandler) PutName(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name *string `json:"name"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Name == nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	name := strings.TrimSpace(*req.Name)
	if !validBrandingName(name) {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "Organisation name must be up to 64 visible characters and ordinary spaces")
		return
	}
	old, err := h.store.Branding()
	if err != nil {
		log.Printf("branding read failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.branding_name_changed", actor.ID, actor.Username, "branding", "settings", h.middleware.ClientIP(r), r.UserAgent(), "success",
		map[string]any{"old": old.Name, "new": name})
	if err := h.store.SetBrandingName(name, event.Row); err != nil {
		log.Printf("branding name write failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	event.Committed()
	h.Get(w, r)
}

// PutLogo takes a PNG or JPEG as the raw request body, decodes it and stores a fresh
// encoding of the pixels: metadata, trailing bytes and anything else riding in the file are
// dropped, so what is served is only an image.
func (h *BrandingHandler) PutLogo(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, maxLogoBytes+1))
	if err != nil || len(data) == 0 {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	if len(data) > maxLogoBytes {
		writeAPIError(w, http.StatusRequestEntityTooLarge, "invalid_request", "Logo must be 128 KiB or smaller")
		return
	}
	contentType, clean, bounds, err := reencodeLogo(data)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.branding_logo_uploaded", actor.ID, actor.Username, "branding", "settings", h.middleware.ClientIP(r), r.UserAgent(), "success",
		map[string]any{"contentType": contentType, "bytes": len(clean), "width": bounds.Dx(), "height": bounds.Dy()})
	if err := h.store.SetBrandingLogo(contentType, clean, event.Row); err != nil {
		log.Printf("branding logo write failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	event.Committed()
	h.Get(w, r)
}

// DeleteLogo removes the logo; the KyIdentity mark shows again.
func (h *BrandingHandler) DeleteLogo(w http.ResponseWriter, r *http.Request) {
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.branding_logo_removed", actor.ID, actor.Username, "branding", "settings", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.SetBrandingLogo("", nil, event.Row); err != nil {
		log.Printf("branding logo delete failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	event.Committed()
	h.Get(w, r)
}

var errLogoFormat = errors.New("Logo must be a PNG or JPEG image")

// reencodeLogo accepts PNG and JPEG by their bytes, never the declared type, bounds the
// canvas from the header, then decodes and re-encodes in the same format.
func reencodeLogo(data []byte) (string, []byte, image.Rectangle, error) {
	contentType := http.DetectContentType(data)
	var decode func(io.Reader) (image.Image, error)
	var config func(io.Reader) (image.Config, error)
	var encode func(io.Writer, image.Image) error
	switch contentType {
	case "image/png":
		decode, config = png.Decode, png.DecodeConfig
		encode = (&png.Encoder{CompressionLevel: png.BestCompression}).Encode
	case "image/jpeg":
		decode, config = jpeg.Decode, jpeg.DecodeConfig
		encode = func(w io.Writer, img image.Image) error { return jpeg.Encode(w, img, &jpeg.Options{Quality: 90}) }
	default:
		return "", nil, image.Rectangle{}, errLogoFormat
	}
	cfg, err := config(bytes.NewReader(data))
	if err != nil {
		return "", nil, image.Rectangle{}, errLogoFormat
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > maxLogoSide || cfg.Height > maxLogoSide {
		return "", nil, image.Rectangle{}, errors.New("Logo must be at most 512 by 512 pixels")
	}
	img, err := decode(bytes.NewReader(data))
	if err != nil {
		return "", nil, image.Rectangle{}, errLogoFormat
	}
	var out bytes.Buffer
	if err := encode(&out, img); err != nil {
		return "", nil, image.Rectangle{}, err
	}
	return contentType, out.Bytes(), img.Bounds(), nil
}
