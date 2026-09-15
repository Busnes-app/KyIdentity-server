package api

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/Busness-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// maxIconBytes bounds an uploaded launcher icon. Icons draw at 20px; anything larger than
// this is a photo, and every signed-in user downloads every icon on the launcher.
const maxIconBytes = 128 << 10

// iconAllowed accepts a built-in icon name or "icon:<id>" for an upload that exists.
func (h *AdminHandler) iconAllowed(name string) bool {
	if launcherIcons[name] {
		return true
	}
	id, ok := strings.CutPrefix(name, "icon:")
	if !ok {
		return false
	}
	icon, err := h.store.GetLauncherIcon(id)
	return err == nil && icon != nil
}

// dropIcon removes an upload once nothing names it. Best effort: an orphaned blob is
// wasted space, not a fault worth failing the admin's edit over, and the periodic
// DeleteOrphanedLauncherIcons sweep catches whatever this misses.
func (h *AdminHandler) dropIcon(name string) {
	if !strings.HasPrefix(name, "icon:") {
		return
	}
	if err := h.store.DeleteLauncherIconIfUnused(name); err != nil {
		log.Printf("icon %s cleanup failed: %v", name, err)
	}
}

// UploadIcon stores an image sent as the raw request body and returns the name a card uses
// to reference it. Bitmaps are accepted on their bytes, not the declared type. SVG goes
// through checkSVG. The sandboxing CSP on ServeIcon and the <img> render context are the
// control; the parse is the second lock, so a later header change does not open a hole.
func (h *AdminHandler) UploadIcon(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	data, err := io.ReadAll(io.LimitReader(r.Body, maxIconBytes+1))
	if err != nil || len(data) == 0 {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if len(data) > maxIconBytes {
		http.Error(w, `{"error":"invalid_request","error_description":"Icon must be 128 KiB or smaller"}`, http.StatusRequestEntityTooLarge)
		return
	}

	contentType, err := iconContentType(data, r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	icon := &store.LauncherIcon{ID: uuid.New().String(), ContentType: contentType, Data: data}
	if err := h.store.CreateLauncherIcon(icon); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	h.audit.Record("admin.icon_uploaded", admin.ID, admin.Username, icon.ID, "icon", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"contentType": contentType, "bytes": len(data),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"iconName": "icon:" + icon.ID})
}

// ServeIcon returns an uploaded icon to any signed-in user. The id is random, so the
// response never changes and can be cached for the session's lifetime and beyond.
func (h *AdminHandler) ServeIcon(w http.ResponseWriter, r *http.Request) {
	icon, err := h.store.GetLauncherIcon(r.PathValue("id"))
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if icon == nil {
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", icon.ContentType)
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	// An SVG opened directly is a document; this keeps it a picture.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	_, _ = w.Write(icon.Data)
}

func iconContentType(data []byte, declared string) (string, error) {
	switch sniffed := http.DetectContentType(data); sniffed {
	case "image/png", "image/jpeg", "image/webp":
		return sniffed, nil
	}
	if strings.HasPrefix(declared, "image/svg+xml") {
		if err := checkSVG(data); err != nil {
			return "", err
		}
		return "image/svg+xml", nil
	}
	return "", errors.New("Icon must be a PNG, JPEG, WebP, or SVG image")
}

// fetchesOutside reports whether CSS or a funcIRI attribute value reaches beyond the file:
// an @import, or a url() that is not a same-document fragment such as url(#gradient).
func fetchesOutside(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "@import") {
		return true
	}
	for rest := lower; ; {
		i := strings.Index(rest, "url(")
		if i < 0 {
			return false
		}
		rest = rest[i+4:]
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			return true
		}
		target := strings.Trim(strings.TrimSpace(rest[:end]), `"'`)
		if !strings.HasPrefix(target, "#") {
			return true
		}
		rest = rest[end:]
	}
}

// funcIRIAttrs are the presentation attributes that accept url(): each is a fetch unless it
// points at a fragment of this document.
var funcIRIAttrs = map[string]bool{"style": true, "fill": true, "stroke": true, "filter": true, "mask": true, "clip-path": true, "marker-start": true, "marker-mid": true, "marker-end": true, "cursor": true}

// checkSVG walks the document and rejects the ways an SVG can run or fetch: scripts,
// event handlers, animation, entities, processing instructions (an XSL stylesheet is a
// fetch), and any href, funcIRI attribute, or text that names a URL outside the file.
// Inline <style> stays because it is how logos colour themselves, but not if it fetches.
func checkSVG(data []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	root := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("SVG is not well-formed XML")
		}
		switch t := tok.(type) {
		case xml.ProcInst:
			return errors.New("SVG must not contain processing instructions")
		case xml.CharData:
			if fetchesOutside(string(t)) {
				return errors.New("SVG must not reference external resources")
			}
		case xml.Directive:
			if bytes.HasPrefix(bytes.TrimSpace(t), []byte("DOCTYPE")) && bytes.Contains(t, []byte("ENTITY")) {
				return errors.New("SVG must not declare entities")
			}
		case xml.StartElement:
			name := strings.ToLower(t.Name.Local)
			if !root {
				if name != "svg" {
					return errors.New("SVG must have an <svg> root element")
				}
				root = true
			}
			switch name {
			case "script", "foreignobject", "iframe", "embed", "object", "handler",
				"animate", "animatetransform", "animatemotion", "set", "discard":
				return errors.New("SVG must not contain <" + name + "> elements")
			}
			for _, attr := range t.Attr {
				attrName := strings.ToLower(attr.Name.Local)
				if strings.HasPrefix(attrName, "on") {
					return errors.New("SVG must not contain event handler attributes")
				}
				if attrName == "href" && !strings.HasPrefix(attr.Value, "#") && !strings.HasPrefix(attr.Value, "data:image/") {
					return errors.New("SVG must not reference external resources")
				}
				if funcIRIAttrs[attrName] && fetchesOutside(attr.Value) {
					return errors.New("SVG must not reference external resources")
				}
			}
		}
	}
	if !root {
		return errors.New("SVG is empty")
	}
	return nil
}
