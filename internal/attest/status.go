package attest

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Status interface {
	// Revoked reports whether serialHex (lowercase, no leading zeros) is revoked or suspended, and
	// whether the answer is backed by a usable list at all.
	Revoked(serialHex string) (revoked bool, known bool)
}

type StatusList struct {
	mu       sync.RWMutex
	url      string
	fetch    func(url string) ([]byte, http.Header, error)
	disabled bool
	entries  map[string]struct{}
	loadedAt time.Time
	maxAge   time.Duration
}

func NewStatusList(url string, fetch func(string) ([]byte, http.Header, error)) *StatusList {
	return &StatusList{url: url, fetch: fetch, disabled: url == "", maxAge: 24 * time.Hour}
}

func (s *StatusList) Refresh() error {
	if s.disabled {
		return nil
	}
	body, hdr, err := s.fetch(s.url)
	if err != nil {
		return err
	}
	var doc struct {
		Entries map[string]struct {
			Status string `json:"status"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}
	if doc.Entries == nil {
		return errors.New("status list without entries")
	}
	set := make(map[string]struct{}, len(doc.Entries))
	for serial, e := range doc.Entries {
		if e.Status == "REVOKED" || e.Status == "SUSPENDED" {
			set[strings.ToLower(strings.TrimLeft(serial, "0"))] = struct{}{}
		}
	}
	maxAge := 24 * time.Hour
	for _, part := range strings.Split(hdr.Get("Cache-Control"), ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "max-age="); ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				maxAge = time.Duration(n) * time.Second
			}
		}
	}
	s.mu.Lock()
	s.entries, s.loadedAt, s.maxAge = set, time.Now(), maxAge
	s.mu.Unlock()
	return nil
}

func (s *StatusList) Stale() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.entries == nil || time.Since(s.loadedAt) > s.maxAge
}

func (s *StatusList) Revoked(serialHex string) (bool, bool) {
	if s.disabled {
		return false, true // check disabled by the operator: every serial is "known good"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.entries == nil || time.Since(s.loadedAt) > 3*s.maxAge {
		return false, false // never loaded, or too old to trust; Verify does not fetch
	}
	_, hit := s.entries[strings.ToLower(strings.TrimLeft(serialHex, "0"))]
	return hit, true
}
