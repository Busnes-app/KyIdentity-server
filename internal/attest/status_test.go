package attest

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func fetchOf(body string, cc string, err error) func(string) ([]byte, http.Header, error) {
	return func(string) ([]byte, http.Header, error) {
		h := http.Header{}
		if cc != "" {
			h.Set("Cache-Control", cc)
		}
		return []byte(body), h, err
	}
}

const listBody = `{"entries":{"0ABC":{"status":"REVOKED"},"def":{"status":"SUSPENDED"},"123":{"status":"OK"}}}`

func TestStatusListRefreshAndNormalisation(t *testing.T) {
	s := NewStatusList("https://x", fetchOf(listBody, "", nil))
	if _, known := s.Revoked("abc"); known {
		t.Fatal("unloaded list must be unknown")
	}
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	for serial, want := range map[string]bool{"abc": true, "ABC": true, "0abc": true, "def": true, "123": false, "999": false} {
		if rev, known := s.Revoked(serial); rev != want || !known {
			t.Errorf("%s: revoked=%v known=%v", serial, rev, known)
		}
	}
}

func TestStatusListDisabled(t *testing.T) {
	s := NewStatusList("", nil)
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	if rev, known := s.Revoked("abc"); rev || !known {
		t.Fatalf("revoked=%v known=%v", rev, known)
	}
}

func TestStatusListMaxAgeAndStaleness(t *testing.T) {
	s := NewStatusList("https://x", fetchOf(listBody, "public, max-age=60", nil))
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	if s.maxAge != time.Minute {
		t.Fatalf("maxAge %v", s.maxAge)
	}
	if s.Stale() {
		t.Fatal("fresh list reported stale")
	}
	s.loadedAt = time.Now().Add(-2 * time.Minute)
	if !s.Stale() {
		t.Fatal("list past max-age must be stale")
	}
	if _, known := s.Revoked("abc"); !known {
		t.Fatal("list within 3x max-age must still answer")
	}
	s.loadedAt = time.Now().Add(-4 * time.Minute)
	if _, known := s.Revoked("abc"); known {
		t.Fatal("list past 3x max-age must be unknown")
	}
}

func TestStatusListFailedRefreshKeepsPrevious(t *testing.T) {
	s := NewStatusList("https://x", fetchOf(listBody, "", nil))
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []func(string) ([]byte, http.Header, error){
		fetchOf("", "", errors.New("down")),
		fetchOf("not json", "", nil),
		fetchOf(`{}`, "", nil),
	} {
		s.fetch = f
		if s.Refresh() == nil {
			t.Fatal("expected error")
		}
		if rev, known := s.Revoked("abc"); !rev || !known {
			t.Fatalf("previous set lost: revoked=%v known=%v", rev, known)
		}
	}
}
