package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func TestRequireLockedBootloaderFailsClosed(t *testing.T) {
	warned := 0
	warn := func(string, ...any) { warned++ }
	bad := requireLockedBootloader(func() (store.AttestationSettings, error) { return store.AttestationSettings{}, errors.New("db down") }, warn)
	if !bad() || warned != 1 {
		t.Fatalf("read error must require locked and warn once: warned=%d", warned)
	}
	for _, want := range []bool{true, false} {
		f := requireLockedBootloader(func() (store.AttestationSettings, error) {
			return store.AttestationSettings{RequireLockedBootloader: want}, nil
		}, warn)
		if f() != want {
			t.Fatalf("stored value %v not honoured", want)
		}
	}
	if warned != 1 {
		t.Fatalf("successful reads must not warn: %d", warned)
	}
}

func TestSweepRequireLocked(t *testing.T) {
	var warned string
	warn := func(f string, _ ...any) { warned = f }
	if sweepRequireLocked(func() (store.AttestationSettings, error) { return store.AttestationSettings{}, errors.New("db down") }, warn) {
		t.Fatal("read error must skip the bootloader check")
	}
	if warned == "" {
		t.Fatal("read error must be logged")
	}
	for _, want := range []bool{true, false} {
		got := sweepRequireLocked(func() (store.AttestationSettings, error) {
			return store.AttestationSettings{RequireLockedBootloader: want}, nil
		}, warn)
		if got != want {
			t.Fatalf("want %v got %v", want, got)
		}
	}
}

func TestRunAttestationHousekeeping(t *testing.T) {
	now := time.Now()
	var refreshed, swept int
	refresh, sweep := func() { refreshed++ }, func() { swept++ }

	last := runAttestationHousekeeping(now, now.Add(-time.Hour), true, refresh, sweep)
	if refreshed != 1 || swept != 0 || !last.Equal(now.Add(-time.Hour)) {
		t.Fatalf("stale, sweep not due: refreshed=%d swept=%d", refreshed, swept)
	}
	last = runAttestationHousekeeping(now, now.Add(-time.Hour), false, refresh, sweep)
	if refreshed != 1 || swept != 0 || !last.Equal(now.Add(-time.Hour)) {
		t.Fatalf("fresh, sweep not due: refreshed=%d swept=%d", refreshed, swept)
	}
	last = runAttestationHousekeeping(now, now.Add(-24*time.Hour), false, refresh, sweep)
	if refreshed != 2 || swept != 1 || !last.Equal(now) {
		t.Fatalf("sweep due: refreshed=%d swept=%d last=%v", refreshed, swept, last)
	}
	if last = runAttestationHousekeeping(now, time.Time{}, true, refresh, sweep); refreshed != 3 || swept != 2 || !last.Equal(now) {
		t.Fatalf("first run: refreshed=%d swept=%d", refreshed, swept)
	}
}

func TestHTTPFetchRefusesRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("[]")) }))
	defer target.Close()
	redirect := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer redirect.Close()
	if _, _, err := httpFetch(redirect.URL); err == nil || !strings.Contains(err.Error(), "status 302") {
		t.Fatalf("redirect followed: %v", err)
	}
	if body, _, err := httpFetch(target.URL); err != nil || string(body) != "[]" {
		t.Fatalf("direct fetch: %q %v", body, err)
	}
}
