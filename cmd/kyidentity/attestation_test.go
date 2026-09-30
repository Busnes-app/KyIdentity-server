package main

import (
	"errors"
	"testing"

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
