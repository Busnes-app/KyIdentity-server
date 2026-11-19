package store

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// Device codes need an enabled workstation app with the grant on, and an app holds at most
// maxPendingDeviceCodes live pending codes.
func TestCreateDeviceCodeGateAndCapacity(t *testing.T) {
	s, done := setupTestStore(t)
	defer done()
	if err := s.CreateWorkstationApp(&OAuthClient{ID: "ws", ClientName: "PCs"}, nil); err != nil {
		t.Fatal(err)
	}
	code := func(i int) *DeviceCode {
		return &DeviceCode{ID: fmt.Sprint("dc-", i), ClientID: "ws", DeviceCodeHash: fmt.Sprint("d", i), UserCodeHash: fmt.Sprint("u", i),
			Scope: "openid", Interval: DeviceCodeInterval, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	}
	if err := s.CreateDeviceCode(code(0)); !errors.Is(err, ErrDeviceGrantUnavailable) {
		t.Fatalf("grant off: %v", err)
	}
	if err := s.UpdateWorkstationApp("ws", true, 300, OfflineWindowDefault, nil); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < maxPendingDeviceCodes; i++ {
		d := code(i)
		if _, err := tx.Exec(`INSERT INTO device_codes(id,client_id,device_code_hash,user_code_hash,scope,ip_address,user_agent,interval_seconds,expires_at,created_at) VALUES(?,?,?,?,?,'','',5,?,?)`,
			d.ID, d.ClientID, d.DeviceCodeHash, d.UserCodeHash, d.Scope, d.ExpiresAt, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateDeviceCode(code(maxPendingDeviceCodes)); err != nil {
		t.Fatalf("last free slot: %v", err)
	}
	if err := s.CreateDeviceCode(code(maxPendingDeviceCodes + 1)); !errors.Is(err, ErrDeviceCodeCapacity) {
		t.Fatalf("over capacity: %v", err)
	}
	if err := s.UpdateWorkstationApp("ws", true, 60, OfflineWindowDefault, nil); err == nil {
		t.Fatal("a 60-second code lifetime was accepted")
	}
}
