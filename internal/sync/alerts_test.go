package sync

import (
	"context"
	"testing"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/mail"
	"github.com/Busness-app/kyidentity-server/internal/store"
)

// An expired budget prevents delivery; cancellation during a send leaves the rest
// pending. Neither assertion depends on database work beating a wall-clock timer.
func TestAlertPassReturnsAtItsBudget(t *testing.T) {
	e, db, admin, cleanup := setupSync(t)
	defer cleanup()
	if err := db.SetAlertSettings(store.AlertSettings{LoginFailureThreshold: 10, LoginFailureWindowSeconds: 600, Recipients: []string{admin.ID}}, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := db.RecordAuditEvent(&store.AuditEvent{ID: "ev" + string(rune('a'+i)), ActorUsername: "root", Action: "admin.scim_token_issued", TargetID: "c" + string(rune('a'+i)), TargetType: "scim_connector", Outcome: "success", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	oldSender, oldBudget := alertSender, alertPassBudget
	defer func() { alertSender, alertPassBudget = oldSender, oldBudget }()
	alertPassBudget = 0
	alertSender = func(*mail.Settings) func(string, string, string) error {
		return func(string, string, string) error {
			t.Fatal("sent mail after the pass budget expired")
			return nil
		}
	}
	e.runAlerts(context.Background())
	alerts, _, err := db.ListAlerts("open", 10, 0)
	if err != nil || len(alerts) != 3 {
		t.Fatal(alerts, err)
	}
	for _, a := range alerts {
		if a.Delivery.Pending != 1 || a.Delivery.Delivered != 0 {
			t.Fatalf("expired budget changed delivery state: %+v", a.Delivery)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	alertPassBudget = time.Hour
	sent := 0
	alertSender = func(*mail.Settings) func(string, string, string) error {
		return func(string, string, string) error {
			sent++
			cancel()
			return nil
		}
	}
	e.runAlerts(ctx)
	alerts, _, err = db.ListAlerts("open", 10, 0)
	if err != nil || len(alerts) != 3 {
		t.Fatal(alerts, err)
	}
	pending, delivered := 0, 0
	for _, a := range alerts {
		pending += a.Delivery.Pending
		delivered += a.Delivery.Delivered
	}
	if sent != 1 || delivered != 1 || pending != 2 {
		t.Fatalf("cancellation must leave the remaining mail pending: sent=%d delivered=%d pending=%d", sent, delivered, pending)
	}
}
