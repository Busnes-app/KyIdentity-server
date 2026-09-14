package sync

import (
	"context"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/mail"
	"github.com/Busness-app/kysignon-server/internal/store"
)

// A stuck relay costs the alert goroutine one pass budget, never the dispatcher: the
// pass returns at its deadline with the rest of the mail still pending.
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
	alertPassBudget = 100 * time.Millisecond
	alertSender = func(*mail.Settings) func(string, string, string) error {
		return func(string, string, string) error { time.Sleep(80 * time.Millisecond); return nil }
	}
	start := time.Now()
	e.runAlerts(context.Background())
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Fatal("pass ran past its budget:", took)
	}
	alerts, _, err := db.ListAlerts("open", 10, 0)
	if err != nil || len(alerts) != 3 {
		t.Fatal(alerts, err)
	}
	pending := 0
	for _, a := range alerts {
		pending += a.Delivery.Pending
	}
	if pending == 0 || pending == 3 {
		t.Fatal("some mail should have gone out and the rest stay pending:", pending)
	}
}
