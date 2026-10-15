package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func decodeAPIError(t *testing.T, rr *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	if !json.Valid(rr.Body.Bytes()) {
		t.Fatalf("error body is not JSON: %s", rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestErrorBodiesStayJSONAndKeepInternalsInside(t *testing.T) {
	quoted := `bad "value" \ here`
	rr := httptest.NewRecorder()
	writeAPIError(rr, http.StatusBadRequest, "invalid_request", quoted)
	if body := decodeAPIError(t, rr); body["error_description"] != quoted {
		t.Fatalf("description mangled: %q", body["error_description"])
	}

	rr = httptest.NewRecorder()
	writeInputError(rr, "invalid_request", store.InputError(quoted))
	if body := decodeAPIError(t, rr); rr.Code != http.StatusBadRequest || body["error_description"] != quoted {
		t.Fatalf("input refusal: %d %v", rr.Code, body)
	}

	rr = httptest.NewRecorder()
	writeInputError(rr, "invalid_request", errors.New(`UNIQUE constraint failed: users.username "secret-row"`))
	body := decodeAPIError(t, rr)
	if rr.Code != http.StatusInternalServerError || body["error"] != "internal_error" || strings.Contains(rr.Body.String(), "UNIQUE") || strings.Contains(rr.Body.String(), "secret-row") {
		t.Fatalf("internal error leaked: %d %s", rr.Code, rr.Body.String())
	}
}

// A validator message that quotes the caller's input once broke the concatenated JSON body.
func TestQuotedValidationErrorIsValidJSON(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	rr := adminRequest(t, srv, "POST", "/api/admin/clients", cookie,
		`{"clientName":"App","redirectUris":["https://app.test/cb"],"backchannelLogoutUri":"https://app.test/%zz"}`)
	body := decodeAPIError(t, rr)
	if rr.Code != http.StatusBadRequest || !strings.Contains(body["error_description"], `"%zz"`) {
		t.Fatalf("got %d %v", rr.Code, body)
	}
}

func TestCreateUserConflictIsOnlyForADuplicate(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	create := `{"username":"dana","email":"dana@example.test"}`
	if rr := adminRequest(t, srv, "POST", "/api/admin/users", cookie, create); rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	rr := adminRequest(t, srv, "POST", "/api/admin/users", cookie, create)
	if body := decodeAPIError(t, rr); rr.Code != http.StatusConflict || body["error"] != "user_exists" {
		t.Fatalf("duplicate: %d %v", rr.Code, body)
	}
}
