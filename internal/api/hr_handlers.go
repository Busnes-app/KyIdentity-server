package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func decodeHR(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return errors.New("one JSON object required")
	}
	return nil
}

func (s *Server) configureHR(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SystemID       string `json:"systemId"`
		Domain         string `json:"domain"`
		WritebackURL   string `json:"writebackUrl"`
		WritebackToken string `json:"writebackToken"`
	}
	if decodeHR(r, &req) != nil {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	id := r.PathValue("id")
	actor := GetUserFromContext(r.Context())
	c := store.HRConnection{ConnectorID: id, SystemID: req.SystemID, Domain: req.Domain, WritebackURL: req.WritebackURL}
	pending := s.audit.Prepare("admin.hr_configured", actor.ID, actor.Username, id, "scim_connector", s.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := s.syncEngine.ConfigureHR(orgStore(r), c, req.WritebackToken, pending.Row); err != nil {
		if auditErr := s.audit.Record("admin.hr_configured", actor.ID, actor.Username, id, "scim_connector", s.middleware.ClientIP(r), r.UserAgent(), "failure", nil); auditErr != nil {
			http.Error(w, `{"error":"internal_error"}`, 500)
			return
		}
		http.Error(w, `{"error":"invalid_hr_configuration"}`, 400)
		return
	}
	pending.Committed()
	writeSuccess(w)
}

func (s *Server) hrStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Another org's connector answers as a missing one does.
	if conn, err := orgStore(r).GetSCIMConnector(id); err != nil {
		writeInputError(w, "internal_error", err)
		return
	} else if conn == nil {
		http.NotFound(w, r)
		return
	}
	c, err := s.store.HRConnection(id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			http.Error(w, `{"error":"invalid_offset"}`, 400)
			return
		}
		offset = n
	}
	workers, err := s.store.ListHRWorkers(id, offset)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	writeGroupJSON(w, map[string]any{"connection": c, "workers": workers, "offset": offset})
}

func (s *Server) importHR(w http.ResponseWriter, r *http.Request) {
	var req struct {
		store.HRInput
		Active *bool `json:"active"`
	}
	if decodeHR(r, &req) != nil || req.Active == nil {
		http.Error(w, `{"error":"invalid_employee"}`, 400)
		return
	}
	req.HRInput.Active = *req.Active
	c := scimConnector(r)
	pending := s.audit.Prepare("hr.employee_imported", c.ID, "hr-connector", "", "hr_worker", s.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	worker, err := s.store.ImportHR(c.ID, req.HRInput, pending.Row)
	if err != nil {
		if auditErr := s.audit.Record("hr.employee_imported", c.ID, "hr-connector", "", "hr_worker", s.middleware.ClientIP(r), r.UserAgent(), "failure", nil); auditErr != nil {
			http.Error(w, `{"error":"internal_error"}`, 500)
			return
		}
		if errors.Is(err, store.ErrHRConflict) {
			http.Error(w, `{"error":"hr_conflict"}`, 409)
			return
		}
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	pending.Committed()
	writeGroupJSON(w, worker)
}

func (s *Server) readHR(w http.ResponseWriter, r *http.Request) {
	worker, err := s.store.HRWorker(scimConnector(r).ID, r.URL.Query().Get("sourceUid"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	writeGroupJSON(w, worker)
}
