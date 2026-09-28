package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/Busnes-app/ky-primitives/health"
	"github.com/Busnes-app/ky-primitives/logging"
	"github.com/Busnes-app/kyidentity-server/internal/config"
)

var auditUnavailable = health.DeclareReason("append_disabled")

func (s *Server) healthHandler() http.Handler {
	lg, err := logging.New(logging.Config{App: "kyidentity"})
	if err != nil {
		panic(err) // The fixed app name is validated at startup.
	}
	return health.Handler("kyidentity", lg,
		health.Check{Name: "database", Run: s.store.PingContext},
		health.Check{Name: "signing_key", Run: func(context.Context) error {
			if s.keyManager == nil || len(s.keyManager.GetJWKS().Keys) == 0 {
				return errors.New("missing signing key")
			}
			return nil
		}},
		health.Check{Name: "encryption_key", Run: func(context.Context) error {
			if len(s.cfg.EncryptionKey) != config.KeyLength {
				return errors.New("missing encryption key")
			}
			return nil
		}},
		health.Check{Name: "audit", Run: func(context.Context) error {
			if degraded, _, _, _ := s.audit.Health(); degraded {
				return health.Degrade(auditUnavailable)
			}
			return nil
		}},
	)
}
