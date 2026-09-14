package api

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Busness-app/kysignon-server/internal/audit"
	"github.com/Busness-app/kysignon-server/internal/config"
	"github.com/Busness-app/kysignon-server/internal/crypto"
	"github.com/Busness-app/kysignon-server/internal/mfa"
	"github.com/Busness-app/kysignon-server/internal/oauth"
	"github.com/Busness-app/kysignon-server/internal/store"
	"github.com/Busness-app/kysignon-server/internal/sync"
)

type Server struct {
	adminRoutes []adminRoute
	cfg         *config.Config
	store       *store.Store
	keyManager  *crypto.JWTKeyManager
	syncEngine  *sync.Engine
	mfaEngine   *mfa.Engine
	oauthEngine *oauth.Engine
	audit       *audit.Logger
	middleware  *MiddlewareManager
	httpServer  *http.Server
	staticFS    fs.FS
}

func NewServer(
	cfg *config.Config,
	s *store.Store,
	km *crypto.JWTKeyManager,
	syncEngine *sync.Engine,
	mfaEngine *mfa.Engine,
	oauthEngine *oauth.Engine,
	auditLogger *audit.Logger,
	staticFS fs.FS,
) *Server {
	mm := NewMiddlewareManager(s, cfg.TrustedProxyCIDRs, cfg.ForwardedHeader, cfg.SecretKey)
	if cfg.SessionIdleTTL > 0 {
		mm.sessionIdleTTL = cfg.SessionIdleTTL
	}

	srv := &Server{
		cfg:         cfg,
		store:       s,
		keyManager:  km,
		syncEngine:  syncEngine,
		mfaEngine:   mfaEngine,
		oauthEngine: oauthEngine,
		audit:       auditLogger,
		middleware:  mm,
		staticFS:    staticFS,
	}

	mux := srv.routes()

	// Order matters: cap the body before any handler reads it, then headers, then CSRF.
	handler := limitRequestBody(mm.SecurityHeaders(mm.CSRFValidate(mux)))

	srv.httpServer = &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: handler,
		// Without these a single idle connection can be held open indefinitely.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return srv
}

// maxRequestBody caps any single request body. Every handler here decodes small JSON
// documents; nothing legitimate approaches this.
const maxRequestBody = 256 << 10 // 256 KiB

func limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()

	authH := NewAuthHandler(s.store, s.mfaEngine, s.audit, s.middleware, s.cfg.SecureCookies)
	if s.cfg.SessionTTL > 0 {
		authH.sessionTTL = s.cfg.SessionTTL
	}
	devH := NewDeviceHandler(s.store, s.mfaEngine, s.audit, s.middleware, s.cfg.IssuerURL)
	adminH := NewAdminHandler(s.store, s.syncEngine, s.audit, s.middleware, s.cfg.IssuerURL)
	onboardH := NewOnboardingHandler(s.store, s.audit, s.middleware, s.cfg.IssuerURL, s.cfg.EncryptionKey)
	scimH := NewSCIMHandler(s.store, s.audit, s.middleware, s.cfg.IssuerURL)
	sessH := NewSessionHandler(s.store, s.audit, s.middleware)
	oauthH := NewOAuthHandler(s.store, s.oauthEngine, s.audit, s.middleware)
	backupH := NewBackupHandler(s.cfg, s.store, s.audit, s.middleware)
	webauthnH := NewWebAuthnHandler(s.store, s.audit, s.mfaEngine, s.middleware, s.cfg.RPID, s.cfg.Origin)

	// Liveness: this process is running and can serve a request. Nothing more is claimed,
	// which is the only honest thing a liveness probe can say.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "alive"})
	})

	// Readiness: this instance can actually authenticate someone. A load balancer that keeps
	// sending logins to a server whose database has gone read-only, because the server said
	// "healthy" from a goroutine that only encodes JSON, is the failure this separates out.
	mux.HandleFunc("GET /readyz", s.readiness)

	// OIDC Discovery & JWKS
	mux.HandleFunc("GET /.well-known/openid-configuration", oauthH.OIDCConfiguration)
	mux.HandleFunc("GET /.well-known/jwks.json", oauthH.JWKS)

	// Auth Endpoints
	mux.HandleFunc("GET /api/auth/csrf", authH.GetCSRFToken)
	mux.Handle("POST /api/auth/login", s.middleware.RateLimit("login", 10, 0.2)(http.HandlerFunc(authH.Login)))
	mux.Handle("POST /api/auth/activate", s.middleware.RateLimit("account_link", 10, 0.2)(onboardH.Redeem("activation")))
	mux.Handle("POST /api/auth/password/reset", s.middleware.RateLimit("account_link", 10, 0.2)(onboardH.Redeem("reset")))
	mux.Handle("POST /api/auth/password/forgot", s.middleware.RateLimit("password_forgot", 5, 0.05)(http.HandlerFunc(onboardH.Forgot)))
	mux.Handle("POST /api/auth/mfa/totp/verify", s.middleware.RateLimit("mfa", 10, 0.2)(http.HandlerFunc(authH.VerifyTOTP)))
	mux.Handle("POST /api/auth/mfa/recovery/verify", s.middleware.RateLimit("mfa", 5, 0.1)(http.HandlerFunc(authH.VerifyRecoveryCode)))
	mux.Handle("POST /api/auth/mfa/push/poll", s.middleware.RateLimit("push_poll", 120, 2.0)(http.HandlerFunc(authH.PollPushChallenge)))
	mux.Handle("POST /api/auth/mfa/push/finish", s.middleware.RateLimit("mfa", 10, 0.2)(http.HandlerFunc(authH.FinishPushLogin)))
	mux.Handle("POST /api/mfa/push/respond", s.middleware.RateLimit("push_respond", 15, 0.5)(http.HandlerFunc(authH.RespondPush)))
	mux.Handle("POST /api/auth/mfa/webauthn/begin", s.middleware.RateLimit("mfa", 10, 0.2)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webauthnH.BeginLogin(w, r, authH)
	})))
	mux.Handle("POST /api/auth/mfa/webauthn/verify", s.middleware.RateLimit("mfa", 10, 0.2)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webauthnH.FinishLogin(w, r, authH)
	})))

	// Native device routes authenticate with a short-lived pairing token or enrolled device key.
	mux.Handle("POST /api/notifications/native/register", s.middleware.RateLimit("device_reg", 10, 0.2)(http.HandlerFunc(devH.RegisterNativeDevice)))
	mux.Handle("PUT /api/notifications/native/devices/{id}/push-token", s.middleware.RateLimit("push_token", 10, 0.2)(http.HandlerFunc(devH.RefreshNativeDevicePushToken)))

	// Authenticated User Routes
	authM := s.middleware.RequireAuth
	mux.Handle("POST /api/auth/logout", authM(http.HandlerFunc(authH.Logout)))
	mux.Handle("GET /api/auth/me", authM(http.HandlerFunc(authH.Me)))
	mux.Handle("POST /api/auth/step-up", authM(s.middleware.RateLimit("step_up", 10, 0.2)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { authH.RequestStepUp(w, r, webauthnH) }))))
	mux.Handle("GET /api/auth/step-up/methods", authM(http.HandlerFunc(authH.StepUpMethods)))
	mux.Handle("POST /api/auth/step-up/finish", authM(s.middleware.RateLimit("step_up_finish", 120, 2)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { authH.FinishStepUp(w, r, webauthnH) }))))
	mux.Handle("POST /api/auth/step-up/cancel", authM(http.HandlerFunc(authH.CancelStepUp)))

	mux.Handle("POST /api/user/devices/pairing-token", authM(http.HandlerFunc(devH.GenerateDevicePairingToken)))
	mux.Handle("GET /api/user/devices", authM(http.HandlerFunc(devH.ListUserDevices)))
	mux.Handle("DELETE /api/user/devices/{id}", authM(http.HandlerFunc(devH.DeleteUserDevice)))
	mux.Handle("PUT /api/notifications/native/devices/{id}/mfa", authM(http.HandlerFunc(devH.SetDeviceMFAApprover)))

	mux.Handle("POST /api/user/mfa/totp/setup", authM(http.HandlerFunc(devH.SetupTOTP)))
	mux.Handle("POST /api/user/mfa/totp/enable", authM(http.HandlerFunc(devH.EnableTOTP)))
	mux.Handle("POST /api/user/recovery-codes", authM(http.HandlerFunc(devH.GenerateRecoveryCodes)))
	mux.Handle("POST /api/user/password", authM(s.requireStepUp(http.HandlerFunc(onboardH.ChangePassword))))
	mux.Handle("GET /api/user/applications", authM(http.HandlerFunc(devH.ListApplications)))
	mux.Handle("GET /api/user/sessions", authM(http.HandlerFunc(sessH.ListOwn)))
	mux.Handle("DELETE /api/user/sessions/{id}", authM(http.HandlerFunc(sessH.RevokeOwn)))
	mux.Handle("POST /api/user/sessions/revoke-others", authM(http.HandlerFunc(sessH.RevokeOthers)))

	mux.Handle("POST /api/user/passkeys/register/begin", authM(s.middleware.RateLimit("passkey_enrol", 10, 0.2)(http.HandlerFunc(webauthnH.BeginRegistration))))
	mux.Handle("POST /api/user/passkeys/register/finish", authM(s.middleware.RateLimit("passkey_enrol", 10, 0.2)(http.HandlerFunc(webauthnH.FinishRegistration))))
	mux.Handle("GET /api/user/passkeys", authM(http.HandlerFunc(webauthnH.ListPasskeys)))
	mux.Handle("DELETE /api/user/passkeys/{id}", authM(http.HandlerFunc(webauthnH.DeletePasskey)))

	// OAuth & OIDC. OptionalAuth is the same session check RequireAuth uses, so an
	// expired session cannot authorise an SSO redirect.
	mux.HandleFunc("GET /api/auth/authorization/{id}", oauthH.InteractionDetails)
	mux.Handle("POST /api/auth/authorization/cancel", s.middleware.RateLimit("authorization_cancel", 20, 1)(http.HandlerFunc(oauthH.CancelInteraction)))
	mux.Handle("GET /oauth/authorize", s.middleware.OptionalAuth(http.HandlerFunc(oauthH.Authorize)))
	mux.Handle("GET /oauth/logout", s.middleware.OptionalAuth(s.middleware.RateLimit("oauth_logout", 30, 1.0)(http.HandlerFunc(oauthH.EndSession))))
	mux.Handle("POST /oauth/logout", s.middleware.OptionalAuth(s.middleware.RateLimit("oauth_logout", 30, 1.0)(http.HandlerFunc(oauthH.EndSession))))
	mux.Handle("POST /oauth/token", s.middleware.RateLimit("oauth_token", 30, 1.0)(http.HandlerFunc(oauthH.Token)))
	mux.Handle("GET /oauth/userinfo", s.middleware.RateLimit("oauth_userinfo", 120, 2.0)(http.HandlerFunc(oauthH.Userinfo)))
	mux.Handle("POST /oauth/revoke", s.middleware.RateLimit("oauth_revoke", 30, 1.0)(http.HandlerFunc(oauthH.Revoke)))

	// Admin routes: every one names its permission and whether it spends a step-up grant.
	//
	// Destructive and secret-bearing routes additionally spend a step-up grant. "Is this
	// session an admin" is the wrong question for creating an administrator, resetting
	// someone else's MFA, rotating a client secret, or exporting recovery material: a
	// stolen cookie answers it. The grant costs the password plus an enrolled factor,
	// binds to this session and operation, and authorizes exactly one change.
	s.adminRoutes = []adminRoute{
		{"GET", "/api/admin/enrollment-policies", permRead, false, http.HandlerFunc(adminH.ListEnrollmentPolicies)},
		{"POST", "/api/admin/enrollment-policies/preview", permAdmin, false, http.HandlerFunc(adminH.PreviewEnrollmentPolicy)},
		{"PUT", "/api/admin/enrollment-policies", permAdmin, true, http.HandlerFunc(adminH.SetEnrollmentPolicy)},
		{"GET", "/api/admin/groups", permDirectory, false, http.HandlerFunc(adminH.ListGroups)},
		{"POST", "/api/admin/groups", permAdmin, true, http.HandlerFunc(adminH.CreateGroup)},
		{"PUT", "/api/admin/groups/{id}", permAdmin, true, http.HandlerFunc(adminH.UpdateGroup)},
		{"DELETE", "/api/admin/groups/{id}", permAdmin, true, http.HandlerFunc(adminH.DeleteGroup)},
		{"GET", "/api/admin/groups/{id}/members", permDirectory, false, http.HandlerFunc(adminH.ListGroupUsers)},
		{"PUT", "/api/admin/groups/{id}/members/{userId}", permAdmin, true, http.HandlerFunc(adminH.SetGroupMembership)},
		{"DELETE", "/api/admin/groups/{id}/members/{userId}", permAdmin, true, http.HandlerFunc(adminH.SetGroupMembership)},
		{"GET", "/api/admin/users", permDirectory, false, http.HandlerFunc(adminH.ListUsers)},
		{"POST", "/api/admin/users", permAdmin, true, http.HandlerFunc(adminH.CreateUser)},
		{"PUT", "/api/admin/users/{id}", permAdmin, true, http.HandlerFunc(adminH.UpdateUser)},
		{"POST", "/api/admin/users/{id}/reset-mfa", permRecovery, true, http.HandlerFunc(adminH.ResetUserMFA)},
		{"POST", "/api/admin/users/{id}/revoke-sessions", permRecovery, false, http.HandlerFunc(adminH.RevokeUserSessions)},
		{"GET", "/api/admin/users/{id}/sessions", permUserRead, false, http.HandlerFunc(sessH.AdminList)},
		{"DELETE", "/api/admin/users/{id}/sessions/{sid}", permRecovery, false, http.HandlerFunc(sessH.AdminRevokeSession)},
		{"POST", "/api/admin/users/{id}/apps/{clientId}/revoke", permRecovery, false, http.HandlerFunc(sessH.AdminRevokeApp)},
		{"POST", "/api/admin/users/{id}/logouts/{deliveryId}/retry", permRecovery, false, http.HandlerFunc(sessH.AdminRetryLogout)},
		{"GET", "/api/admin/users/{id}/offboarding", permUserRead, false, http.HandlerFunc(adminH.UserOffboarding)},
		{"POST", "/api/admin/users/{id}/activation-link", permRecovery, true, onboardH.AdminIssueLink("activation")},
		{"POST", "/api/admin/users/{id}/reset-link", permRecovery, true, onboardH.AdminIssueLink("reset")},
		{"GET", "/api/admin/app-registry/{id}/roles", permAppRead, false, http.HandlerFunc(adminH.ListAppRoles)},
		{"POST", "/api/admin/app-registry/{id}/roles", permAppGrants, true, http.HandlerFunc(adminH.CreateAppRole)},
		{"DELETE", "/api/admin/app-registry/{id}/roles/{roleId}", permAppGrants, true, http.HandlerFunc(adminH.DeleteAppRole)},
		{"PUT", "/api/admin/app-registry/{id}/roles/{roleId}/assignments/{kind}/{principal}", permAppGrants, true, http.HandlerFunc(adminH.SetAppRoleAssignment)},
		{"DELETE", "/api/admin/app-registry/{id}/roles/{roleId}/assignments/{kind}/{principal}", permAppGrants, true, http.HandlerFunc(adminH.SetAppRoleAssignment)},
		{"PUT", "/api/admin/app-registry/{id}/claims", permAdmin, true, http.HandlerFunc(adminH.SetAppClaimSettings)},
		{"GET", "/api/admin/scim-connectors", permRead, false, http.HandlerFunc(scimH.AdminList)},
		{"POST", "/api/admin/scim-connectors", permAdmin, true, http.HandlerFunc(scimH.AdminCreate)},
		{"PUT", "/api/admin/scim-connectors/{id}", permAdmin, true, http.HandlerFunc(scimH.AdminUpdate)},
		{"POST", "/api/admin/scim-connectors/{id}/tokens", permAdmin, true, http.HandlerFunc(scimH.AdminIssueToken)},
		{"DELETE", "/api/admin/scim-connectors/{id}/tokens/{tokenId}", permAdmin, false, http.HandlerFunc(scimH.AdminRevokeToken)},
		{"DELETE", "/api/admin/scim-connectors/{id}", permAdmin, true, http.HandlerFunc(scimH.AdminDelete)},
		{"GET", "/api/admin/mail", permRead, false, http.HandlerFunc(onboardH.GetMail)},
		{"PUT", "/api/admin/mail", permAdmin, true, http.HandlerFunc(onboardH.PutMail)},
		{"POST", "/api/admin/mail/test", permAdmin, false, http.HandlerFunc(onboardH.TestMail)},
		{"DELETE", "/api/admin/users/{id}", permAdmin, true, http.HandlerFunc(adminH.DeleteUser)},
		{"GET", "/api/admin/systems/{id}/deliveries", permRead, false, http.HandlerFunc(adminH.ListSyncDeliveries)},
		{"POST", "/api/admin/systems/{id}/deliveries/{token}/read-back", permAdmin, false, http.HandlerFunc(adminH.ReadBackSyncDelivery)},
		{"POST", "/api/admin/systems/{id}/deliveries/{token}/resume", permAdmin, true, http.HandlerFunc(adminH.ResumeSyncDelivery)},
		{"GET", "/api/admin/systems/{id}/provisioning", permRead, false, http.HandlerFunc(adminH.ListProvisioningState)},
		{"POST", "/api/admin/systems/{id}/provisioning/{userId}/retry", permAdmin, false, http.HandlerFunc(adminH.RetryProvisioning)},
		{"GET", "/api/admin/systems/{id}/reconcile", permRead, false, http.HandlerFunc(adminH.ListReconcileJobs)},
		{"POST", "/api/admin/systems/{id}/reconcile/preview", permAdmin, false, adminH.startReconcile("preview")},
		{"POST", "/api/admin/systems/{id}/reconcile/repair", permAdmin, true, adminH.startReconcile("repair")},
		{"GET", "/api/admin/systems", permRead, false, http.HandlerFunc(adminH.ListPairedSystems)},
		{"PUT", "/api/admin/systems/{id}/connection", permAdmin, true, http.HandlerFunc(adminH.ConfigureSystem)},
		{"POST", "/api/admin/systems/{id}/test", permAdmin, false, http.HandlerFunc(adminH.TestSystem)},
		{"POST", "/api/admin/systems", permAdmin, true, http.HandlerFunc(adminH.CreatePairedSystem)},
		{"POST", "/api/admin/systems/{id}/resync", permAdmin, false, http.HandlerFunc(adminH.ResyncSystem)},
		{"DELETE", "/api/admin/systems/{id}", permAdmin, true, http.HandlerFunc(adminH.DeletePairedSystem)},
		{"GET", "/api/admin/clients", permRead, false, http.HandlerFunc(adminH.ListOAuthClients)},
		{"POST", "/api/admin/clients", permAdmin, true, http.HandlerFunc(adminH.CreateOAuthClient)},
		{"PUT", "/api/admin/clients/{id}", permAdmin, true, http.HandlerFunc(adminH.UpdateOAuthClient)},
		{"DELETE", "/api/admin/clients/{id}", permAdmin, true, http.HandlerFunc(adminH.DeleteOAuthClient)},
		{"PUT", "/api/admin/clients/{id}/launcher", permAdmin, false, http.HandlerFunc(adminH.UpdateClientLauncher)},
		{"GET", "/api/admin/app-registry/{id}/access-users", permAppRead, false, http.HandlerFunc(adminH.ListAppAccessUsers)},
		{"GET", "/api/admin/app-registry/{id}/access-groups", permAppRead, false, http.HandlerFunc(adminH.ListAppAccessGroups)},
		{"PUT", "/api/admin/app-registry/{id}/access-policy", permAdmin, true, http.HandlerFunc(adminH.SetAppPolicy)},
		{"PUT", "/api/admin/app-registry/{id}/assignments/{kind}/{principal}", permAppGrants, true, http.HandlerFunc(adminH.SetAppAssignment)},
		{"DELETE", "/api/admin/app-registry/{id}/assignments/{kind}/{principal}", permAppGrants, true, http.HandlerFunc(adminH.SetAppAssignment)},
		{"PUT", "/api/admin/app-registry/{id}/authentication-policy", permAdmin, true, http.HandlerFunc(adminH.SetAppAuthenticationPolicy)},
		{"GET", "/api/admin/app-registry", permDirectory, false, http.HandlerFunc(adminH.ListAppRecords)},
		{"POST", "/api/admin/app-registry/{id}/link", permAdmin, true, http.HandlerFunc(adminH.LinkAppRecords)},
		{"POST", "/api/admin/app-registry/{id}/unlink", permAdmin, true, http.HandlerFunc(adminH.UnlinkAppRecord)},
		{"GET", "/api/admin/applications", permRead, false, http.HandlerFunc(adminH.ListApplications)},
		{"POST", "/api/admin/applications", permAdmin, false, http.HandlerFunc(adminH.CreateApplication)},
		{"PUT", "/api/admin/applications/{id}", permAdmin, false, http.HandlerFunc(adminH.UpdateApplication)},
		{"DELETE", "/api/admin/applications/{id}", permAdmin, false, http.HandlerFunc(adminH.DeleteApplication)},
		{"POST", "/api/admin/icons", permAdmin, false, s.middleware.RateLimit("icon_upload", 20, 0.1)(http.HandlerFunc(adminH.UploadIcon))},
		{"GET", "/api/admin/audit-events", permRead, false, http.HandlerFunc(adminH.ListAuditEvents)},
		{"POST", "/api/admin/backup/drill", permAdmin, false, http.HandlerFunc(backupH.RunDrill)},
		{"GET", "/api/admin/backup/export-capsule", permAdmin, true, http.HandlerFunc(backupH.ExportCapsule)},
		{"POST", "/api/admin/backup/pair-remote", permAdmin, true, http.HandlerFunc(backupH.PairRemote)},
		{"POST", "/api/admin/backup/deposit", permAdmin, true, http.HandlerFunc(backupH.Deposit)},
		{"DELETE", "/api/admin/backup/pairing", permAdmin, true, http.HandlerFunc(backupH.Unpair)},
		{"POST", "/api/admin/backup/pin-key", permAdmin, true, http.HandlerFunc(backupH.PinKey)},
		{"PUT", "/api/admin/backup/schedule", permAdmin, true, http.HandlerFunc(backupH.SetSchedule)},
		{"GET", "/api/admin/backup/status", permRead, false, http.HandlerFunc(backupH.Status)},
		{"GET", "/api/admin/users/{id}/delegations", permAdmin, false, http.HandlerFunc(adminH.GetDelegations)},
		{"PUT", "/api/admin/users/{id}/delegations", permAdmin, true, http.HandlerFunc(adminH.SetDelegations)},
	}
	for _, rt := range s.adminRoutes {
		mux.Handle(rt.method+" "+rt.path, s.require(rt.perm, rt.stepUp, rt.h))
	}
	mux.Handle("GET /api/icons/{id}", authM(http.HandlerFunc(adminH.ServeIcon)))

	// Inbound SCIM: Bearer connector tokens only, never cookies. Discovery is readable
	// with any live token; Users need write scope to change anything.
	mux.Handle("GET /scim/v2/ServiceProviderConfig", scimH.Authenticate(false, scimH.ServiceProviderConfig))
	mux.Handle("GET /scim/v2/ResourceTypes", scimH.Authenticate(false, scimH.ResourceTypes))
	mux.Handle("GET /scim/v2/ResourceTypes/{id}", scimH.Authenticate(false, scimH.ResourceTypes))
	mux.Handle("GET /scim/v2/Schemas", scimH.Authenticate(false, scimH.Schemas))
	mux.Handle("GET /scim/v2/Schemas/{id}", scimH.Authenticate(false, scimH.Schemas))
	mux.Handle("GET /scim/v2/Users", scimH.Authenticate(false, scimH.List))
	mux.Handle("GET /scim/v2/Users/{id}", scimH.Authenticate(false, scimH.Get))
	mux.Handle("POST /scim/v2/Users", scimH.Authenticate(true, scimH.Create))
	mux.Handle("PUT /scim/v2/Users/{id}", scimH.Authenticate(true, scimH.Replace))
	mux.Handle("PATCH /scim/v2/Users/{id}", scimH.Authenticate(true, scimH.Patch))
	mux.Handle("DELETE /scim/v2/Users/{id}", scimH.Authenticate(true, scimH.Delete))
	mux.Handle("GET /scim/v2/Groups", scimH.Authenticate(false, scimH.ListGroups))
	mux.Handle("GET /scim/v2/Groups/{id}", scimH.Authenticate(false, scimH.GetGroup))
	mux.Handle("POST /scim/v2/Groups", scimH.Authenticate(true, scimH.CreateGroup))
	mux.Handle("PUT /scim/v2/Groups/{id}", scimH.Authenticate(true, scimH.ReplaceGroup))
	mux.Handle("PATCH /scim/v2/Groups/{id}", scimH.Authenticate(true, scimH.PatchGroup))
	mux.Handle("DELETE /scim/v2/Groups/{id}", scimH.Authenticate(true, scimH.DeleteGroup))

	// Static CSS & Fonts from filesystem if present
	cssDir := http.Dir("./css")
	mux.Handle("GET /css/", http.StripPrefix("/css/", http.FileServer(cssDir)))

	fontsDir := http.Dir("./fonts")
	mux.Handle("GET /fonts/", http.StripPrefix("/fonts/", http.FileServer(fontsDir)))

	// Explicit Favicon routes
	mux.HandleFunc("GET /favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if s.staticFS != nil {
			if data, err := fs.ReadFile(s.staticFS, "favicon.svg"); err == nil {
				_, _ = w.Write(data)
				return
			}
		}
		if data, err := os.ReadFile("web/dist/favicon.svg"); err == nil {
			_, _ = w.Write(data)
			return
		}
		_, _ = w.Write([]byte(defaultFaviconSVG))
	})

	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if s.staticFS != nil {
			if data, err := fs.ReadFile(s.staticFS, "favicon.ico"); err == nil {
				_, _ = w.Write(data)
				return
			}
			if data, err := fs.ReadFile(s.staticFS, "favicon.svg"); err == nil {
				_, _ = w.Write(data)
				return
			}
		}
		if data, err := os.ReadFile("web/dist/favicon.ico"); err == nil {
			_, _ = w.Write(data)
			return
		}
		_, _ = w.Write([]byte(defaultFaviconSVG))
	})

	// Static Frontend SPA fallback handler
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Check if requesting static asset file directly
		if s.staticFS != nil {
			f, err := s.staticFS.Open(strings.TrimPrefix(path, "/"))
			if err == nil {
				_ = f.Close()
				http.FileServer(http.FS(s.staticFS)).ServeHTTP(w, r)
				return
			}

			// SPA Fallback to index.html
			indexData, err := fs.ReadFile(s.staticFS, "index.html")
			if err == nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(indexData)
				return
			}
		}

		// Fallback to local web/dist or minimal placeholder
		if data, err := os.ReadFile(filepath.Join("web", "dist", "index.html")); err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(data)
			return
		}

		// Serve minimal SPA bootstrap
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(defaultIndexHTML))
	})

	return mux
}

func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

const defaultIndexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KySignOn — Identity & SSO</title>
    <link rel="stylesheet" href="/css/styles.css">
    <style>
        body { margin: 0; background: #0d0f14; color: #e2e8f0; font-family: 'Space Grotesk', sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .card { background: #161a22; border: 1px solid rgba(77, 238, 234, 0.2); border-radius: 8px; padding: 2rem; max-width: 480px; width: 90%; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }
        h1 { font-family: 'Space Grotesk', sans-serif; color: #4deeea; font-size: 1.5rem; margin-top: 0; }
        p { color: #94a3b8; font-size: 0.9rem; line-height: 1.5; }
        .badge { font-family: 'IBM Plex Mono', monospace; background: rgba(77, 238, 234, 0.1); color: #4deeea; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }
    </style>
</head>
<body>
    <div id="root">
        <div class="card">
            <h1>KySignOn Server</h1>
            <p>Single-Organization Identity & Account Replication Service.</p>
            <p><span class="badge">API READY</span> • Check <code>/healthz</code> or <code>/.well-known/openid-configuration</code>.</p>
        </div>
    </div>
</body>
</html>`

const defaultFaviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">
  <rect width="64" height="64" rx="14" fill="#0d0f14"/>
  <rect x="1" y="1" width="62" height="62" rx="13" stroke="#4deeea" stroke-opacity="0.3" stroke-width="1.5"/>
  <path d="M32 10 L48 16 V30 C48 41.5 41.2 50.2 32 54 C22.8 50.2 16 41.5 16 30 V16 L32 10 Z" fill="#121820" stroke="#4deeea" stroke-width="2.5" stroke-linejoin="round"/>
  <circle cx="32" cy="27" r="5.5" fill="#0d0f14" stroke="#4deeea" stroke-width="2"/>
  <path d="M32 32.5 V42 M29 42 H35" stroke="#4deeea" stroke-width="2.5" stroke-linecap="round"/>
  <circle cx="32" cy="27" r="2" fill="#4deeea"/>
</svg>`

// requireStepUp spends the step-up grant carried on this request before the handler runs.
//
// The grant is consumed up front rather than after the work: a grant that survives a failed
// attempt is a grant an attacker can retry with.
func (s *Server) requireStepUp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := consumeStepUp(s.store, r); err != nil {
			user := GetUserFromContext(r.Context())
			var actorID, actorName string
			if user != nil {
				actorID, actorName = user.ID, user.Username
			}
			s.audit.Record("admin.step_up_required", actorID, actorName, r.URL.Path, "endpoint",
				s.middleware.ClientIP(r), r.UserAgent(), "denied", map[string]any{"method": r.Method})
			writeStepUpError(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// readiness reports whether this instance can do its job, not merely whether it is running.
//
// It is unauthenticated, because a load balancer probe cannot hold a session, so it reports
// fixed verdicts and never the underlying error. The detail goes to the process log, where
// an operator can already see it and an anonymous caller cannot.
func (s *Server) readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	checks := map[string]string{}
	ready := true
	fail := func(name string, detail error) {
		checks[name] = "unavailable"
		ready = false
		log.Printf("readiness: %s unavailable: %v", name, detail)
	}

	// A bounded read against the table every login touches. A volume that has gone read-only
	// or vanished fails here rather than at the next sign-in.
	if err := s.store.PingContext(ctx); err != nil {
		fail("database", err)
	} else {
		checks["database"] = "ok"
	}

	// Key material is loaded once at start; without it no token can be issued and no stored
	// secret can be read, so serving traffic would only produce failed logins.
	if s.keyManager == nil || len(s.keyManager.GetJWKS().Keys) == 0 {
		fail("signing_key", errors.New("RSA signing key is not loaded"))
	} else {
		checks["signing_key"] = "ok"
	}
	if len(s.cfg.EncryptionKey) != config.KeyLength {
		fail("encryption_key", errors.New("deployment encryption key is missing or the wrong size"))
	} else {
		checks["encryption_key"] = "ok"
	}

	// A server still authenticating people while keeping no record of it is degraded, not
	// healthy. It is reported rather than fatal: pulling an identity provider out of rotation
	// over audit storage would trade an evidence gap for an outage.
	if degraded, failures, lastErr, _ := s.audit.Health(); degraded {
		checks["audit"] = "degraded"
		log.Printf("readiness: audit persistence degraded after %d consecutive failures: %s", failures, lastErr)
	} else {
		checks["audit"] = "ok"
	}

	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": map[bool]string{true: "ready", false: "not_ready"}[ready],
		"checks": checks,
	})
}
