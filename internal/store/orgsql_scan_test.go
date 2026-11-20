package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// sqlTableRef finds the tables a statement reads or writes.
var sqlTableRef = regexp.MustCompile(`(?i)\b(?:FROM|JOIN|INTO|UPDATE|TABLE|ON)\s+([a-z_]+)\b`)

// orgSQLUnit is one SQL text in the store: a string literal, or a chain of literals joined
// with +, the parts that are not literals standing in as "?".
type orgSQLUnit struct {
	decl, text string
	pos        token.Position
}

// orgSQLUnits returns every unit in the package's non-test files that names an org-owned
// table and not org_id, keyed by the declaration (function, method or package-level name)
// it is in.
func orgSQLUnits(t *testing.T) map[string][]orgSQLUnit {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	owned := map[string]bool{}
	for _, name := range orgOwnedTables {
		owned[name] = true
	}
	fset := token.NewFileSet()
	out := map[string][]orgSQLUnit{}
	scan := func(node ast.Node, name string) {
		ast.Inspect(node, func(n ast.Node) bool {
			e, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			text, ok := sqlText(e)
			if !ok {
				return true
			}
			if strings.Contains(text, "org_id") {
				return false
			}
			for _, m := range sqlTableRef.FindAllStringSubmatch(text, -1) {
				if owned[strings.ToLower(m[1])] {
					out[name] = append(out[name], orgSQLUnit{name, text, fset.Position(e.Pos())})
					break
				}
			}
			return false
		})
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, file, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if g, ok := d.(*ast.GenDecl); ok {
				for _, spec := range g.Specs {
					if v, ok := spec.(*ast.ValueSpec); ok && len(v.Names) > 0 {
						scan(spec, v.Names[0].Name)
					}
				}
				continue
			}
			scan(d, declName(d))
		}
	}
	return out
}

func declName(d ast.Decl) string {
	f := d.(*ast.FuncDecl)
	if f.Recv != nil && len(f.Recv.List) > 0 {
		recv := f.Recv.List[0].Type
		if s, ok := recv.(*ast.StarExpr); ok {
			recv = s.X
		}
		if id, ok := recv.(*ast.Ident); ok {
			return id.Name + "." + f.Name.Name
		}
	}
	return f.Name.Name
}

// sqlText joins the literal parts of a string expression; ok is false for anything that
// holds no string literal.
func sqlText(e ast.Expr) (string, bool) {
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		l, lok := sqlText(e.X)
		r, rok := sqlText(e.Y)
		if !lok && !rok {
			return "", false
		}
		if !lok {
			l = " ? "
		}
		if !rok {
			r = " ? "
		}
		return l + r, true
	case *ast.ParenExpr:
		return sqlText(e.X)
	}
	return "", false
}

// Every store SQL text that names an org-owned table also names org_id, or its declaration
// is listed here with the reason it may not. Crude by design (the tenancy design's
// "Isolation enforcement"): a listed declaration may hold a scoped and an unscoped text.
func TestOrgSQLNamesOrgID(t *testing.T) {
	units := orgSQLUnits(t)
	for _, name := range slices.Sorted(maps.Keys(units)) {
		if _, ok := orgSQLAllowlist[name]; ok {
			continue
		}
		for _, u := range units[name] {
			t.Errorf("%s: %s names an org-owned table and not org_id: %.120q", u.pos, name, strings.Join(strings.Fields(u.text), " "))
		}
	}
	for name := range orgSQLAllowlist {
		if units[name] == nil {
			t.Errorf("orgSQLAllowlist[%q]: no unscoped SQL left there; remove the entry", name)
		}
	}
}

// orgSQLAllowlist: the declarations whose SQL may name an org-owned table without org_id.
// "pre-org" and "platform" entries stay; an entry naming a build plan step (2b, 2c, 2d,
// PR 3) goes when that step scopes it. The test fails on an entry with nothing left to allow.
var orgSQLAllowlist = map[string]string{
	"OrgStore.AcknowledgeAlert":                     "fragment: alertVisibleSQL binds the org (a.org_id=?)",
	"OrgStore.ListAlerts":                           "fragment: alertVisibleSQL binds the org (a.org_id=?)",
	"OrgStore.CountAuditEvents":                     "fragment: AuditFilter.where binds the org first",
	"OrgStore.SearchAuditEventsContext":             "fragment: AuditFilter.where binds the org first",
	"OrgStore.ConfigureHR":                          "keyed by a connector it first finds in the org",
	"OrgStore.DeleteSCIMConnector":                  "keyed by a connector it first finds in the org (requireOrgConnectorTx)",
	"PlatformStore.ClaimLogoutDelivery":             "platform: the back-channel delivery worker, over every org; each delivery carries its org_id",
	"PlatformStore.FinishLogoutDelivery":            "platform: the back-channel delivery worker, over every org; each delivery carries its org_id",
	"PlatformStore.DeleteLogoutDeliveriesOlderThan": "platform: retention over every org",
	"OrgStore.DecideAccessRequest":                  "the actor's own authority, read by the actor's ID; the request is found in the org first",
	"OrgStore.ExplainAccess":                        "keyed by a user it first finds in the org",
	"OrgStore.ListAccessRequests":                   "the actor's own authority, by the actor's ID; the rows are filtered by u.org_id",
	"PlatformStore.RunDueExpiries":                  "platform: the expiry sweep over every org, each user ended in its own org",
	"OrgStore.DeleteUserWithSyncEvents":             "keyed by the user it first finds in the org; its provisioning rows are the worker's",
	"PlatformStore.CountAdmins":                     "platform: the first-start bootstrap counts every org's administrators; only the default or staff org has any (D8)",
	"Store.ADGroupMembers":                          "platform: the AD connector (ad_connectors is platform) and its agent, over every org",
	"Store.ADPasswordBehind":                        "platform: the AD connector (ad_connectors is platform) and its agent, over every org",
	"Store.ADPasswordStatuses":                      "platform: the AD connector (ad_connectors is platform) and its agent, over every org",
	"Store.AccessEndsAt":                            "principal: the user a code, refresh family or device sign-on names, at token issuance",
	"Store.ApplyInstallerSetup":                     "installer: single-tenant only, its objects are in the default org",
	"Store.AuthenticateSCIMToken":                   "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"Store.ClaimDueSyncEvents":                      "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.ClaimHR":                                 "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"Store.ConsumeStepUpToken":                      "principal: keyed by the user a session, code, token or verified credential names (PR 4 names these checks credential_principals/active_principals)",
	"Store.CountSCIMConnectorGroups":                "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"Store.CountSCIMConnectorUsers":                 "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"Store.CreateAuthorizationCode":                 "principal: keyed by the user a session, code, token or verified credential names (PR 4 names these checks credential_principals/active_principals)",
	"Store.CreateMFAToken":                          "principal: keyed by the user a session, code, token or verified credential names (PR 4 names these checks credential_principals/active_principals)",
	"Store.CreateSessionForInteraction":             "principal: keyed by the user a session, code, token or verified credential names (PR 4 names these checks credential_principals/active_principals)",
	"Store.DeleteAlertsOlderThan":                   "platform: the alert worker over every org; each alert carries its org_id",
	"Store.DeleteAuditEventsOlderThan":              "platform: audit retention over every org",
	"Store.DeleteDeliveredSyncEvents":               "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.DeletePairedSystem":                      "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.DeleteSCIMLink":                          "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.DeleteUpstreamGroup":                     "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"Store.DeleteWebAuthnCredential":                "principal: the signed-in user's own passkey",
	"Store.DeliverAlerts":                           "platform: the alert worker over every org; each alert carries its org_id",
	"Store.ExportRecoveryEvidence":                  "platform: a paired system's recovery export (platform route)",
	"Store.FinishADPassword":                        "platform: the AD connector (ad_connectors is platform) and its agent, over every org",
	"Store.FinishHR":                                "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"Store.FinishSyncDelivery":                      "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.ForwardSessionFor":                       "principal: keyed by the user a session, code, token or verified credential names (PR 4 names these checks credential_principals/active_principals)",
	"Store.GetDueSyncEvents":                        "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.GetPendingSyncEvents":                    "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.GetUpstreamGroup":                        "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"Store.GetUpstreamUser":                         "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"Store.GetUserByEmail":                          "pre-org: forgot-password finds the principal by email (unique across orgs, D5)",
	"Store.GetUserByUsername":                       "pre-org: sign-in and operator commands find the principal by username (unique across orgs, D5)",
	"Store.ImportHR":                                "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"Store.InstallerSetupAdministrator":             "installer: single-tenant only, its objects are in the default org",
	"Store.IsTokenRevoked":                          "principal: keyed by the user a session, code, token or verified credential names (PR 4 names these checks credential_principals/active_principals)",
	"Store.LauncherAdminClients":                    "principal: the signed-in user's, or a suite call's sub (scoped in PR 3)",
	"Store.ListFailingSyncEvents":                   "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.ListProvisioningState":                   "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.ListSyncDeliveryAttempts":                "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.ListUpstreamGroups":                      "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"Store.ListUpstreamUsers":                       "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"Store.MarkSyncDeliveryUncertain":               "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.PingContext":                             "platform: the readiness probe reads one row of any org",
	"Store.PrincipalByID":                           "pre-org: the user a session, code, refresh family, MFA or step-up token, device sign-on or verified token names",
	"Store.QueueDirectoryPassword":                  "platform: the AD connector (ad_connectors is platform) and its agent, over every org",
	"Store.ReconcileDrift":                          "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.RedeemAccountToken":                      "pre-org: an account token found by its hash names the user",
	"startWorkstationSessionTx":                     "principal: keyed by the user a session, code, token or verified credential names (PR 4 names these checks credential_principals/active_principals)",
	"Store.RejectSCIMCreate":                        "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.ReleaseSyncEventLease":                   "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.ReplaceUpstreamGroup":                    "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"Store.ResumeSyncDeliveries":                    "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.ResumeSyncDelivery":                      "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.ResyncSystem":                            "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.RetryProvisioning":                       "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.SCIMGroupMembers":                        "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.SCIMLink":                                "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.SetEnrollmentPolicy":                     "platform: enrollment policies are platform-wide (D10)",
	"Store.SuiteGroupsFor":                          "PR 3: suite API scoping",
	"Store.SuitePeople":                             "PR 3: suite API scoping",
	"Store.SyncBacklog":                             "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.UpdateSyncEventStatus":                   "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.applyRestoredStateTx":                    "platform: a restore is the whole install",
	"Store.changeEnrollmentDevice":                  "platform: enrollment policies are platform-wide (D10)",
	"Store.evaluateBatch":                           "platform: the alert worker over every org; each alert carries its org_id",
	"Store.evaluateOutages":                         "platform: the alert worker over every org; each alert carries its org_id",
	"migrateOrgIDRequiredPostgres":                  "migration: lifts and restores the alerts org_id trigger around the platform-alert move",
	"Store.migrateAlerts":                           "migration: written before org_id existed",
	"Store.migrateAppAccess":                        "migration: written before org_id existed",
	"Store.migrateAuditIndexes":                     "migration: written before org_id existed",
	"Store.migrateEnrollmentPolicy":                 "migration: written before org_id existed",
	"Store.migrateInboundSCIM":                      "migration: written before org_id existed",
	"Store.migrateInboundSCIMGroups":                "migration: written before org_id existed",
	"Store.migrateLegacy":                           "migration: written before org_id existed",
	"Store.migrateLogoutDeliveries":                 "migration: written before org_id existed",
	"Store.migrateOnboarding":                       "migration: written before org_id existed",
	"Store.migratePasswordChangeRequired":           "migration: written before org_id existed",
	"Store.migrateProvisioning":                     "migration: written before org_id existed",
	"Store.migrateReconcile":                        "migration: written before org_id existed",
	"Store.migrateSyncDelivery":                     "migration: written before org_id existed",
	"Store.migrateSyncEventLease":                   "migration: written before org_id existed",
	"Store.migrateSyncEventsUserReference":          "migration: written before org_id existed",
	"Store.reconcileSyncEvents":                     "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.releaseFencesForRemovalsTx":              "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"Store.resolveQuietLoginAlerts":                 "platform: the alert worker over every org; each alert carries its org_id",
	"Store.workstationGroups":                       "principal: keyed by the user a session, code, token or verified credential names (PR 4 names these checks credential_principals/active_principals)",
	"accessRequestSelect":                           "fragment: OrgStore.ListAccessRequests adds u.org_id; DecideAccessRequest reads a request it found in the org",
	"alertReaderTx":                                 "platform: the alert worker over every org; each alert carries its org_id",
	"alertSelect":                                   "platform: the alert worker over every org; each alert carries its org_id",
	"appClaimsTx":                                   "keyed by a user ID its caller resolved: token claims of a principal",
	"auditSelect":                                   "fragment: AuditFilter.where binds the org",
	"bootstrapPasswordUnchangedSQL":                 "principal: the signed-in user's own password state",
	"classifyTx":                                    "platform: the alert worker over every org; each alert carries its org_id",
	"configureInstallerGroups":                      "installer: single-tenant only, its objects are in the default org",
	"createStepUpTokenTx":                           "principal: keyed by the user a session, code, token or verified credential names (PR 4 names these checks credential_principals/active_principals)",
	"deleteGroupTx":                                 "keyed by a group ID it first checks is in the org; the org of a row cannot change",
	"desiredGroupsTx":                               "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"externalGroupFreeTx":                           "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"forwardAccess":                                 "principal: keyed by the user a session, code, token or verified credential names (PR 4 names these checks credential_principals/active_principals)",
	"groupMembersTx":                                "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"membersOwnedTx":                                "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"offboardUserTx":                                "keyed by a user its caller resolved in the org",
	"pgSchemaV1":                                    "migration: the version-1 Postgres schema, before org_id existed",
	"prepareSyncDeliveryTx":                         "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"previewEnrollmentTx":                           "platform: enrollment policies are platform-wide (D10)",
	"provisionedTx":                                 "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"queueDesiredStateTx":                           "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"queueUserNotificationTx":                       "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"queueUserUpdateTx":                             "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"raiseAlertTx":                                  "platform: the alert worker over every org; each alert carries its org_id",
	"reconcileGroupsTx":                             "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"reconcileProvisioningTx":                       "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"recordIssuedTokenTx":                           "principal: keyed by the user a session, code, token or verified credential names (PR 4 names these checks credential_principals/active_principals)",
	"refreshSyncEventRolesTx":                       "platform: keyed by a queued event's user, in the provisioning worker",
	"rejectCrossIdentityTx":                         "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
	"releaseAttemptEventTx":                         "platform: the provisioning worker and its admin views (platform routes), over every org; their rows carry org_id",
	"requirePermanentAdminTx":                       "the last-administrator rule counts every org: only the default or staff org has administrators (D8)",
	"roleChangeTx":                                  "keyed by user IDs its caller resolved in the org",
	"uniqueSuiteSlugTx":                             "slugs stay unique across orgs: SQLite keeps the global unique (D2), and whether apps use the slug globally is unverified",
	"upstreamGroupColumns":                          "connector: keyed by the inbound connector its token names, whose org owns the rows (inbound SCIM and HR are off in multi-tenant v1)",
}

// The pre-org lookups find the principal that decides the org, and DefaultOrg binds the
// single-tenant org without one. Outside the store each call site is listed here, keyed
// "file:function", so a handler cannot reach a user by a request-chosen name or ID.
var preOrgCallers = map[string]string{
	"cmd/kyidentity/main.go:ensureBootstrapAdmin":                                "operator bootstrap; single-tenant, so its admin is in the default org",
	"cmd/kyidentity/main.go:clearFirstRunPasswordFile":                           "operator start-up: the first-run administrator, by username",
	"internal/api/alert_handlers.go:AlertHandler.PutSettings":                    "a recipient named by username must be in the caller's org (checked)",
	"internal/api/authorization_interactions.go:OAuthHandler.InteractionDetails": "the user bound to a pending authorization",
	"internal/api/auth_handlers.go:AuthHandler.Login":                            "sign-in",
	"internal/api/auth_handlers.go:AuthHandler.resolveMFAToken":                  "the user an MFA token names",
	"internal/api/onboarding_handlers.go:OnboardingHandler.Forgot":               "forgot-password",
	"internal/api/middleware.go:MiddlewareManager.authenticate":                  "the user a session names",
	"internal/api/suite_handlers.go:SuiteHandler.People":                         "a suite call's sub (scoped in build plan PR 3)",
	"internal/mfa/mfa.go:Engine.dispatchPushChallenge":                           "the user a push challenge names (display only)",
	"internal/oauth/oauth.go:Engine.ExchangeAuthorizationCode":                   "the user an authorization code names",
	"internal/oauth/oauth.go:Engine.ExchangeRefreshToken":                        "the user a refresh family names",
	"internal/oauth/oauth.go:Engine.GetUserinfo":                                 "a verified access token's sub",
	"internal/oauth/device_grant.go:Engine.PollDeviceCode":                       "the user an approved device code names",
	"internal/oauth/device_assertion.go:Engine.ExchangeDeviceAssertion":          "a device sign-on assertion's subject, after its JTI is spent",
}

func TestPreOrgCallers(t *testing.T) {
	preOrg := map[string]bool{"PrincipalByID": true, "GetUserByUsername": true, "GetUserByEmail": true, "DefaultOrg": true}
	seen := map[string]bool{}
	fset := token.NewFileSet()
	for _, dir := range []string{"../../cmd", "../../internal"} {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.HasPrefix(path, "../../internal/store/") {
				return err
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				key := strings.TrimPrefix(path, "../../") + ":" + declName(fn)
				ast.Inspect(fn, func(n ast.Node) bool {
					if sel, ok := n.(*ast.SelectorExpr); ok && preOrg[sel.Sel.Name] {
						seen[key] = true
						if _, ok := preOrgCallers[key]; !ok {
							t.Errorf("%s: %s calls %s; list it in preOrgCallers with its reason, or use the request's OrgStore", fset.Position(sel.Pos()), key, sel.Sel.Name)
						}
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for key := range preOrgCallers {
		if !seen[key] {
			t.Errorf("preOrgCallers[%q]: no such call left; remove the entry", key)
		}
	}
}
