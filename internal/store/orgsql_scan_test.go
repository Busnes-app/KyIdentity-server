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
	"OrgStore.DecideAccessRequest":          "the actor's own authority, read by the actor's ID; the request is found in the org first",
	"OrgStore.ExplainAccess":                "keyed by a user it first finds in the org",
	"OrgStore.ListAccessRequests":           "the actor's own authority, by the actor's ID; the rows are filtered by u.org_id",
	"PlatformStore.RunDueExpiries":          "platform: the expiry sweep over every org, each user ended in its own org",
	"OrgStore.DeleteUserWithSyncEvents":     "2d: the deletion's provisioning rows (the user is checked in the org first)",
	"PlatformStore.CountAdmins":             "platform: the first-start bootstrap counts every org's administrators; only the default or staff org has any (D8)",
	"Store.ADGroupMembers":                  "2d: Active Directory connector",
	"Store.ADPasswordBehind":                "2d: Active Directory connector",
	"Store.ADPasswordStatuses":              "2d: Active Directory connector",
	"Store.AccessEndsAt":                    "principal: the user a code, refresh family or device sign-on names, at token issuance",
	"Store.AcknowledgeAlert":                "2d: alerts",
	"Store.ApplyInstallerSetup":             "installer: single-tenant only, its objects are in the default org",
	"Store.AuthenticateSCIMToken":           "2d: inbound SCIM",
	"Store.BeginSyncDelivery":               "2d: sync delivery",
	"Store.ChangePassword":                  "2c: account tokens",
	"Store.ClaimDueSyncEvents":              "2d: sync events",
	"Store.ClaimHR":                         "2d: HR provisioning",
	"Store.ClaimLogoutDelivery":             "2c: back-channel logout deliveries",
	"Store.ConfigureHR":                     "2d: HR provisioning",
	"Store.ConsumeStepUpToken":              "2c: step-up",
	"Store.CountAuditEvents":                "2d: audit",
	"Store.CountSCIMConnectorGroups":        "2d: inbound SCIM groups",
	"Store.CountSCIMConnectorUsers":         "2d: inbound SCIM",
	"Store.CreateAuthorizationCode":         "2c: authorization codes",
	"Store.CreateMFAToken":                  "2c: MFA tokens",
	"Store.CreateSCIMConnector":             "2d: inbound SCIM",
	"Store.CreateSessionForInteraction":     "2c: sessions",
	"Store.CreateUpstreamGroup":             "2d: inbound SCIM groups",
	"Store.CreateUpstreamUser":              "2d: inbound SCIM",
	"Store.DeleteAlertsOlderThan":           "2d: alerts",
	"Store.DeleteAuditEventsOlderThan":      "2d: audit retention",
	"Store.DeleteDeliveredSyncEvents":       "2d: sync events",
	"Store.DeleteLogoutDeliveriesOlderThan": "2c: back-channel logout deliveries",
	"Store.DeletePairedSystem":              "2d: sync events",
	"Store.DeleteSCIMConnector":             "2d: inbound SCIM",
	"Store.DeleteSCIMLink":                  "2d: outbound SCIM links",
	"Store.DeleteUpstreamGroup":             "2d: inbound SCIM groups",
	"Store.DeleteWebAuthnCredential":        "2c: passkeys",
	"Store.DeliverAlerts":                   "2d: alerts",
	"Store.ExportRecoveryEvidence":          "2d: provisioning recovery evidence",
	"Store.FinishADPassword":                "2d: Active Directory connector",
	"Store.FinishHR":                        "2d: HR provisioning",
	"Store.FinishLogoutDelivery":            "2c: back-channel logout deliveries",
	"Store.FinishSyncDelivery":              "2d: sync delivery",
	"Store.ForwardSessionFor":               "2c: forward-auth sessions",
	"Store.GetDueSyncEvents":                "2d: sync events",
	"Store.GetPendingSyncEvents":            "2d: sync events",
	"Store.GetSCIMConnector":                "2d: inbound SCIM",
	"Store.GetUpstreamGroup":                "2d: inbound SCIM groups",
	"Store.GetUpstreamUser":                 "2d: inbound SCIM",
	"Store.GetUserByEmail":                  "pre-org: forgot-password finds the principal by email (unique across orgs, D5)",
	"Store.GetUserByUsername":               "pre-org: sign-in and operator commands find the principal by username (unique across orgs, D5)",
	"Store.ImportHR":                        "2d: HR provisioning",
	"Store.InstallerSetupAdministrator":     "installer: single-tenant only, its objects are in the default org",
	"Store.IsTokenRevoked":                  "2c: issued tokens",
	"Store.IssueAccountToken":               "2c: account tokens",
	"Store.IssueSCIMToken":                  "2d: inbound SCIM",
	"Store.LauncherAdminClients":            "principal: the signed-in user's, or a suite call's sub (scoped in PR 3)",
	"Store.ListAlerts":                      "2d: alerts",
	"Store.ListFailingSyncEvents":           "2d: sync delivery",
	"Store.ListLogoutDeliveries":            "2c: back-channel logout deliveries",
	"Store.ListProvisioningState":           "2d: reconcile",
	"Store.ListSCIMConnectors":              "2d: inbound SCIM",
	"Store.ListSyncDeliveryAttempts":        "2d: sync delivery",
	"Store.ListUpstreamGroups":              "2d: inbound SCIM groups",
	"Store.ListUpstreamUsers":               "2d: inbound SCIM",
	"Store.MarkSyncDeliveryUncertain":       "2d: sync delivery",
	"Store.PingContext":                     "platform: the readiness probe reads one row of any org",
	"Store.PrincipalByID":                   "pre-org: the user a session, code, refresh family, MFA or step-up token, device sign-on or verified token names",
	"Store.QueueDirectoryPassword":          "2d: Active Directory connector",
	"Store.ReconcileDrift":                  "2d: reconcile",
	"Store.RedeemAccountToken":              "2c: account tokens",
	"Store.RedeemDeviceCode":                "2c: workstation sign-on",
	"Store.RejectSCIMCreate":                "2d: outbound SCIM links",
	"Store.ReleaseSyncEventLease":           "2d: sync events",
	"Store.ReplaceUpstreamGroup":            "2d: inbound SCIM groups",
	"Store.ResetUserMFA":                    "2c: MFA reset",
	"Store.ResumeSyncDeliveries":            "2d: sync delivery",
	"Store.ResumeSyncDelivery":              "2d: sync delivery",
	"Store.ResyncSystem":                    "2d: provisioning",
	"Store.RetryLogoutDeliveryNow":          "2c: back-channel logout deliveries",
	"Store.RetryProvisioning":               "2d: reconcile",
	"Store.SCIMGroupMembers":                "2d: provisioning",
	"Store.SCIMLink":                        "2d: outbound SCIM links",
	"Store.SaveSCIMLink":                    "2d: outbound SCIM links",
	"Store.SearchAuditEventsContext":        "2d: audit",
	"Store.SetEnrollmentPolicy":             "2c: MFA enrollment",
	"Store.StartSCIMCreate":                 "2d: outbound SCIM links",
	"Store.SuiteGroupsFor":                  "PR 3: suite API scoping",
	"Store.SuitePeople":                     "PR 3: suite API scoping",
	"Store.SyncBacklog":                     "2d: sync delivery",
	"Store.UpdateSCIMConnector":             "2d: inbound SCIM",
	"Store.UpdateSyncEventStatus":           "2d: sync events",
	"Store.applyRestoredStateTx":            "platform: a restore is the whole install",
	"Store.changeEnrollmentDevice":          "2c: MFA enrollment",
	"Store.evaluateBatch":                   "2d: alerts",
	"Store.evaluateOutages":                 "2d: alerts",
	"Store.migrateAlerts":                   "migration: written before org_id existed",
	"Store.migrateAppAccess":                "migration: written before org_id existed",
	"Store.migrateAuditIndexes":             "migration: written before org_id existed",
	"Store.migrateEnrollmentPolicy":         "migration: written before org_id existed",
	"Store.migrateInboundSCIM":              "migration: written before org_id existed",
	"Store.migrateInboundSCIMGroups":        "migration: written before org_id existed",
	"Store.migrateLegacy":                   "migration: written before org_id existed",
	"Store.migrateLogoutDeliveries":         "migration: written before org_id existed",
	"Store.migrateOnboarding":               "migration: written before org_id existed",
	"Store.migratePasswordChangeRequired":   "migration: written before org_id existed",
	"Store.migrateProvisioning":             "migration: written before org_id existed",
	"Store.migrateReconcile":                "migration: written before org_id existed",
	"Store.migrateSyncDelivery":             "migration: written before org_id existed",
	"Store.migrateSyncEventLease":           "migration: written before org_id existed",
	"Store.migrateSyncEventsUserReference":  "migration: written before org_id existed",
	"Store.reconcileSyncEvents":             "2d: sync delivery",
	"Store.releaseFencesForRemovalsTx":      "2d: sync delivery",
	"Store.resolveQuietLoginAlerts":         "2d: alerts",
	"Store.workstationGroups":               "2c: workstation sign-on",
	"accessRequestSelect":                   "fragment: OrgStore.ListAccessRequests adds u.org_id; DecideAccessRequest reads a request it found in the org",
	"alertReaderTx":                         "2d: alerts",
	"alertSelect":                           "2d: alerts",
	"appClaimsTx":                           "keyed by a user ID its caller resolved: token claims of a principal",
	"auditSelect":                           "2d: audit",
	"bootstrapPasswordUnchangedSQL":         "2c: password change",
	"classifyTx":                            "2d: alerts",
	"configureInstallerGroups":              "installer: single-tenant only, its objects are in the default org",
	"createStepUpTokenTx":                   "2c: step-up",
	"deleteGroupTx":                         "keyed by a group ID it first checks is in the org; the org of a row cannot change",
	"desiredGroupsTx":                       "2d: provisioning",
	"enqueueLogoutTx":                       "2c: back-channel logout deliveries",
	"externalGroupFreeTx":                   "2d: inbound SCIM groups",
	"forwardAccess":                         "2c: forward-auth sessions",
	"groupMembersTx":                        "2d: inbound SCIM groups",
	"insertAuditEventSQL":                   "2d: audit",
	"insertResourceEventTx":                 "2d: provisioning",
	"membersOwnedTx":                        "2d: inbound SCIM groups",
	"offboardUserTx":                        "2c: offboarding revokes sessions and grants",
	"pgSchemaV1":                            "migration: the version-1 Postgres schema, before org_id existed",
	"prepareSyncDeliveryTx":                 "2d: sync delivery",
	"previewEnrollmentTx":                   "2c: MFA enrollment",
	"provisionedTx":                         "2d: provisioning",
	"queueDesiredStateTx":                   "2d: provisioning",
	"queueUserNotificationTx":               "2d: provisioning",
	"queueUserUpdateTx":                     "2d: provisioning",
	"raiseAlertTx":                          "2d: alerts",
	"reconcileGroupsTx":                     "2d: provisioning",
	"reconcileProvisioningTx":               "2d: provisioning",
	"recordIssuedTokenTx":                   "2c: issued tokens",
	"refreshSyncEventRolesTx":               "keyed by a queued event's user (2d scopes sync events)",
	"rejectCrossIdentityTx":                 "2d: inbound SCIM",
	"releaseAttemptEventTx":                 "2d: sync delivery",
	"requirePermanentAdminTx":               "the last-administrator rule counts every org: only the default or staff org has administrators (D8)",
	"roleChangeTx":                          "keyed by user IDs its caller resolved in the org",
	"uniqueSuiteSlugTx":                     "slugs stay unique across orgs: SQLite keeps the global unique (D2), and whether apps use the slug globally is unverified",
	"upstreamGroupColumns":                  "2d: inbound SCIM groups",
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
