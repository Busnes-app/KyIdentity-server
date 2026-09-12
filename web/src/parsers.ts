/**
 * Parsers for every API response the UI consumes.
 *
 * These exist because an identity UI's failure paths have to be deterministic. A response
 * that changed shape, or an error body arriving where a success body was expected, must fail
 * here with a legible message rather than reaching a component that dereferences a field the
 * server never sent.
 */
import { isRecord } from './api';
import type {
  AppRecord, AppAccessPage, AppAccessGroup, AppAuthenticationPolicy, EnrollmentStatus, EnrollmentPolicy, EnrollmentPreview,
  DirectoryGroup,
  DirectoryPage,
  GroupUser,
  Application,
  AuditEvent,
  BackupDrillResult,
  BackupRunResult,
  BackupStatus,
  DepositReceipt,
  NativeDevice,
  OAuthClient,
  PairedSystem,
  Passkey,
  ProvisioningRow,
  ProvisioningEvent,
  ReconcileJob,
  DriftReport,
  DriftEntry,
  User,
} from './types';
import type { BeginLogin, BeginRegistration } from './webauthn';

function fail(what: string): never {
  throw new Error(`expected ${what}`);
}

function obj(value: unknown, what: string): Record<string, unknown> {
  return isRecord(value) ? value : fail(what);
}

function str(source: Record<string, unknown>, key: string): string {
  const v = source[key];
  return typeof v === 'string' ? v : fail(`string field "${key}"`);
}

function optStr(source: Record<string, unknown>, key: string): string | undefined {
  const v = source[key];
  return typeof v === 'string' ? v : undefined;
}

function bool(source: Record<string, unknown>, key: string): boolean {
  return source[key] === true;
}

/**
 * Reads a field that must be one of a fixed set of values.
 *
 * Folding an unrecognised value into a default is how a boundary check becomes a boundary
 * fiction: a server that grows a `locked` or `pending` status, or an error body arriving
 * where a user was expected, would be rendered as a healthy active account. An identity UI
 * has to refuse to guess what a security state means.
 */
function oneOf<T extends string>(
  source: Record<string, unknown>,
  key: string,
  allowed: readonly T[],
): T {
  const v = source[key];
  return allowed.includes(v as T) ? (v as T) : fail(`field "${key}" to be one of ${allowed.join(', ')}`);
}

function arr(value: unknown, what: string): unknown[] {
  return Array.isArray(value) ? value : fail(what);
}

function strArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === 'string');
}

function jsonStringArray(source: Record<string, unknown>, key: string): string[] {
  const encoded = str(source, key);
  let decoded: unknown;
  try {
    decoded = JSON.parse(encoded);
  } catch {
    return fail(`field "${key}" to contain a JSON string array`);
  }
  return arr(decoded, `field "${key}" to contain a JSON array`).map((item) =>
    typeof item === 'string' ? item : fail(`field "${key}" to contain only strings`),
  );
}

/** Reads an array that the server may omit entirely when empty. */
function list<T>(value: unknown, parse: (item: unknown) => T): T[] {
  if (value === null || value === undefined) return [];
  return arr(value, 'an array').map(parse);
}

export function parseUser(value: unknown): User {
  const o = obj(value, 'a user object');
  return {
    enrollment: o.enrollment === undefined ? undefined : parseEnrollmentStatus(o.enrollment),
    id: str(o, 'id'),
    username: str(o, 'username'),
    displayName: optStr(o, 'displayName') ?? str(o, 'username'),
    email: optStr(o, 'email') ?? '',
    role: oneOf(o, 'role', ['admin', 'user'] as const),
    status: oneOf(o, 'status', ['active', 'disabled'] as const),
    mfaMethods: strArray(o.mfaMethods),
    createdAt: optStr(o, 'createdAt'),
  };
}

export function parseUsers(value: unknown): User[] {
  const o = obj(value, 'a users response');
  return list(o.users, parseUser);
}

/** /api/auth/me returns the user either bare or wrapped. */
export function parseMe(value: unknown): User {
  const o = obj(value, 'an auth response');
  return parseUser(isRecord(o.user) ? o.user : o);
}

export function parseDevice(value: unknown): NativeDevice {
  const o = obj(value, 'a device object');
  return {
    id: str(o, 'id'),
    userId: optStr(o, 'userId') ?? '',
    deviceName: optStr(o, 'deviceName') ?? 'Unnamed device',
    deviceIdentifier: optStr(o, 'deviceIdentifier') ?? '',
    platform: optStr(o, 'platform'),
    pushToken: optStr(o, 'pushToken'),
    isMfaApprover: bool(o, 'isMfaApprover'),
    lastSeenAt: optStr(o, 'lastSeenAt'),
    createdAt: optStr(o, 'createdAt') ?? '',
  };
}

export function parseDevices(value: unknown): NativeDevice[] {
  const o = obj(value, 'a devices response');
  return list(o.devices, parseDevice);
}

export interface PairingToken {
  pairingToken: string;
  pinCode: string;
  qrPayload: string;
  expiresAt: number;
}

export function parsePairingToken(value: unknown): PairingToken {
  const o = obj(value, 'a pairing token response');
  const expiresAt = Date.parse(str(o, 'expiresAt'));
  if (!Number.isFinite(expiresAt)) return fail('a valid pairing expiry timestamp');
  return {
    pairingToken: str(o, 'pairingToken'),
    pinCode: optStr(o, 'pinCode') ?? '',
    qrPayload: optStr(o, 'qrPayload') ?? '',
    expiresAt,
  };
}

export interface TOTPSetup {
  secret: string;
  uri: string;
}

export function parseTOTPSetup(value: unknown): TOTPSetup {
  const o = obj(value, 'a TOTP setup response');
  return { secret: str(o, 'secret'), uri: str(o, 'uri') };
}

export function parseRecoveryCodes(value: unknown): string[] {
  const o = obj(value, 'a recovery codes response');
  const codes = strArray(o.recoveryCodes);
  return codes.length > 0 ? codes : fail('a non-empty recoveryCodes array');
}

export function parsePasskey(value: unknown): Passkey {
  const o = obj(value, 'a passkey object');
  return {
    id: str(o, 'id'),
    name: str(o, 'name'),
    backupEligible: bool(o, 'backupEligible'),
    backupState: bool(o, 'backupState'),
    lastUsedAt: optStr(o, 'lastUsedAt'),
    createdAt: optStr(o, 'createdAt') ?? '',
  };
}

/** /api/user/passkeys answers with a bare array, not an object wrapping one. */
export function parsePasskeys(value: unknown): Passkey[] {
  return list(value, parsePasskey);
}

export function parseBeginRegistration(value: unknown): BeginRegistration {
  const o = obj(value, 'a passkey registration begin response');
  return {
    challenge: str(o, 'challenge'),
    rpId: str(o, 'rpId'),
    rpName: str(o, 'rpName'),
    userHandle: str(o, 'userHandle'),
    username: str(o, 'username'),
    excludeCredentials: strArray(o.excludeCredentials),
  };
}

export function parseBeginLogin(value: unknown): BeginLogin {
  const o = obj(value, 'a passkey login begin response');
  return {
    challenge: str(o, 'challenge'),
    rpId: str(o, 'rpId'),
    allowCredentials: strArray(o.allowCredentials),
  };
}

/** True only when the server confirms success; anything else must not be read as one. */
export function parseSuccess(value: unknown): true {
  const o = obj(value, 'a success response');
  return bool(o, 'success') ? true : fail('field "success" to be true');
}

export interface StepUpGrant {
  stepUpToken: string;
  expiresAt: string;
}

export function parseStepUpGrant(value: unknown): StepUpGrant {
  const o = obj(value, 'a step-up response');
  return { stepUpToken: str(o, 'stepUpToken'), expiresAt: optStr(o, 'expiresAt') ?? '' };
}

export function parseApplications(value: unknown): Application[] {
  const o = obj(value, 'an applications response');
  return list(o.applications, (item) => {
    const a = obj(item, 'an application object');
    const source = optStr(a, 'source');
    return {
      id: str(a, 'id'),
      source: source === 'client' || source === 'custom' ? source : undefined,
      name: str(a, 'name'),
      url: optStr(a, 'url') ?? '',
      iconName: optStr(a, 'iconName') ?? '',
      description: optStr(a, 'description'),
      sortOrder: typeof a.sortOrder === 'number' ? a.sortOrder : undefined,
      enabled: a.enabled !== false,
    };
  });
}

export function parsePairedSystems(value: unknown): PairedSystem[] {
  const o = obj(value, 'a systems response');
  return list(o.systems, (item) => {
    const s = obj(item, 'a paired system object');
    return {
      id: str(s, 'id'),
      name: str(s, 'name'),
      systemType: optStr(s, 'systemType') ?? 'custom',
      description: optStr(s, 'description'),
      iconUrl: optStr(s, 'iconUrl'),
      callbackUrl: optStr(s, 'callbackUrl') ?? '',
      status: oneOf(s, 'status', ['active', 'failing', 'disabled'] as const),
      lastSyncedAt: optStr(s, 'lastSyncedAt'),
      createdAt: optStr(s, 'createdAt') ?? '',
      groupsEnabled: bool(s, 'groupsEnabled'),
      reconcileHours: s.reconcileHours === undefined ? 0 : directoryCount(s, 'reconcileHours'),
    };
  });
}

export interface CreatedSystem {
  system: PairedSystem;
  bearerToken: string;
}

export function parseCreatedSystem(value: unknown): CreatedSystem {
  const o = obj(value, 'a created system response');
  return {
    system: parsePairedSystems({ systems: [o.system] })[0],
    bearerToken: optStr(o, 'bearerToken') ?? '',
  };
}

export function parseOAuthClients(value: unknown): OAuthClient[] {
  const o = obj(value, 'a clients response');
  return list(o.clients, (item) => {
    const c = obj(item, 'a client object');
    return {
      id: str(c, 'id'),
      clientName: optStr(c, 'clientName') ?? str(c, 'id'),
      clientType: oneOf(c, 'clientType', ['confidential', 'public'] as const),
      redirectUris: jsonStringArray(c, 'redirectUrisJson'),
      allowedScopes: jsonStringArray(c, 'allowedScopesJson'),
      launchUrl: optStr(c, 'launchUrl'),
      enabled: c.enabled !== false,
      createdAt: optStr(c, 'createdAt') ?? '',
    };
  });
}

export function parseOIDCIssuer(value: unknown): string {
  return str(obj(value, 'OIDC discovery metadata'), 'issuer').replace(/\/$/, '');
}

export function parseCreatedClientSecret(value: unknown): string | undefined {
  const o = obj(value, 'a created client response');
  return optStr(o, 'clientSecret');
}

export interface AuditPage {
  events: AuditEvent[];
  total: number;
}

export function parseAuditPage(value: unknown): AuditPage {
  const o = obj(value, 'an audit response');
  const events = list(o.auditEvents, (item) => {
    const e = obj(item, 'an audit event');
    return {
      id: str(e, 'id'),
      actorId: optStr(e, 'actorId'),
      actorUsername: optStr(e, 'actorUsername'),
      action: str(e, 'action'),
      targetId: optStr(e, 'targetId'),
      targetType: optStr(e, 'targetType'),
      ipAddress: optStr(e, 'ipAddress') ?? '',
      userAgent: optStr(e, 'userAgent') ?? '',
      outcome: oneOf(e, 'outcome', ['success', 'failure', 'denied'] as const),
      detailsJson: optStr(e, 'detailsJson'),
      createdAt: optStr(e, 'createdAt') ?? '',
    } satisfies AuditEvent;
  });
  return { events, total: typeof o.total === 'number' ? o.total : events.length };
}

export function parseDepositReceipt(value: unknown): DepositReceipt {
  const o = obj(value, 'a deposit receipt');
  return {
    capsuleId: str(o, 'capsule_id'),
    digest: optStr(o, 'digest') ?? '',
    sizeBytes: typeof o.size_bytes === 'number' ? o.size_bytes : 0,
    depositedAt: optStr(o, 'deposited_at') ?? '',
  };
}

function optNum(source: Record<string, unknown>, key: string): number | undefined {
  return typeof source[key] === 'number' ? (source[key] as number) : undefined;
}

export function parseBackupRun(value: unknown): BackupRunResult {
  const o = obj(value, 'a backup run result');
  const m = obj(o.manifest, 'a capsule manifest');
  return {
    capsuleId: str(m, 'capsule_id'),
    sizeBytes: optNum(o, 'size_bytes') ?? 0,
    localPath: optStr(o, 'local_path'),
    localError: optStr(o, 'local_error'),
    receipt: isRecord(o.receipt) ? parseDepositReceipt(o.receipt) : undefined,
  };
}

export function parseBackupStatus(value: unknown): BackupStatus {
  const o = obj(value, 'a backup status response');
  return {
    paired: bool(o, 'paired'),
    keyPinned: o.key_pinned === true,
    recovery_url: optStr(o, 'recovery_url'),
    recovery_key_id: optStr(o, 'recovery_key_id'),
    recovery_key_error: optStr(o, 'recovery_key_error'),
    threshold: optNum(o, 'threshold'),
    total_shares: optNum(o, 'total_shares'),
    last_deposit: isRecord(o.last_deposit) ? parseDepositReceipt(o.last_deposit) : undefined,
    intervalSec: optNum(o, 'interval_sec'),
    minIntervalSec: optNum(o, 'min_interval_sec'),
    nextRunAt: optStr(o, 'next_run_at'),
    localDir: optStr(o, 'local_dir'),
    localKeep: optNum(o, 'local_keep'),
    localCopies: Array.isArray(o.local_copies)
      ? list(o.local_copies, (item) => {
          const c = obj(item, 'a local copy');
          return { name: str(c, 'name'), sizeBytes: optNum(c, 'size_bytes') ?? 0, createdAt: optStr(c, 'created_at') ?? '' };
        })
      : [],
    localError: optStr(o, 'local_error'),
    members: Array.isArray(o.members) ? strArray(o.members) : [],
    app_name: optStr(o, 'app_name') ?? 'KySignOn',
    app_version: optStr(o, 'app_version') ?? '',
  };
}

export function parseDrillResult(value: unknown): BackupDrillResult {
  const o = obj(value, 'a drill result');
  return {
    passed: bool(o, 'passed'),
    duration_ms: typeof o.duration_ms === 'number' ? o.duration_ms : 0,
    checks: list(o.checks, (item) => {
      const c = obj(item, 'a drill check');
      return {
        name: str(c, 'name'),
        passed: bool(c, 'passed'),
        message: optStr(c, 'message') ?? '',
      };
    }),
    error_message: optStr(o, 'error_message'),
  };
}

/** Login and MFA responses share a status-plus-optional-user shape. */
/** Mirrors the server's LoginResponse, which every MFA step also answers with. */
export interface AuthStep {
  restartAuthorization?: boolean;
  success: boolean;
  user?: User;
  mfaRequired: boolean;
  mfaMethods: string[];
  mfaToken?: string;
  challengeId?: string;
  matchDigits?: string;
  decoyDigits: string[];
}

export function parseAuthStep(value: unknown): AuthStep {
  const o = obj(value, 'an authentication response');
  return {
    success: bool(o, 'success'),
    restartAuthorization: o.restartAuthorization === true,
    user: isRecord(o.user) ? parseUser(o.user) : undefined,
    mfaRequired: o.mfaRequired === true,
    mfaMethods: strArray(o.mfaMethods),
    mfaToken: optStr(o, 'mfaToken'),
    challengeId: optStr(o, 'challengeId'),
    matchDigits: optStr(o, 'matchDigits'),
    decoyDigits: strArray(o.decoyDigits),
  };
}

/** The push-challenge poll answers with a bare status. */
export function parsePushStatus(value: unknown): string {
  const o = obj(value, 'a push poll response');
  return str(o, 'status');
}

function directoryCount(o: Record<string, unknown>, key: string): number {
  const n = o[key];
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 0 ? n : fail(`nonnegative integer field "${key}"`);
}
function directoryMember(o: Record<string, unknown>): boolean {
  return typeof o.member === 'boolean' ? o.member : fail('boolean field "member"');
}
function directoryPage<T>(value: unknown, key: string, parse: (item: unknown) => T): DirectoryPage<T> {
  const o = obj(value, 'a directory page');
  const limit = directoryCount(o, 'limit');
  if (limit < 1 || limit > 100) fail('page limit between 1 and 100');
  const items = list(o[key], parse);
  if (items.length > limit) fail('no more items than the page limit');
  return { items, limit, total: directoryCount(o, 'total'), offset: directoryCount(o, 'offset') };
}
export function parseGroupPage(value: unknown): DirectoryPage<DirectoryGroup> {
  return directoryPage(value, 'groups', item => {
    const o = obj(item, 'a group');
    return { id: str(o, 'id'), name: str(o, 'name'), description: str(o, 'description'),
      memberCount: directoryCount(o, 'memberCount'), member: directoryMember(o),
      createdAt: str(o, 'createdAt'), updatedAt: str(o, 'updatedAt') };
  });
}
export function parseGroupUserPage(value: unknown): DirectoryPage<GroupUser> {
  return directoryPage(value, 'users', item => {
    const o = obj(item, 'a group user');
    return { id: str(o, 'id'), username: str(o, 'username'), displayName: str(o, 'displayName'),
      email: str(o, 'email'), status: oneOf(o, 'status', ['active', 'disabled']), member: directoryMember(o) };
  });
}

export function parseAppAuthenticationPolicy(value: unknown): AppAuthenticationPolicy {
 const p = obj(value, 'an authentication policy');
 const policy = {
  mode: oneOf(p, 'mode', ['reuse', 'fresh', 'max_age']),
  primaryMaxAge: directoryCount(p, 'primaryMaxAge'),
  factor: oneOf(p, 'factor', ['password', 'mfa', 'passkey']),
  factorMaxAge: directoryCount(p, 'factorMaxAge'),
 };
 if (policy.primaryMaxAge > 2147483647 || policy.factorMaxAge > 2147483647 ||
     (policy.mode === 'max_age' ? policy.primaryMaxAge === 0 : policy.primaryMaxAge !== 0) ||
     (policy.factor === 'password' && policy.factorMaxAge !== 0)) return fail('valid authentication ages');
 return policy;
}

export function parseAppRecord(value: unknown): AppRecord {
  const a = obj(value, 'an app record');
  const revision = directoryCount(a, 'revision');
  if (revision < 1) return fail('a positive revision');
  const record = {
    id: str(a, 'id'), revision,
    authentication: parseAppAuthenticationPolicy(a.authentication),
    authenticationRevision: directoryCount(a, 'authenticationRevision'),
    accessMode: oneOf(a, 'accessMode', ['all_active_users', 'assigned_only']),
    enabled: requiredBool(a, 'enabled'),
    clientId: str(a, 'clientId'), clientName: str(a, 'clientName'),
    launcherId: str(a, 'launcherId'), launcherName: str(a, 'launcherName'),
    systemId: str(a, 'systemId'), systemName: str(a, 'systemName'),
  };
  if (!record.id || (!record.clientId && !record.launcherId && !record.systemId)) return fail('an app with a connection');
  return record;
}
export function parseAppRecordPage(value: unknown): DirectoryPage<AppRecord> {
 return directoryPage(value, 'records', parseAppRecord);
}
function requiredBool(o: Record<string, unknown>, key: string): boolean {
 const value = o[key]; return typeof value === 'boolean' ? value : fail(`boolean field "${key}"`);
}
export function parseAppAccessPage(value: unknown): AppAccessPage {
 const o = obj(value, 'an app access page');
 return { ...directoryPage(value, 'users', item => {
  const u = obj(item, 'an app access user');
  return { id: str(u,'id'), username: str(u,'username'), displayName: str(u,'displayName'), status: oneOf(u,'status',['active','disabled']),
   direct: requiredBool(u,'direct'), groupAssigned: requiredBool(u,'groupAssigned'), effective: requiredBool(u,'effective'), preview: requiredBool(u,'preview'),
   reason: oneOf(u,'reason',['user_disabled','app_disabled','client_disabled','all_active_users','direct_assignment','group_assignment','not_assigned']) };
 }), app: parseAppRecord(o.app), losingAccess: directoryCount(o,'losingAccess'), gainingAccess: directoryCount(o,'gainingAccess') };
}
export function parseAppAccessGroups(value: unknown): DirectoryPage<AppAccessGroup> {
 return directoryPage(value,'groups',item => { const g=obj(item,'an assigned group'); return {id:str(g,'id'),name:str(g,'name'),assigned:requiredBool(g,'assigned')}; });
}

function enrollmentMethods(value: unknown): string[] {
 const methods = arr(value, 'factor methods').map(v => typeof v === 'string' && ['totp','push','webauthn'].includes(v) ? v : fail('permitted MFA method'));
 if (!methods.length || new Set(methods).size !== methods.length) return fail('nonempty distinct MFA methods');
 return methods;
}
export function parseEnrollmentStatus(value: unknown): EnrollmentStatus {
 const o=obj(value,'enrollment status');return {required:requiredBool(o,'required'),allowedMethods:enrollmentMethods(o.allowedMethods),deadline:directoryCount(o,'deadline'),enrolled:requiredBool(o,'enrolled'),restricted:requiredBool(o,'restricted')};
}
function enrollmentScope(o: Record<string, unknown>): EnrollmentPolicy['scope'] {
 const scope = str(o, 'scope');
 if (scope === 'organization' || scope === 'administrators') return scope;
 if (scope.startsWith('group:') && scope.length > 6 && scope.length <= 512) return `group:${scope.slice(6)}`;
 return fail('an enrollment policy scope');
}
export function parseEnrollmentPolicies(value: unknown): EnrollmentPolicy[] {
 return arr(obj(value,'enrollment policies').policies,'policies').map(v=>{const o=obj(v,'policy');return {scope:enrollmentScope(o),required:requiredBool(o,'required'),allowedMethods:enrollmentMethods(o.allowedMethods),graceSeconds:directoryCount(o,'graceSeconds'),revision:directoryCount(o,'revision')};});
}
export function parseEnrollmentPreview(value: unknown): EnrollmentPreview {
 const o=obj(value,'policy preview');return {affected:directoryCount(o,'affected'),missingFactor:directoryCount(o,'missingFactor'),restrictedSessions:directoryCount(o,'restrictedSessions'),canActivate:requiredBool(o,'canActivate')};
}

export function parseSyncDeliveries(value: unknown) {
  if (!Array.isArray(value)) return fail('delivery attempts');
  return value.map((item: unknown) => {
    const row = obj(item, 'delivery attempt');
    const recoverAfter = str(row, 'recoverAfter');
    if (!Number.isFinite(Date.parse(recoverAfter))) return fail('recovery timestamp');
    return { token: str(row, 'token'), userId: str(row, 'userId'), eventType: str(row, 'eventType'), recoverAfter };
  });
}

export function parseSyncReadBack(value: unknown): string {
  const row = obj(value, 'read-back');
  switch (str(row, 'state')) {
    case 'unsupported': return 'This signed webhook has no SCIM read-back endpoint. Check the receiving service directly.';
    case 'absent': return 'No matching remote user was observed.';
    case 'present':
      return `Matching remote user ${str(row, 'remoteId')} was observed. Inspect its attributes in the receiving service.`;
    default: return fail('read-back state');
  }
}

function parseProvisioningEvent(value: unknown): ProvisioningEvent {
  const e = obj(value, 'a provisioning event');
  return { type: str(e, 'type'), status: oneOf(e, 'status', ['pending', 'delivered', 'failed']), error: optStr(e, 'error'),
    attempts: directoryCount(e, 'attempts'), nextAttemptAt: optStr(e, 'nextAttemptAt'), updatedAt: str(e, 'updatedAt') };
}
export function parseProvisioningPage(value: unknown): DirectoryPage<ProvisioningRow> {
  return directoryPage(value, 'users', item => {
    const u = obj(item, 'a provisioning row');
    return { userId: str(u, 'userId'), username: str(u, 'username'), displayName: str(u, 'displayName'),
      desired: requiredBool(u, 'desired'), recorded: requiredBool(u, 'recorded'), acknowledged: requiredBool(u, 'acknowledged'),
      observed: oneOf(u, 'observed', ['', 'present_active', 'present_inactive', 'absent', 'unsupported']), observedAt: optStr(u, 'observedAt'),
      revision: directoryCount(u, 'revision'), blocked: requiredBool(u, 'blocked'),
      lastEvent: u.lastEvent == null ? undefined : parseProvisioningEvent(u.lastEvent) };
  });
}

function parseDriftEntry(value: unknown): DriftEntry {
  const e = obj(value, 'a drift entry');
  return { id: str(e, 'id'), username: optStr(e, 'username'), reason: str(e, 'reason') };
}
function parseDriftReport(value: unknown): DriftReport {
  const r = obj(value, 'a drift report');
  return { supported: requiredBool(r, 'supported'), complete: requiredBool(r, 'complete'), repaired: requiredBool(r, 'repaired'),
    listedUsers: directoryCount(r, 'listedUsers'), unrelated: directoryCount(r, 'unrelated'),
    missingCount: directoryCount(r, 'missingCount'), staleCount: directoryCount(r, 'staleCount'), orphanedCount: directoryCount(r, 'orphanedCount'),
    missing: list(r.missing, parseDriftEntry), stale: list(r.stale, parseDriftEntry), orphaned: list(r.orphaned, parseDriftEntry),
    groupsRequeued: directoryCount(r, 'groupsRequeued'), groupsOrphaned: directoryCount(r, 'groupsOrphaned'), listingError: optStr(r, 'listingError') };
}
export function parseReconcileJob(value: unknown): ReconcileJob {
  const j = obj(obj(value, 'a reconcile job response').job, 'a reconcile job');
  return { id: str(j, 'id'), systemId: str(j, 'systemId'), kind: oneOf(j, 'kind', ['preview', 'repair']),
    status: oneOf(j, 'status', ['queued', 'running', 'done', 'failed']), requestedBy: str(j, 'requestedBy'),
    attempts: directoryCount(j, 'attempts'), createdAt: str(j, 'createdAt'), startedAt: optStr(j, 'startedAt'), finishedAt: optStr(j, 'finishedAt'),
    error: optStr(j, 'error'), result: j.result == null ? undefined : parseDriftReport(j.result) };
}
export function parseReconcileJobs(value: unknown): ReconcileJob[] {
  return list(obj(value, 'a reconcile jobs response').jobs, job => parseReconcileJob({ job }));
}
