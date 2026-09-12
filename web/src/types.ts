export interface EnrollmentStatus { required: boolean; allowedMethods: string[]; deadline: number; enrolled: boolean; restricted: boolean }
export interface EnrollmentPolicy { scope: 'organization' | 'administrators' | `group:${string}`; required: boolean; allowedMethods: string[]; graceSeconds: number; revision: number }
export interface EnrollmentPreview { affected: number; missingFactor: number; restrictedSessions: number; canActivate: boolean }

export interface User {
  enrollment?: EnrollmentStatus;
  id: string;
  username: string;
  displayName: string;
  email: string;
  role: 'user' | 'admin';
  status?: 'active' | 'disabled';
  mfaMethods?: string[];
  createdAt?: string;
}

export interface PairedSystem {
  id: string;
  name: string;
  systemType: string;
  description?: string;
  iconUrl?: string;
  callbackUrl: string;
  status: 'active' | 'failing' | 'disabled';
  lastSyncedAt?: string;
  createdAt: string;
  groupsEnabled: boolean;
  /** Scheduled repair interval; 0 = off. Only meaningful for SCIM. */
  reconcileHours: number;
}

export interface NativeDevice {
  id: string;
  userId: string;
  deviceName: string;
  deviceIdentifier: string;
  platform?: string;
  pushToken?: string;
  isMfaApprover: boolean;
  lastSeenAt?: string;
  createdAt: string;
}

export interface Passkey {
  id: string;
  name: string;
  backupEligible: boolean;
  backupState: boolean;
  lastUsedAt?: string;
  createdAt: string;
}

export interface Application {
  id: string;
  /** Where the card came from, which decides the endpoint that edits it. */
  source?: 'client' | 'custom';
  name: string;
  url: string;
  iconName: string;
  description?: string;
  sortOrder?: number;
  enabled: boolean;
}

export interface OAuthClient {
  id: string;
  clientName: string;
  clientType: 'public' | 'confidential';
  redirectUris: string[];
  allowedScopes: string[];
  launchUrl?: string;
  enabled: boolean;
  createdAt: string;
}

export interface AuditEvent {
  id: string;
  actorId?: string;
  actorUsername?: string;
  action: string;
  targetId?: string;
  targetType?: string;
  ipAddress: string;
  userAgent: string;
  outcome: 'success' | 'failure' | 'denied';
  detailsJson?: string;
  createdAt: string;
}

export interface BackupDrillCheck {
  name: string;
  passed: boolean;
  message: string;
}

export interface BackupDrillResult {
  passed: boolean;
  duration_ms: number;
  checks: BackupDrillCheck[];
  error_message?: string;
}

export interface DepositReceipt {
  capsuleId: string;
  digest: string;
  sizeBytes: number;
  depositedAt: string;
}

export interface LocalCopy {
  name: string;
  sizeBytes: number;
  createdAt: string;
}

export interface BackupRunResult {
  capsuleId: string;
  sizeBytes: number;
  localPath?: string;
  localError?: string;
  receipt?: DepositReceipt;
}

export interface BackupStatus {
  paired: boolean;
  keyPinned: boolean;
  recovery_url?: string;
  recovery_key_id?: string;
  recovery_key_error?: string;
  threshold?: number;
  total_shares?: number;
  last_deposit?: DepositReceipt;
  intervalSec?: number;
  minIntervalSec?: number;
  nextRunAt?: string;
  localDir?: string;
  localKeep?: number;
  localCopies: LocalCopy[];
  localError?: string;
  members: string[];
  app_name: string;
  app_version: string;
}

export interface DirectoryGroup {
  id: string;
  name: string;
  description: string;
  memberCount: number;
  member: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface GroupUser {
  id: string;
  username: string;
  displayName: string;
  email: string;
  status: 'active' | 'disabled';
  member: boolean;
}

export interface DirectoryPage<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface AppAuthenticationPolicy {
 mode: 'reuse' | 'fresh' | 'max_age';
 primaryMaxAge: number;
 factor: 'password' | 'mfa' | 'passkey';
 factorMaxAge: number;
}

export interface AppRecord {
 authentication: AppAuthenticationPolicy;
 authenticationRevision: number;
  accessMode: 'all_active_users' | 'assigned_only';
  enabled: boolean;
  id: string;
  revision: number;
  clientId: string;
  clientName: string;
  launcherId: string;
  launcherName: string;
  systemId: string;
  systemName: string;
}

export interface AppAccessUser {
 id: string; username: string; displayName: string; status: 'active' | 'disabled';
 direct: boolean; groupAssigned: boolean; effective: boolean; preview: boolean;
 reason: 'user_disabled' | 'app_disabled' | 'client_disabled' | 'all_active_users' | 'direct_assignment' | 'group_assignment' | 'not_assigned';
}
export interface AppAccessGroup { id: string; name: string; assigned: boolean }
export interface AppAccessPage extends DirectoryPage<AppAccessUser> { app: AppRecord; losingAccess: number; gainingAccess: number }

export type ObservedState = '' | 'present_active' | 'present_inactive' | 'absent' | 'unsupported';
export interface ProvisioningEvent {
  type: string; status: 'pending' | 'delivered' | 'failed'; error?: string; attempts: number; nextAttemptAt?: string; updatedAt: string;
}
export interface ProvisioningRow {
  userId: string; username: string; displayName: string;
  desired: boolean; recorded: boolean; acknowledged: boolean;
  observed: ObservedState; observedAt?: string; revision: number; blocked: boolean; lastEvent?: ProvisioningEvent;
}
export interface DriftEntry { id: string; username?: string; reason: string }
export interface DriftReport {
  supported: boolean; complete: boolean; repaired: boolean;
  listedUsers: number; unrelated: number; missingCount: number; staleCount: number; orphanedCount: number;
  missing: DriftEntry[]; stale: DriftEntry[]; orphaned: DriftEntry[];
  groupsRequeued: number; groupsOrphaned: number; listingError?: string;
}
export interface ReconcileJob {
  id: string; systemId: string; kind: 'preview' | 'repair'; status: 'queued' | 'running' | 'done' | 'failed';
  requestedBy: string; attempts: number; createdAt: string; startedAt?: string; finishedAt?: string; error?: string; result?: DriftReport;
}
