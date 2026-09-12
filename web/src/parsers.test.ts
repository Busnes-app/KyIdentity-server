import { parseAppRecordPage, parseAppAccessPage, parsePairingToken, parseEnrollmentPolicies, parseProvisioningPage, parseReconcileJobs } from './parsers';
import { describe, expect, it } from 'vitest';
import {
  parseGroupPage,
  parseGroupUserPage,
  parseApplications,
  parseAuditPage,
  parseAuthStep,
  parseBeginLogin,
  parseBeginRegistration,
  parseMe,
  parseOAuthClients,
  parseOIDCIssuer,
  parsePairedSystems,
  parsePasskeys,
  parseSuccess,
  parseUsers,
} from './parsers';

const user = {
  id: 'u1',
  username: 'ada',
  displayName: 'Ada',
  email: 'ada@x.test',
  role: 'admin',
  status: 'active',
};

describe('parseUser', () => {
  it('reads a well-formed user', () => {
    const parsed = parseMe(user);
    expect(parsed.role).toBe('admin');
    expect(parsed.status).toBe('active');
  });

  it('accepts the wrapped shape /api/auth/me may return', () => {
    expect(parseMe({ user }).username).toBe('ada');
  });

  // A security state the UI does not understand must not be rendered as a safe one. If the
  // API grows `locked` or `pending`, showing that account as active is worse than failing.
  it.each(['locked', 'pending', '', undefined, null, 'ADMIN'])(
    'refuses the unknown status %p rather than defaulting to active',
    (status) => {
      expect(() => parseMe({ ...user, status })).toThrow(/status/);
    },
  );

  it.each(['superuser', 'root', '', undefined, null])(
    'refuses the unknown role %p rather than defaulting to user',
    (role) => {
      expect(() => parseMe({ ...user, role })).toThrow(/role/);
    },
  );

  // The specific bug this guards: an error body reaching a parser that shrugs and invents
  // a valid account.
  it('refuses an error body where a user was expected', () => {
    expect(() => parseMe({ error: 'unauthorized' })).toThrow();
  });

  it('rejects a users list containing one malformed entry', () => {
    expect(() => parseUsers({ users: [user, { ...user, role: 'wizard' }] })).toThrow(/role/);
  });

  it('treats an omitted users array as empty rather than failing', () => {
    expect(parseUsers({})).toEqual([]);
  });
});

describe('parseOAuthClients', () => {
  const client = {
    id: 'c1',
    clientName: 'App',
    clientType: 'confidential',
    redirectUrisJson: '[]',
    allowedScopesJson: '[]',
  };

  it('reads a well-formed client', () => {
    expect(parseOAuthClients({ clients: [client] })[0].clientType).toBe('confidential');
  });

  it('decodes registered URLs and scopes at the API boundary', () => {
    const parsed = parseOAuthClients({
      clients: [{ ...client, redirectUrisJson: '["https://app.test/callback"]', allowedScopesJson: '["openid","email"]' }],
    })[0];
    expect(parsed.redirectUris).toEqual(['https://app.test/callback']);
    expect(parsed.allowedScopes).toEqual(['openid', 'email']);
  });

  it('refuses malformed registered URL metadata', () => {
    expect(() => parseOAuthClients({ clients: [{ ...client, redirectUrisJson: '[1]' }] })).toThrow(
      /redirectUrisJson/,
    );
  });

  // Defaulting an unknown type to `public` silently downgrades how the UI describes the
  // client's authentication.
  it.each(['native', '', undefined])('refuses the unknown client type %p', (clientType) => {
    expect(() => parseOAuthClients({ clients: [{ ...client, clientType }] })).toThrow(
      /clientType/,
    );
  });
});

describe('parseOIDCIssuer', () => {
  it('reads the configured issuer and removes its trailing slash', () => {
    expect(parseOIDCIssuer({ issuer: 'https://auth.example.test/' })).toBe(
      'https://auth.example.test',
    );
  });
});

describe('parsePairedSystems', () => {
  const system = { id: 's1', name: 'S', callbackUrl: 'https://x.test', status: 'failing' };

  it('reads every known status', () => {
    for (const status of ['active', 'failing', 'disabled']) {
      expect(parsePairedSystems({ systems: [{ ...system, status }] })[0].status).toBe(status);
    }
  });

  it('refuses an unknown system status rather than reporting it active', () => {
    expect(() => parsePairedSystems({ systems: [{ ...system, status: 'paused' }] })).toThrow(
      /status/,
    );
  });

  it('defaults groupsEnabled to false when absent', () => {
    expect(parsePairedSystems({ systems: [system] })[0].groupsEnabled).toBe(false);
    expect(parsePairedSystems({ systems: [{ ...system, groupsEnabled: true }] })[0].groupsEnabled).toBe(true);
  });

  it('defaults reconcileHours to 0 and refuses negative or fractional values', () => {
    expect(parsePairedSystems({ systems: [system] })[0].reconcileHours).toBe(0);
    expect(parsePairedSystems({ systems: [{ ...system, reconcileHours: 24 }] })[0].reconcileHours).toBe(24);
    expect(() => parsePairedSystems({ systems: [{ ...system, reconcileHours: -1 }] })).toThrow(/reconcileHours/);
    expect(() => parsePairedSystems({ systems: [{ ...system, reconcileHours: 1.5 }] })).toThrow(/reconcileHours/);
  });
});

describe('parseAuditPage', () => {
  const event = {
    id: 'e1',
    action: 'admin.user_deleted',
    outcome: 'denied',
    ipAddress: '1.2.3.4',
    userAgent: 'test',
    createdAt: 'now',
  };

  it('preserves a denied outcome', () => {
    expect(parseAuditPage({ auditEvents: [event], total: 1 }).events[0].outcome).toBe('denied');
  });

  // Rendering an unrecognised outcome as "success" turns the audit view into a source of
  // false assurance, which is the one thing it may never be.
  it('refuses an unknown outcome rather than showing it as success', () => {
    expect(() => parseAuditPage({ auditEvents: [{ ...event, outcome: 'partial' }] })).toThrow(
      /outcome/,
    );
  });

  it('falls back to the event count when total is missing', () => {
    expect(parseAuditPage({ auditEvents: [event] }).total).toBe(1);
  });
});

describe('parseAuthStep', () => {
  it('reads an MFA challenge', () => {
    const step = parseAuthStep({
      success: false,
      mfaRequired: true,
      mfaMethods: ['totp', 'push'],
      mfaToken: 't',
      challengeId: 'c',
      matchDigits: '42',
      decoyDigits: ['11', '99'],
    });
    expect(step).toMatchObject({
      success: false,
      mfaRequired: true,
      mfaMethods: ['totp', 'push'],
      matchDigits: '42',
    });
    expect(step.user).toBeUndefined();
  });

  it('parses the user on a completed login', () => {
    expect(parseAuthStep({ success: true, user }).user?.role).toBe('admin');
  });

  // A login response carrying a user the parser cannot validate must fail the login, not
  // sign the operator in as an invented account.
  it('fails a login whose user carries an unknown role', () => {
    expect(() => parseAuthStep({ success: true, user: { ...user, role: 'wizard' } })).toThrow(
      /role/,
    );
  });
});

describe('parseApplications', () => {
  it('keeps the card source the launcher needs to pick an edit endpoint', () => {
    const [client, custom] = parseApplications({
      applications: [
        { id: 'kydns', name: 'KyDNS', url: 'https://dns.x.test', iconName: 'globe', source: 'client' },
        { id: 'a1', name: 'Portainer', url: 'https://p.x.test', iconName: 'favicon', source: 'custom' },
      ],
    });
    expect(client.source).toBe('client');
    expect(custom.source).toBe('custom');
  });

  it('leaves an undescribed card without a description rather than inventing one', () => {
    const [app] = parseApplications({
      applications: [{ id: 'kydns', name: 'KyDNS', url: 'https://dns.x.test', iconName: 'favicon' }],
    });
    expect(app.description).toBeUndefined();
    expect(app.source).toBeUndefined();
  });

  it('drops a source it does not recognise instead of trusting it', () => {
    const [app] = parseApplications({
      applications: [{ id: 'x', name: 'X', url: 'https://x.test', iconName: 'globe', source: 'admin' }],
    });
    expect(app.source).toBeUndefined();
  });
});

describe('parsePasskeys', () => {
  const passkey = {
    id: 'p1',
    name: 'YubiKey',
    backupEligible: true,
    backupState: true,
    createdAt: '2026-01-01T00:00:00Z',
  };

  // The server answers with a bare array, not one wrapped in an object.
  it('reads the bare array the server sends', () => {
    expect(parsePasskeys([passkey])[0].name).toBe('YubiKey');
  });

  it('treats a missing lastUsedAt as never-used rather than inventing a date', () => {
    expect(parsePasskeys([passkey])[0].lastUsedAt).toBeUndefined();
  });

  // backupEligible is the whole reason the UI can tell a synced passkey from a
  // device-bound one; losing it would silently erase that distinction.
  it('preserves backupEligible false as a device-bound passkey', () => {
    expect(parsePasskeys([{ ...passkey, backupEligible: false }])[0].backupEligible).toBe(false);
  });

  it('rejects a passkey list containing one malformed entry', () => {
    expect(() => parsePasskeys([passkey, { ...passkey, id: undefined }])).toThrow(/id/);
  });

  it('treats a null response as empty rather than failing', () => {
    expect(parsePasskeys(null)).toEqual([]);
  });
});

describe('parseBeginRegistration', () => {
  const begin = {
    challenge: 'c',
    rpId: 'kysignon.test',
    rpName: 'KySignOn',
    userHandle: 'uh',
    username: 'ada',
    excludeCredentials: ['e1', 'e2'],
  };

  it('reads a well-formed registration ceremony', () => {
    expect(parseBeginRegistration(begin)).toEqual(begin);
  });

  it('treats a missing excludeCredentials as an empty list', () => {
    const { excludeCredentials, ...rest } = begin;
    void excludeCredentials;
    expect(parseBeginRegistration(rest).excludeCredentials).toEqual([]);
  });

  it('refuses a response missing the challenge', () => {
    const { challenge, ...rest } = begin;
    void challenge;
    expect(() => parseBeginRegistration(rest)).toThrow(/challenge/);
  });
});

describe('parseBeginLogin', () => {
  it('reads a well-formed login ceremony', () => {
    const begin = { challenge: 'c', rpId: 'kysignon.test', allowCredentials: ['a1'] };
    expect(parseBeginLogin(begin)).toEqual(begin);
  });

  it('refuses a response missing the rpId', () => {
    expect(() => parseBeginLogin({ challenge: 'c', allowCredentials: [] })).toThrow(/rpId/);
  });
});

describe('parseSuccess', () => {
  it('accepts an explicit success', () => {
    expect(parseSuccess({ success: true })).toBe(true);
  });

  // A response that merely omits `success: false` must not be read as a completed
  // operation — that is exactly the shape an error body with a different key would take.
  it('refuses a response where success is not true', () => {
    expect(() => parseSuccess({ success: false })).toThrow(/success/);
    expect(() => parseSuccess({ error: 'step_up_required' })).toThrow(/success/);
  });
});


describe('group directory pages', () => {
  const group = { id: 'g1', name: 'Operations', description: '', member: true, memberCount: 3, createdAt: '2026-09-05T00:00:00Z', updatedAt: '2026-09-05T00:00:00Z' };
  const page = { groups: [group], total: 4, limit: 25, offset: 0 };
  it('preserves membership and pagination without interpreting names as roles', () => {
    expect(parseGroupPage(page)).toEqual({ items: [group], total: 4, limit: 25, offset: 0 });
    const member = { id: 'u1', username: 'ada', displayName: 'Ada', email: 'ada@example.test', status: 'disabled', member: false };
    expect(parseGroupUserPage({ users: [member], total: 1, limit: 25, offset: 0 }).items).toEqual([member]);
  });
  it('rejects malformed membership and pagination', () => {
    for (const invalid of [{ ...page, limit: 0 }, { ...page, offset: -1 }, { ...page, total: 1.5 }, { ...page, groups: [{ ...group, member: 'false' }] }, { ...page, groups: [{ ...group, memberCount: -1 }] }]) {
      expect(() => parseGroupPage(invalid)).toThrow();
    }
    expect(() => parseGroupUserPage({ users: [{ ...user, status: 'unknown', member: false }], limit: 25, offset: 0, total: 1 })).toThrow();
  });
});

it('validates app registry references and revisions', () => {
  const record = { id: 'app', revision: 1, authenticationRevision: 1, authentication: { mode: 'reuse', primaryMaxAge: 0, factor: 'password', factorMaxAge: 0 }, accessMode: 'assigned_only', enabled: true, clientId: 'client', clientName: 'Example', launcherId: '', launcherName: '', systemId: '', systemName: '' };
  const page = { records: [record], total: 1, limit: 25, offset: 0 };
  expect(parseAppRecordPage(page).items[0]).toEqual(record);
  expect(() => parseAppRecordPage({ ...page, records: [{ ...record, revision: 0 }] })).toThrow();
  expect(() => parseAppRecordPage({ ...page, records: [{ ...record, clientId: '' }] })).toThrow();
  expect(() => parseAppRecordPage({ ...page, records: [{ ...record, systemId: 42 }] })).toThrow();
});

it('validates effective-access decisions and preview metadata', () => {
 const app = { id: 'app', revision: 1, authenticationRevision: 1, authentication: { mode: 'reuse', primaryMaxAge: 0, factor: 'password', factorMaxAge: 0 }, accessMode: 'assigned_only', enabled: true, clientId: 'c', clientName: 'C', launcherId: '', launcherName: '', systemId: '', systemName: '' };
 const user = { id: 'u', username: 'User', displayName: '', status: 'active', direct: false, groupAssigned: true, effective: true, preview: false, reason: 'group_assignment' };
 const page = { app, users: [user], total: 1, limit: 25, offset: 0, losingAccess: 1, gainingAccess: 2 };
 expect(parseAppAccessPage(page).items[0].effective).toBe(true);
 expect(parseAppAccessPage(page).gainingAccess).toBe(2);
 expect(() => parseAppAccessPage({ ...page, users: [{ ...user, effective: 'yes' }] })).toThrow();
 expect(() => parseAppAccessPage({ ...page, users: [{ ...user, reason: 'unknown' }] })).toThrow();
 expect(() => parseAppAccessPage({ ...page, losingAccess: -1 })).toThrow();
});

it('preserves a successful login when its authorization must restart', () => {
  const result = parseAuthStep({ success: true, user, restartAuthorization: true });
  expect(result.success).toBe(true);
  expect(result.user?.id).toBe(user.id);
  expect(result.restartAuthorization).toBe(true);
});


describe('authentication policy boundary', () => {
 const record = { id: 'app', revision: 1, authenticationRevision: 1, accessMode: 'assigned_only', enabled: true, clientId: 'client', clientName: 'Example', launcherId: '', launcherName: '', systemId: '', systemName: '' };
 it('rejects invalid server policy before displaying editable controls', () => {
  for (const authentication of [null, {}, { mode: 'max_age', primaryMaxAge: 0, factor: 'mfa', factorMaxAge: 0 }, { mode: 'reuse', primaryMaxAge: 0, factor: 'password', factorMaxAge: 60 }, { mode: 'reuse', primaryMaxAge: 0, factor: 'passkey', factorMaxAge: -1 }]) {
   expect(() => parseAppRecordPage({ records: [{ ...record, authentication }], total: 1, limit: 25, offset: 0 })).toThrow();
  }
 });
});


describe('enrollment status boundary', () => {
  const enrollment = { required: true, allowedMethods: ['totp'], deadline: 1800000000, enrolled: false, restricted: true };
  it('preserves the server restriction and deadline', () => {
    expect(parseMe({ ...user, enrollment }).enrollment).toEqual(enrollment);
  });
  it.each([
    { restricted: 'false' }, { restricted: null }, { allowedMethods: [] },
    { allowedMethods: ['recovery'] }, { allowedMethods: ['totp', 'totp'] },
    { deadline: -1 }, { deadline: '1800000000' },
  ])('rejects malformed security state %p', invalid => {
    expect(() => parseMe({ ...user, enrollment: { ...enrollment, ...invalid } })).toThrow();
  });
});


describe('pairing expiry', () => {
  it('reads the server ISO timestamp without resetting the countdown to epoch zero', () => {
    expect(parsePairingToken({pairingToken:'test', expiresAt:'2026-09-06T01:00:00Z'}).expiresAt).toBe(Date.parse('2026-09-06T01:00:00Z'));
  });
  it.each([undefined, '', 'invalid'])('rejects an invalid expiry %p', expiresAt => {
    expect(() => parsePairingToken({pairingToken:'test', expiresAt})).toThrow();
  });
});

describe('group enrollment policies', () => {
  it('accepts a stable group scope', () => {
    expect(parseEnrollmentPolicies({policies:[{scope:'group:g1',required:true,allowedMethods:['totp'],graceSeconds:3600,revision:2}]} )[0].scope).toBe('group:g1');
  });
  it.each(['group:', 'group', 'group:'+'x'.repeat(513)])('rejects invalid scope %p', scope => {
    expect(() => parseEnrollmentPolicies({policies:[{scope,required:true,allowedMethods:['totp'],graceSeconds:0,revision:1}]})).toThrow();
  });
});

describe('provisioning state', () => {
  const row = { userId: 'u1', username: 'ada', displayName: 'Ada', desired: true, recorded: true, acknowledged: false, observed: 'present_active',
    observedAt: '2026-09-06T00:00:00Z', revision: 3, blocked: false, lastEvent: { type: 'user.updated', status: 'pending', attempts: 2, nextAttemptAt: '2026-09-06T01:00:00Z', updatedAt: '2026-09-06T00:30:00Z' } };
  const page = { users: [row], total: 1, limit: 25, offset: 0 };
  it('reads a provisioning row and tolerates absent optional fields', () => {
    expect(parseProvisioningPage(page).items[0]).toEqual(row);
    const bare = parseProvisioningPage({ ...page, users: [{ ...row, observed: '', observedAt: undefined, lastEvent: undefined }] }).items[0];
    expect(bare.observed).toBe('');
    expect(bare.lastEvent).toBeUndefined();
  });
  it('refuses an unknown observed state or malformed last event', () => {
    expect(() => parseProvisioningPage({ ...page, users: [{ ...row, observed: 'present' }] })).toThrow(/observed/);
    expect(() => parseProvisioningPage({ ...page, users: [{ ...row, desired: 'yes' }] })).toThrow(/desired/);
    expect(() => parseProvisioningPage({ ...page, users: [{ ...row, lastEvent: { ...row.lastEvent, status: 'retrying' } }] })).toThrow(/status/);
  });
});

describe('reconcile jobs', () => {
  const result = { supported: true, complete: true, repaired: false, listedUsers: 10, unrelated: 2, missingCount: 1, staleCount: 0, orphanedCount: 1,
    missing: [{ id: 'u1', username: 'ada', reason: 'not listed' }], stale: [], orphaned: [{ id: 'r9', reason: 'managed account without access' }], groupsRequeued: 0, groupsOrphaned: 0 };
  const job = { id: 'j1', systemId: 's1', kind: 'preview', status: 'done', requestedBy: 'admin', attempts: 1, createdAt: '2026-09-06T00:00:00Z', finishedAt: '2026-09-06T00:01:00Z', result };
  it('reads a finished job with its drift report', () => {
    expect(parseReconcileJobs({ jobs: [job] })[0]).toEqual(job);
  });
  it('accepts a queued job with no result and an empty list', () => {
    expect(parseReconcileJobs({ jobs: [{ ...job, status: 'queued', finishedAt: undefined, result: undefined }] })[0].result).toBeUndefined();
    expect(parseReconcileJobs({})).toEqual([]);
  });
  it('refuses unknown status or kind and malformed reports', () => {
    expect(() => parseReconcileJobs({ jobs: [{ ...job, status: 'cancelled' }] })).toThrow(/status/);
    expect(() => parseReconcileJobs({ jobs: [{ ...job, kind: 'audit' }] })).toThrow(/kind/);
    expect(() => parseReconcileJobs({ jobs: [{ ...job, result: { ...result, missingCount: -1 } }] })).toThrow(/missingCount/);
    expect(() => parseReconcileJobs({ jobs: [{ ...job, result: { ...result, missing: [{ reason: 'x' }] } }] })).toThrow(/id/);
  });
});
