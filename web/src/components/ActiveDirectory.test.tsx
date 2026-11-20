import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ADFields, DirectoryPasswords, IssuedAgentToken, createActiveDirectory, sendPasswordRequest } from './ActiveDirectory';
import { SystemRowActions } from './AdminSystems';
import { parseActiveDirectory, parseAgentToken } from '../parsers';
import type { ADPasswordStatus, ADSettingsInput } from '../types';

/** Answers the CSRF fetch (cached across tests) and then `body`, recording each call. */
function stubFetch(body: unknown) {
  const calls: Array<{ path: string; init: RequestInit }> = [];
  vi.stubGlobal('fetch', vi.fn((path: string, init: RequestInit = {}) => {
    calls.push({ path, init });
    const value = path === '/api/auth/csrf' ? { csrfToken: 'c' } : body;
    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(value), text: () => Promise.resolve(JSON.stringify(value)) } as Response);
  }));
  return calls;
}
afterEach(() => vi.unstubAllGlobals());

const grant = vi.fn((_reason: string, _operation: string) => Promise.resolve('grant-1'));
const ad: ADSettingsInput = {
  ldapsUrl: 'ldaps://dc1.example.org', bindPassword: 'bind-secret', bindDn: 'CN=kyidentity-sync,CN=Users,DC=example,DC=org',
  baseDn: 'OU=KyIdentity,DC=example,DC=org', caPem: '-----BEGIN CERTIFICATE-----...', agentPublicKey: '', passwordTtlMinutes: 1440,
};
const system = { id: 's1', name: 'Office AD', systemType: 'active_directory', callbackUrl: 'ldaps://dc1.example.org', status: 'active', createdAt: '', groupsEnabled: false, reconcileHours: 0, provisioningHold: false };
const user = (state: ADPasswordStatus['state'], lastError?: string): ADPasswordStatus => ({ userId: `u-${state}`, username: state, displayName: '', state, lastError });

describe('active directory connector', () => {
  it('posts the create body the server expects, behind step-up', async () => {
    const calls = stubFetch({ system });
    await createActiveDirectory('Office AD', ad, grant);
    expect(grant.mock.calls[0][1]).toBe('POST /api/admin/systems');
    const post = calls.find((c) => c.path === '/api/admin/systems');
    expect(new Headers(post?.init.headers).get('X-KyIdentity-StepUp')).toBe('grant-1');
    expect(JSON.parse(String(post?.init.body))).toEqual({
      name: 'Office AD', systemType: 'active_directory', callbackUrl: 'ldaps://dc1.example.org', bearerToken: 'bind-secret',
      activeDirectory: { bindDn: ad.bindDn, baseDn: ad.baseDn, caPem: ad.caPem, agentPublicKey: '', passwordTtlMinutes: 1440 },
    });
  });

  it('never pre-fills or shows the bind password', () => {
    const parsed = parseActiveDirectory({ ldapsUrl: 'ldaps://dc1', entrySigningKey: 'ed25519:k', bindPassword: 'leak', settings: { systemId: 's1', bindDn: 'b', baseDn: 'o', caPem: 'p', agentPublicKey: '', agentTokenSet: true, passwordTtlMinutes: 60, bindPassword: 'leak' }, passwords: [] });
    expect(JSON.stringify(parsed)).not.toContain('leak');
    const html = renderToStaticMarkup(<ADFields value={{ ...ad, bindPassword: '' }} onChange={() => {}} passwordSet />);
    expect(html).toContain('Bind password: set');
    expect(html).toMatch(/<input[^>]*type="password"[^>]*value=""/);
    expect(html).not.toContain('bind-secret');
  });

  it('shows a new agent token once, with the warning', () => {
    expect(parseAgentToken({ agentToken: 'kyad_abc' })).toBe('kyad_abc');
    expect(() => parseAgentToken({ agentToken: 'abc' })).toThrow();
    const html = renderToStaticMarkup(<IssuedAgentToken token="kyad_abc" />);
    expect(html).toContain('kyad_abc');
    expect(html).toContain('It will not be shown again.');
  });

  it('labels every directory password state and offers a request only where a PC sign-in fails', () => {
    const html = renderToStaticMarkup(<DirectoryPasswords busy={false} onRequest={() => {}} passwords={[
      user('current'), user('locked'), user('pending'), user('stale', 'expired'), user('rejected', 'password_policy'), user('missing', 'agent_key_replaced')]} />);
    expect(html).toContain('3 users cannot sign in to a PC yet.');
    expect([...html.matchAll(/data-ky-status="(\w+)">([^<]+)/g)].map((m) => `${m[1]}:${m[2]}`)).toEqual([
      'success:In directory', 'warning:Locked until the user sets a password', 'warning:Waiting for agent', 'warning:Older password in directory', 'danger:Rejected by directory', 'warning:Password not yet in directory']);
    for (const words of ['Expired before the agent applied it', 'Directory password policy refused it', 'Agent key replaced']) expect(html).toContain(words);
    expect(html.match(/Send password-change request/g)).toHaveLength(3);
  });

  it('sends the password-change request through the reset link, behind step-up', async () => {
    const calls = stubFetch({ kind: 'reset', delivery: 'email', expiresAt: '2026-11-20T00:00:00Z' });
    await sendPasswordRequest({ userId: 'u1', username: 'ana' }, grant);
    const post = calls.find((c) => c.path === '/api/admin/users/u1/reset-link');
    expect(post?.init.method).toBe('POST');
    expect(JSON.parse(String(post?.init.body))).toEqual({ send: true });
    expect(grant.mock.calls.at(-1)?.[1]).toBe('POST /api/admin/users/u1/reset-link');
  });

  it('offers directory settings and a connection test, but no SCIM connection or group items', () => {
    const none = () => {};
    const html = renderToStaticMarkup(<SystemRowActions system={{ ...system, status: 'active' }} onConnection={none} onDeliveries={none} onProvisioning={none} onTest={none} onResync={none} onDelete={none} />);
    expect([...html.matchAll(/class="row-action[^"]*"[^>]*>(?:<svg[\s\S]*?<\/svg>)?([^<]+)/g)].map((m) => m[1]))
      .toEqual(['Directory settings', 'Deliveries', 'Provisioning', 'Test connection', 'Resync directory', 'Disconnect']);
  });
});
