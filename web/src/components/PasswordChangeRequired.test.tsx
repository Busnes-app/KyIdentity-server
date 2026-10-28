import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchCSRF } from '../api';
import { changeGivenPassword, PasswordChangeRequired } from './PasswordChangeRequired';
import type { User } from '../types';

const user: User = { id: 'u1', username: 'admin', displayName: 'Administrator', email: 'admin@x.test', role: 'admin', passwordChangeRequired: true };

describe('forced password change screen', () => {
  const html = renderToStaticMarkup(<PasswordChangeRequired user={user} onChanged={() => {}} onLogout={() => {}} />);

  it('asks only for a repeated new one under the server policy; step-up takes the given password', () => {
    expect(html).toContain('Choose a new password');
    expect(html).not.toContain('Current or temporary password');
    expect(html).not.toContain('current-password');
    expect(html.match(/type="password"/g)).toHaveLength(2);
    expect(html).toContain('Repeat new password');
    expect(html).toContain('12 to 1024 characters');
    expect(html.match(/minLength="12"/g)).toHaveLength(2);
  });

  it('offers nothing but the change, a factor replacement and sign-out', () => {
    expect(html).toContain('Sign out');
    expect(html).not.toContain('side-nav');
  });
});

describe('forced password change submission', () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  async function stubFetch() {
    const fetch = vi.fn((_path: string, _init: RequestInit) => Promise.resolve(new Response(JSON.stringify({ csrfToken: 'csrf', success: true }), { status: 200 })));
    vi.stubGlobal('fetch', fetch);
    await fetchCSRF(true);
    fetch.mockClear();
    return fetch;
  }

  it('sends the new password under the grant for this operation, without a current password', async () => {
    const fetch = await stubFetch();
    const requestGrant = vi.fn().mockResolvedValue('grant-1');
    await changeGivenPassword('my-own-password-42', requestGrant);
    expect(requestGrant).toHaveBeenCalledWith(expect.any(String), 'POST /api/user/password');
    expect(fetch).toHaveBeenCalledTimes(1);
    const [path, init] = fetch.mock.calls[0];
    expect(path).toBe('/api/user/password');
    expect(init.method).toBe('POST');
    expect(new Headers(init.headers).get('X-KyIdentity-StepUp')).toBe('grant-1');
    expect(JSON.parse(String(init.body))).toEqual({ newPassword: 'my-own-password-42' });
  });

  it('sends nothing when step-up is cancelled', async () => {
    const fetch = await stubFetch();
    await expect(changeGivenPassword('my-own-password-42', vi.fn().mockRejectedValue(new Error('cancelled')))).rejects.toThrow('cancelled');
    expect(fetch).not.toHaveBeenCalled();
  });
});
