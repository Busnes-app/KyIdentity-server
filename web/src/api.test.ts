import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, apiJson, apiRequest, fetchCSRF, isStepUpRequired } from './api';

/** A fetch stub that answers from a queue, recording what it was asked for. */
function stubFetch(responses: Array<{ status?: number; body?: unknown; text?: string }>) {
  const calls: Array<{ path: string; init: RequestInit & { headers: Headers } }> = [];
  const fetchMock = vi.fn((path: string, init: RequestInit = {}) => {
    calls.push({ path, init: { ...init, headers: new Headers(init.headers) } });
    const next = responses.shift() ?? { status: 200, body: {} };
    const status = next.status ?? 200;
    const text = next.text ?? JSON.stringify(next.body ?? {});
    return Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(JSON.parse(text) as unknown),
      text: () => Promise.resolve(text),
    } as Response);
  });
  vi.stubGlobal('fetch', fetchMock);
  return calls;
}

const csrf = { body: { csrfToken: 'token-1' } };

beforeEach(() => {
  vi.stubGlobal('window', { dispatchEvent: vi.fn() } as unknown as Window);
});

afterEach(async () => {
  // The module caches the CSRF token; clear it so tests do not leak into each other.
  stubFetch([{ body: { csrfToken: 'reset' } }]);
  await fetchCSRF(true);
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('CSRF handling', () => {
  it('attaches a token to mutating requests only', async () => {
    const calls = stubFetch([csrf, { body: { ok: true } }]);
    await fetchCSRF(true);
    calls.length = 0;

    await apiRequest('/api/admin/users', { method: 'POST', body: '{}' });
    expect(calls[0].init.headers.get('X-CSRF-Token')).toBe('token-1');

    calls.length = 0;
    stubFetch([{ body: { ok: true } }]);
    await apiRequest('/api/admin/users');
  });

  // The retry exists because a rotated cookie invalidates the cached token. Without it the
  // admin sees a spurious failure on a change that was never actually rejected.
  it('refreshes the token once and retries when the server rejects it', async () => {
    stubFetch([csrf]);
    await fetchCSRF(true);

    const calls = stubFetch([
      { status: 403, body: { error: 'invalid_csrf' } },
      { body: { csrfToken: 'token-2' } },
      { body: { success: true } },
    ]);

    const result = await apiRequest('/api/admin/users/u1', { method: 'DELETE' });
    expect(result).toEqual({ success: true });
    expect(calls.map((c) => c.path)).toEqual([
      '/api/admin/users/u1',
      '/api/auth/csrf',
      '/api/admin/users/u1',
    ]);
    expect(calls[0].init.headers.get('X-CSRF-Token')).toBe('token-1');
    expect(calls[2].init.headers.get('X-CSRF-Token')).toBe('token-2');
  });

  // One retry, not a loop. A server that always answers invalid_csrf must surface as an
  // error rather than an unbounded stream of requests.
  it('retries at most once', async () => {
    stubFetch([csrf]);
    await fetchCSRF(true);

    const calls = stubFetch([
      { status: 403, body: { error: 'invalid_csrf' } },
      { body: { csrfToken: 'token-2' } },
      { status: 403, body: { error: 'invalid_csrf' } },
    ]);

    await expect(apiRequest('/api/admin/users/u1', { method: 'DELETE' })).rejects.toBeInstanceOf(
      ApiError,
    );
    expect(calls).toHaveLength(3);
  });

  it('does not retry a 403 that is not a CSRF rejection', async () => {
    stubFetch([csrf]);
    await fetchCSRF(true);

    const calls = stubFetch([{ status: 403, body: { error: 'step_up_required' } }]);
    await expect(apiRequest('/api/admin/users/u1', { method: 'DELETE' })).rejects.toSatisfy(
      isStepUpRequired,
    );
    expect(calls).toHaveLength(1);
  });
});

describe('unauthorized session handling', () => {
  it('announces an expired session so the app can return to login', async () => {
    const dispatch = vi.fn();
    vi.stubGlobal('window', { dispatchEvent: dispatch } as unknown as Window);
    stubFetch([{ status: 401, body: { error: 'unauthorized' } }]);

    await expect(apiRequest('/api/auth/me')).rejects.toBeInstanceOf(ApiError);
    expect(dispatch).toHaveBeenCalledTimes(1);
    expect((dispatch.mock.calls[0][0] as CustomEvent).type).toBe('kyidentity:unauthorized');
  });

  it.each(['/api/auth/step-up', '/api/auth/step-up/finish'])('keeps the session on failed credentials at %s', async path => {
    stubFetch([{ status: 401, body: { error: 'invalid_credentials' } }]);
    await expect(apiRequest(path, { method: 'POST', body: '{}' })).rejects.toThrow();
    expect(window.dispatchEvent).not.toHaveBeenCalled();
    stubFetch([{ status: 401, body: { error: 'unauthorized' } }]);
    await expect(apiRequest(path, { method: 'POST', body: '{}' })).rejects.toThrow();
    expect(window.dispatchEvent).toHaveBeenCalledTimes(1);
  });

  // A rejected password on the login form is not an expired session. Firing the event here
  // would bounce the user mid-login and hide the real error.
  it('stays quiet when login itself returns 401', async () => {
    const dispatch = vi.fn();
    vi.stubGlobal('window', { dispatchEvent: dispatch } as unknown as Window);
    stubFetch([{ status: 401, body: { error: 'invalid_credentials' } }]);

    await expect(apiRequest('/api/auth/login', { method: 'POST', body: '{}' })).rejects.toThrow();
    expect(dispatch).not.toHaveBeenCalled();
  });
});

describe('error and body handling', () => {
  it('prefers the server description in ApiError', async () => {
    stubFetch([{ status: 400, body: { error: 'bad', error_description: 'Nope' } }]);
    await expect(apiRequest('/api/x')).rejects.toMatchObject({
      message: 'Nope',
      code: 'bad',
      status: 400,
    });
  });

  it('survives a non-JSON error body', async () => {
    stubFetch([{ status: 502, text: '<html>gateway</html>' }]);
    await expect(apiRequest('/api/x')).rejects.toMatchObject({ status: 502 });
  });

  it('treats an empty body as an empty object', async () => {
    stubFetch([{ status: 200, text: '' }]);
    await expect(apiRequest('/api/x')).resolves.toEqual({});
  });

  // apiJson exists to stop a shape mismatch surfacing as an undefined field three
  // components away, so the failure must name the path.
  it('reports the path when a response fails its parser', async () => {
    stubFetch([{ body: { unexpected: true } }]);
    await expect(
      apiJson('/api/admin/users', () => {
        throw new Error('expected a users response');
      }),
    ).rejects.toThrow('/api/admin/users: expected a users response');
  });
});
