import { isValidElement } from 'react';
import type { ReactElement, ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, fetchCSRF } from '../api';
import { cancelHandoff, finishHandoff } from '../keyringAPI';
import { buildHandoffErrorURL } from '../keyringCrypto';
import { HandoffRecovery } from './KeyringHandoff';

const done = { redirect_uri: 'https://app.example.test/callback', code: 'code-1', state: 'st' };

// Finds a button by its text in a rendered HandoffRecovery tree.
function button(node: ReactNode, text: string): ReactElement<{ onClick: () => void }> | undefined {
  if (Array.isArray(node)) return node.map(n => button(n, text)).find(Boolean);
  if (!isValidElement<{ children?: ReactNode; onClick?: () => void }>(node)) return undefined;
  if (node.type === 'button' && node.props.children === text) return node as ReactElement<{ onClick: () => void }>;
  return button(node.props.children, text);
}

describe('keyring handoff completion failures', () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it('a 503 during completion is retryable and a retry completes', async () => {
    const complete = vi.fn()
      .mockRejectedValueOnce(new ApiError(503, { error: 'Service unavailable' }))
      .mockResolvedValueOnce(done);
    const build = vi.fn((d: typeof done) => `${d.redirect_uri}?code=${d.code}`);

    const first = await finishHandoff(complete, build);
    expect(first.kind).toBe('retry');
    expect(build).not.toHaveBeenCalled();

    expect(await finishHandoff(complete, build)).toEqual({ kind: 'redirect', target: 'https://app.example.test/callback?code=code-1' });
  });

  it('offers try again and cancel before the interaction is consumed', () => {
    const onRetry = vi.fn();
    const onCancel = vi.fn();
    const tree = HandoffRecovery({ stage: 'retry', busy: false, restart: null, onRetry, onCancel });
    button(tree, 'Try again')?.props.onClick();
    button(tree, 'Cancel sign-in')?.props.onClick();
    expect(onRetry).toHaveBeenCalledOnce();
    expect(onCancel).toHaveBeenCalledOnce();
    expect(renderToStaticMarkup(tree)).not.toContain('Restart sign-in');
  });

  it('a sealing failure after completion offers a restart that carries no code', async () => {
    const outcome = await finishHandoff(() => Promise.resolve(done), () => Promise.reject(new Error('seal failed')));
    expect(outcome.kind).toBe('restart');
    if (outcome.kind !== 'restart') return;
    const restart = new URL(outcome.restart ?? '');
    expect(restart.origin + restart.pathname).toBe(done.redirect_uri);
    expect(restart.searchParams.get('error')).toBe('server_error');
    expect(restart.searchParams.get('state')).toBe('st');
    expect(restart.searchParams.has('code')).toBe(false);
    expect(restart.hash).toBe('');

    const replace = vi.fn();
    vi.stubGlobal('window', { location: { replace } });
    const tree = HandoffRecovery({ stage: 'restart', busy: false, restart: outcome.restart, onRetry: vi.fn(), onCancel: vi.fn() });
    button(tree, 'Restart sign-in')?.props.onClick();
    expect(replace).toHaveBeenCalledWith(outcome.restart);
    const html = renderToStaticMarkup(tree);
    expect(html).not.toContain('Try again');
    expect(html).toContain('Back to KyIdentity');
  });

  it('still offers a way out when the consumed interaction has no usable redirect', async () => {
    const outcome = await finishHandoff(() => Promise.resolve({ ...done, redirect_uri: '' }), () => { throw new Error('bad'); });
    expect(outcome).toMatchObject({ kind: 'restart', restart: null });
    const html = renderToStaticMarkup(HandoffRecovery({ stage: 'restart', busy: false, restart: null, onRetry: vi.fn(), onCancel: vi.fn() }));
    expect(html).toContain('Back to KyIdentity');
  });

  it('cancel deletes the live interaction and returns access_denied to the app', async () => {
    const fetch = vi.fn((path: string) => Promise.resolve(new Response(JSON.stringify(
      path === '/api/auth/csrf' ? { csrfToken: 'csrf' } : { redirect_uri: done.redirect_uri, state: 'st' },
    ), { status: 200 })));
    vi.stubGlobal('fetch', fetch);
    await fetchCSRF(true);
    fetch.mockClear();

    const cancelled = await cancelHandoff('ix-1');
    const [path, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(path).toBe('/api/user/keyring/handoff/ix-1');
    expect(init.method).toBe('DELETE');
    const target = new URL(buildHandoffErrorURL(cancelled.redirect_uri, cancelled.state, 'access_denied', 'cancelled'));
    expect(target.searchParams.get('error')).toBe('access_denied');
  });
});
