import { useState } from 'react';
import { apiJson, apiRequest, errorMessage, logout } from '../api';
import { parseDeviceCodeView } from '../parsers';
import type { DeviceCodeView, User } from '../types';
import { AuthFrame } from './AuthFrame';

type Step = { kind: 'enter' } | { kind: 'confirm'; view: DeviceCodeView } | { kind: 'done'; approved: boolean };

/**
 * /device: a signed-in person approves or denies a code a workstation shows (RFC 8628).
 * The screen names the app, its client ID and the address that asked, so a code someone
 * else sent can be recognised and denied.
 */
export function DeviceApproval({ user }: { user: User }) {
  const [code, setCode] = useState(() => new URLSearchParams(window.location.search).get('user_code') ?? '');
  const [step, setStep] = useState<Step>({ kind: 'enter' });
  const [error, setError] = useState<{ text: string; reauth?: boolean } | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true); setError(null);
    try { await fn(); } catch (err) {
      const text = errorMessage(err, 'Something went wrong');
      setError({ text, reauth: /newer or stronger sign-in/.test(text) });
    } finally { setBusy(false); }
  };
  const lookup = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => setStep({ kind: 'confirm', view: await apiJson('/api/device/lookup', parseDeviceCodeView, { method: 'POST', body: JSON.stringify({ userCode: code }) }) }));
  };
  const decide = (approve: boolean) => void run(async () => {
    await apiRequest('/api/device/decision', { method: 'POST', body: JSON.stringify({ userCode: code, approve }) });
    setStep({ kind: 'done', approved: approve });
  });
  const signInAgain = () => void run(async () => {
    if (await logout()) window.location.assign(`/device?user_code=${encodeURIComponent(code)}`);
  });

  return <AuthFrame>
    <h2>Sign in on a computer</h2>
    {error && <div className="alert-box error" role="alert"><p>{error.text}</p>
      {error.reauth && <button type="button" className="secondary-btn" disabled={busy} onClick={signInAgain}>Sign out and sign in again</button>}</div>}
    {step.kind === 'enter' && <form onSubmit={lookup}>
      <p>Enter the code the computer shows. You are signed in as <strong>{user.username}</strong>.</p>
      <div className="form-group"><label className="form-label" htmlFor="device-code">Code</label>
        <input id="device-code" className="form-input font-mono" autoComplete="off" autoCapitalize="characters" spellCheck={false} required maxLength={12}
          placeholder="BCDF-GHJK" value={code} disabled={busy} onChange={e => setCode(e.target.value.toUpperCase())} autoFocus /></div>
      <button type="submit" className="primary-btn" disabled={busy || !code.trim()}>Continue</button>
    </form>}
    {step.kind === 'confirm' && <>
      <p>A computer is asking to sign in as <strong>{user.username}</strong>. Approve only if you started this sign-in yourself, on a computer in front of you.</p>
      <dl className="connection-details">
        <dt>App</dt><dd>{step.view.clientName}</dd>
        <dt>Client ID</dt><dd><code className="cell-id">{step.view.clientId}</code></dd>
        <dt>Requested from</dt><dd><code>{step.view.ipAddress || 'unknown address'}</code></dd>
        <dt>Requested at</dt><dd>{new Date(step.view.createdAt).toLocaleString()}</dd>
      </dl>
      <div className="action-buttons-wrap">
        <button type="button" className="primary-btn" disabled={busy} onClick={() => decide(true)}>Approve</button>
        <button type="button" className="secondary-btn" disabled={busy} onClick={() => decide(false)}>Deny</button>
      </div>
    </>}
    {step.kind === 'done' && <div role="status">
      {step.approved
        ? <p>Approved. Go back to the computer; it finishes signing in within a few seconds.</p>
        : <p>Denied. The computer was not signed in. If you did not start this, tell your administrator.</p>}
      <a className="secondary-btn" href="/">Go to your dashboard</a>
    </div>}
  </AuthFrame>;
}
