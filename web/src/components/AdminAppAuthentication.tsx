import { useEffect, useRef, useState } from 'react';
import { apiRequest, errorMessage } from '../api';
import { refreshBounds, validRefresh } from '../parsers';
import type { AppRecord, AppAuthenticationPolicy } from '../types';
import { isCancelled, useStepUp } from './StepUpPrompt';

export function AdminAppAuthentication({ app, onClose }: { app: AppRecord; onClose: () => void }) {
 const [policy, setPolicy] = useState(app.authentication);
 const [busy, setBusy] = useState(false);
 const [error, setError] = useState<string | null>(null);
 const heading = useRef<HTMLHeadingElement | null>(null);
 const { requestGrant, stepUpPrompt } = useStepUp();
 useEffect(() => { heading.current?.focus(); }, []);
 const updateMode = (mode: AppAuthenticationPolicy['mode']) => setPolicy(p => ({ ...p, mode, primaryMaxAge: mode === 'max_age' ? (p.primaryMaxAge || 3600) : 0 }));
 const updateFactor = (factor: AppAuthenticationPolicy['factor']) => setPolicy(p => ({ ...p, factor, factorMaxAge: factor === 'password' ? 0 : p.factorMaxAge }));
 const submit = async (event: React.FormEvent) => {
  event.preventDefault(); setBusy(true); setError(null);
  const path = `/api/admin/app-registry/${encodeURIComponent(app.id)}/authentication-policy`;
  try {
   const stepUpToken = await requestGrant(`Change authentication for ${app.clientName}. Outstanding sign-ins and this app's registered tokens will be revoked.`, `PUT ${path}`);
   await apiRequest(path, { method: 'PUT', stepUpToken, body: JSON.stringify({ policy, revision: app.revision }) });
   onClose();
  } catch (err) { if (!isCancelled(err)) setError(errorMessage(err, 'Could not save policy. Return to app connections and reopen to refresh.')); }
  finally { setBusy(false); }
 };
 return <div className="admin-page">
  <div className="page-header"><h1 className="page-title" ref={heading} tabIndex={-1}>Authentication for {app.clientName}</h1><button className="secondary-btn" disabled={busy} onClick={onClose}>Back to app connections</button></div>
  <p>These requirements apply whenever this OAuth app requests authorization. The app may request stronger authentication.</p>
  {error && <div className="alert-box error" role="alert">{error}</div>}
  <form className="settings-section" onSubmit={submit}><div className="modal-body">
   <div className="form-group"><label className="form-label" htmlFor="auth-mode">Password freshness</label><select id="auth-mode" className="form-input" value={policy.mode} disabled={busy} onChange={e => { const v = e.target.value; if (v === 'reuse' || v === 'fresh' || v === 'max_age') updateMode(v); }}>
    <option value="reuse">Reuse SSO</option><option value="max_age">Maximum password age</option><option value="fresh">Fresh sign-in every authorization</option>
   </select></div>
   {policy.mode === 'max_age' && <div className="form-group"><label className="form-label" htmlFor="primary-age">Maximum password age (seconds)</label><input id="primary-age" className="form-input" type="number" min="1" max="2147483647" step="1" required disabled={busy} value={policy.primaryMaxAge} onChange={e => setPolicy(p => ({ ...p, primaryMaxAge: e.target.valueAsNumber }))}/></div>}
   <div className="form-group"><label className="form-label" htmlFor="auth-factor">Required authentication</label><select id="auth-factor" className="form-input" value={policy.factor} disabled={busy} onChange={e => { const v = e.target.value; if (v === 'password' || v === 'mfa' || v === 'passkey') updateFactor(v); }}>
    <option value="password">Password and any already-enrolled second factor</option><option value="mfa">Password plus MFA</option><option value="passkey">Password plus passkey</option>
   </select></div>
   {policy.factor !== 'password' && <div className="form-group"><label className="form-label" htmlFor="factor-age">Maximum second-factor age (seconds; 0 means no additional age limit)</label><input id="factor-age" className="form-input" type="number" min="0" max="2147483647" step="1" required disabled={busy} value={policy.factorMaxAge} onChange={e => setPolicy(p => ({ ...p, factorMaxAge: e.target.valueAsNumber }))}/></div>}
   <fieldset className="form-group"><legend className="form-label">Refresh tokens</legend>
    <label><input type="checkbox" checked={policy.refreshLifetime > 0} disabled={busy} onChange={e => setPolicy(p => ({ ...p, refreshIdle: e.target.checked ? 3600 : 0, refreshLifetime: e.target.checked ? 86400 : 0 }))}/> Issue rotating refresh tokens (confidential clients only)</label>
    {policy.refreshLifetime > 0 && <>
     <label className="form-label" htmlFor="refresh-idle">Unused refresh token expires after (seconds, {refreshBounds.minIdle}–{refreshBounds.maxIdle})</label>
     <input id="refresh-idle" className="form-input" type="number" min={refreshBounds.minIdle} max={Math.min(refreshBounds.maxIdle, policy.refreshLifetime)} step="1" required disabled={busy} value={policy.refreshIdle} onChange={e => setPolicy(p => ({ ...p, refreshIdle: e.target.valueAsNumber }))}/>
     <label className="form-label" htmlFor="refresh-lifetime">Sign-in lasts at most (seconds, {refreshBounds.minLifetime}–{refreshBounds.maxLifetime})</label>
     <input id="refresh-lifetime" className="form-input" type="number" min={refreshBounds.minLifetime} max={refreshBounds.maxLifetime} step="1" required disabled={busy} value={policy.refreshLifetime} onChange={e => setPolicy(p => ({ ...p, refreshLifetime: e.target.valueAsNumber }))}/>
    </>}
   </fieldset>
   <p>Preview: {policy.mode === 'fresh' ? 'A new password and any required second factor on each authorization.' : policy.mode === 'max_age' ? `Password proof no older than ${policy.primaryMaxAge} seconds.` : 'Reuse the existing SSO session.'} {policy.factor === 'passkey' ? 'A passkey is required; TOTP, push and recovery do not qualify.' : policy.factor === 'mfa' ? 'TOTP, push or a passkey is required; recovery does not qualify.' : 'Existing enrollment rules still apply.'} {policy.factorMaxAge > 0 && `Second-factor proof must be no older than ${policy.factorMaxAge} seconds.`} {policy.refreshLifetime > 0 ? `The app may stay signed in by refreshing at least every ${policy.refreshIdle} seconds, for at most ${policy.refreshLifetime} seconds, never past the browser session or the ages above.` : 'No refresh tokens; the app keeps its own session.'}</p>
   <p>Users without a required factor must enroll from their dashboard before accessing this app. Fresh sign-in verifies the password and second factor together.</p>
   <p className="text-muted">Saving a changed policy cancels outstanding app sign-ins and revokes its registered tokens. Offline tokens may remain valid for up to 15 minutes, and the app's own session may last longer. Launcher links and downstream provisioning are unaffected.</p>
   <button className="primary-btn" disabled={busy || !validRefresh(policy.refreshIdle, policy.refreshLifetime) || JSON.stringify(policy) === JSON.stringify(app.authentication)}>Apply authentication policy</button>
  </div></form>
  {stepUpPrompt}
 </div>;
}
