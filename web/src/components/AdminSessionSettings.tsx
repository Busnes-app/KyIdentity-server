import { useEffect, useState } from 'react';
import { apiJson, errorMessage } from '../api';
import { parseSessionLimits, sessionBounds, validSessionLimits } from '../parsers';
import type { SessionLimits } from '../types';
import { isCancelled, useStepUp } from './StepUpPrompt';

// Global browser session limits. Every app's sign-in and refresh is bounded by them.
export function AdminSessionSettings() {
 const [saved, setSaved] = useState<SessionLimits | null>(null);
 const [draft, setDraft] = useState<SessionLimits | null>(null);
 const [busy, setBusy] = useState(false);
 const [error, setError] = useState<string | null>(null);
 const { requestGrant, stepUpPrompt } = useStepUp();
 const path = '/api/admin/session-settings';
 useEffect(() => { apiJson(path, parseSessionLimits).then(l => { setSaved(l); setDraft(l); }).catch(err => setError(errorMessage(err, 'Could not load session limits'))); }, []);
 const save = async (event: React.FormEvent) => {
  event.preventDefault();
  if (!draft) return;
  setBusy(true); setError(null);
  try {
   const stepUpToken = await requestGrant('Change how long sign-ins last. Shorter limits also end existing sessions that exceed them.', `PUT ${path}`);
   const l = await apiJson(path, parseSessionLimits, { method: 'PUT', stepUpToken, body: JSON.stringify(draft) });
   setSaved(l); setDraft(l);
  } catch (err) { if (!isCancelled(err)) setError(errorMessage(err, 'Could not save session limits')); }
  finally { setBusy(false); }
 };
 const b = sessionBounds;
 return <div className="settings-section"><form className="modal-body" onSubmit={save}><h2>Sign-in sessions</h2>
  {error && <div className="alert-box error" role="alert">{error}</div>}
  {draft && <>
   <div className="form-group"><label className="form-label" htmlFor="session-absolute">Sign-in lasts at most (hours, {b.minAbsolute / 3600}–{b.maxAbsolute / 3600})</label>
    <input id="session-absolute" className="form-input" type="number" min={b.minAbsolute / 3600} max={b.maxAbsolute / 3600} step="1" required disabled={busy} value={draft.absolute / 3600} onChange={e => setDraft({ ...draft, absolute: e.target.valueAsNumber * 3600 })}/></div>
   <div className="form-group"><label className="form-label" htmlFor="session-idle">Signed out after no activity for (minutes, {b.minIdle / 60}–{b.maxIdle / 60})</label>
    <input id="session-idle" className="form-input" type="number" min={b.minIdle / 60} max={Math.min(b.maxIdle, draft.absolute) / 60} step="1" required disabled={busy} value={draft.idle / 60} onChange={e => setDraft({ ...draft, idle: e.target.valueAsNumber * 60 })}/></div>
   <p>Activity is any request to KyIdentity, including an app signing in or refreshing its tokens. Each app's own re-authentication ages and refresh lifetimes apply on top of these. Shorter limits end existing sessions that exceed them; longer limits do not extend existing sessions.</p>
   <button className="primary-btn" disabled={busy || !validSessionLimits(draft) || JSON.stringify(draft) === JSON.stringify(saved)}>Apply session limits</button>
  </>}
 </form>{stepUpPrompt}</div>;
}
