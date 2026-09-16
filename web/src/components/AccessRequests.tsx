import { useEffect, useState } from 'react';
import { apiJson, apiRequest, errorMessage } from '../api';
import { parseOwnAccessRequests } from '../parsers';
import type { AccessRequest, RequestableApp } from '../types';
import { describeInstant } from '../instant';

const DURATIONS: [label: string, seconds: number][] = [['No end date', 0], ['1 day', 86400], ['7 days', 7 * 86400], ['30 days', 30 * 86400], ['90 days', 90 * 86400]];

const STATUS_LABEL: Record<AccessRequest['status'], string> = { pending: 'Pending', approved: 'Approved', denied: 'Denied', cancelled: 'Withdrawn', expired: 'Expired unanswered' };

/**
 * Ask for an app an administrator opened to requests. Only such apps are named here;
 * an owner or administrator answers, and an approval is an ordinary bounded grant.
 */
export function AccessRequests() {
  const [apps, setApps] = useState<RequestableApp[]>([]);
  const [requests, setRequests] = useState<AccessRequest[]>([]);
  const [asking, setAsking] = useState<RequestableApp | null>(null);
  const [reason, setReason] = useState('');
  const [duration, setDuration] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = async () => {
    try {
      const own = await apiJson('/api/user/access-requests', parseOwnAccessRequests);
      setApps(own.requestable); setRequests(own.requests);
    } catch (err) { setError(errorMessage(err, 'Could not load access requests')); }
  };
  useEffect(() => { void reload(); }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!asking) return;
    setBusy(true); setError(null);
    try {
      await apiRequest('/api/user/access-requests', { method: 'POST', body: JSON.stringify({ appId: asking.appId, reason: reason.trim(), durationSeconds: duration }) });
      setAsking(null); setReason(''); setDuration(0);
      await reload();
    } catch (err) { setError(errorMessage(err, 'Request refused')); } finally { setBusy(false); }
  };
  const cancel = async (r: AccessRequest) => {
    setBusy(true); setError(null);
    try { await apiRequest(`/api/user/access-requests/${encodeURIComponent(r.id)}`, { method: 'DELETE' }); await reload(); }
    catch (err) { setError(errorMessage(err, 'Could not withdraw the request')); } finally { setBusy(false); }
  };

  if (apps.length === 0 && requests.length === 0) return null;
  return <section className="settings-section" aria-labelledby="access-requests-title">
    <div className="section-header"><div className="section-title-wrap"><h2 id="access-requests-title">Request access</h2></div></div>
    {error && <div className="alert-box error" role="alert">{error}</div>}
    {apps.length > 0 && <ul className="device-list">
      {apps.map(a => <li key={a.appId} className="device-card"><div><b>{a.name}</b>{a.pending && <div className="text-muted text-sm">Request pending</div>}</div>
        {!a.pending && <button className="secondary-btn sm" disabled={busy} onClick={() => { setAsking(a); setReason(''); setDuration(0); }}>Request access</button>}</li>)}
    </ul>}
    {asking && <form className="modal-body" onSubmit={submit}>
      <div className="form-group"><label className="form-label" htmlFor="request-reason">Why do you need {asking.name}?</label>
        <textarea id="request-reason" className="form-input" maxLength={500} required value={reason} disabled={busy} onChange={e => setReason(e.target.value)} /></div>
      <div className="form-group"><label className="form-label" htmlFor="request-duration">For how long</label>
        <select id="request-duration" className="form-select" value={duration} disabled={busy} onChange={e => setDuration(Number(e.target.value))}>
          {DURATIONS.map(([label, seconds]) => <option key={seconds} value={seconds}>{label}</option>)}
        </select></div>
      <div className="modal-footer"><button type="button" className="secondary-btn" disabled={busy} onClick={() => setAsking(null)}>Cancel</button>
        <button type="submit" className="primary-btn" disabled={busy || !reason.trim()}>Send request</button></div>
    </form>}
    {requests.length > 0 && <table className="admin-table"><thead><tr><th>App</th><th>Status</th><th>Reason</th><th></th></tr></thead><tbody>
      {requests.map(r => <tr key={r.id}><td>{r.appName}</td>
        <td>{STATUS_LABEL[r.status]}{r.decidedAt && <div className="text-muted text-sm">{describeInstant(r.decidedAt)}</div>}{r.decisionNote && <div className="text-muted text-sm">{r.decisionNote}</div>}</td>
        <td style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{r.reason}</td>
        <td>{r.status === 'pending' && <button className="secondary-btn sm" disabled={busy} onClick={() => cancel(r)}>Withdraw</button>}</td></tr>)}
    </tbody></table>}
  </section>;
}
