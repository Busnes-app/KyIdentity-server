import { useEffect, useState } from 'react';
import { apiJson, apiRequest, errorMessage } from '../api';
import { parseAlertPage, parseAlertSettings, parseSuccess } from '../parsers';
import type { Access, Alert, AlertSettings } from '../types';
import { describeInstant } from '../instant';
import { pageSize, Pager, useDirectoryPage } from './DirectoryPage';
import { isCancelled, useStepUp } from './StepUpPrompt';

const STATUSES = ['open', 'acknowledged', 'resolved', 'all'] as const;

function delivery(a: Alert): string {
  const d = a.delivery;
  const parts: string[] = [];
  if (d.delivered) parts.push(`${d.delivered} mailed`);
  if (d.pending) parts.push(`${d.pending} pending`);
  if (d.failed) parts.push(`${d.failed} failed`);
  if (d.skipped) parts.push(`${d.skipped} skipped`);
  return parts.length ? parts.join(', ') : 'no mail configured';
}

/**
 * The alert inbox and its settings. Alerts are derived on the server from the audit
 * trail and connector state; acknowledging is an administrator's act, and recipients
 * are re-checked by the server for the right to read alerts before each message.
 */
export function AdminAlerts({ access }: { access?: Access }) {
  const admin = access?.admin === true;
  const [status, setStatus] = useState<(typeof STATUSES)[number]>('open');
  const [offset, setOffset] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [settings, setSettings] = useState<AlertSettings | null>(null);
  const [threshold, setThreshold] = useState(10);
  const [windowMinutes, setWindowMinutes] = useState(10);
  const [recipients, setRecipients] = useState('');
  const { requestGrant, stepUpPrompt } = useStepUp();
  const params = new URLSearchParams({ status, limit: String(pageSize), offset: String(offset) });
  const { page, error: loadError, reload } = useDirectoryPage(`/api/admin/alerts?${params}`, parseAlertPage);
  useEffect(() => { if (page && offset > 0 && offset >= page.total) setOffset(Math.max(0, offset - pageSize)); }, [page, offset]);

  const loadSettings = async () => {
    try {
      const s = await apiJson('/api/admin/alerts/settings', parseAlertSettings);
      setSettings(s); setThreshold(s.loginFailureThreshold); setWindowMinutes(Math.round(s.loginFailureWindowSeconds / 60)); setRecipients(s.recipients.map(r => r.username).join(', '));
    } catch (err) { setError(errorMessage(err, 'Could not load alert settings')); }
  };
  useEffect(() => { void loadSettings(); }, []);

  const acknowledge = async (a: Alert) => {
    setBusy(true); setError(null);
    try {
      await apiJson(`/api/admin/alerts/${encodeURIComponent(a.id)}/acknowledge`, parseSuccess, { method: 'POST' });
      reload();
    } catch (err) { setError(errorMessage(err, 'Could not acknowledge')); } finally { setBusy(false); }
  };

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError(null); setNotice(null);
    const names = recipients.split(',').map(s => s.trim()).filter(Boolean);
    try {
      const stepUpToken = await requestGrant('Changing who is mailed about security alerts and when repeated login failures count.', 'PUT /api/admin/alerts/settings');
      await apiRequest('/api/admin/alerts/settings', { method: 'PUT', stepUpToken, body: JSON.stringify({ loginFailureThreshold: threshold, loginFailureWindowSeconds: windowMinutes * 60, recipients: names }) });
      setNotice('Saved.');
      await loadSettings();
    } catch (err) { if (!isCancelled(err)) setError(errorMessage(err, 'Could not save alert settings')); } finally { setBusy(false); }
  };

  return <div className="admin-page">
    {stepUpPrompt}
    <div className="page-header"><div><h1 className="page-title">Alerts</h1>
      <p>Privilege changes, recovery use, connector credential changes, repeated login failures, failed access removal and provisioning outages. Repeats fold into one alert; an acknowledged alert reopens on the next occurrence and an outage resolves itself when deliveries succeed again.</p></div></div>
    {(error || loadError) && <div className="alert-box error" role="alert">{error || loadError} <button className="secondary-btn sm" onClick={reload}>Refresh</button></div>}
    {notice && <div className="alert-box" role="status">{notice}</div>}
    <div className="form-group"><label className="form-label" htmlFor="alert-status">Show</label>
      <select id="alert-status" className="form-select" value={status} onChange={e => { const v = e.target.value; if ((STATUSES as readonly string[]).includes(v)) { setStatus(v as (typeof STATUSES)[number]); setOffset(0); } }}>
        {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}</select></div>
    <div className="table-card"><table className="admin-table">
      <thead><tr><th>Severity</th><th>Alert</th><th>Seen</th><th>Mail</th><th>Status</th></tr></thead>
      <tbody>{page?.items.map(a => <tr key={a.id}>
        <td>{a.severity}</td>
        <td><b>{a.title}</b><div className="text-sm" style={{ overflowWrap: 'anywhere', maxWidth: '28rem' }}>{a.summary}</div></td>
        <td>{a.count}× <div className="text-muted text-sm">first {describeInstant(a.firstSeen)}</div><div className="text-muted text-sm">last {describeInstant(a.lastSeen)}</div></td>
        <td>{delivery(a)}{a.delivery.lastError && <div className="text-muted text-sm" style={{ overflowWrap: 'anywhere', maxWidth: '16rem' }}>{a.delivery.lastError}</div>}</td>
        <td>{a.status}
          {a.acknowledgedBy && <div className="text-muted text-sm">by {a.acknowledgedBy}{a.acknowledgedAt && ` ${describeInstant(a.acknowledgedAt)}`}</div>}
          {a.resolvedAt && <div className="text-muted text-sm">{describeInstant(a.resolvedAt)}</div>}
          {admin && a.status === 'open' && <div><button className="secondary-btn sm" disabled={busy} onClick={() => acknowledge(a)}>Acknowledge</button></div>}
        </td>
      </tr>)}</tbody>
    </table></div>
    {page?.items.length === 0 && <p className="empty-box">No {status === 'all' ? '' : status + ' '}alerts.</p>}
    <Pager page={page} offset={offset} onChange={setOffset} />
    {settings && <form className="settings-section" onSubmit={save}>
      <div className="modal-body">
        <h2 className="page-title">Alert settings</h2>
        <p>Recipients are mailed when an alert opens, reopens or resolves, through the mail relay. Only administrators and auditors can be recipients, and each message is withheld from anyone who has since lost that access.</p>
        <div className="form-row">
          <div className="form-group"><label className="form-label" htmlFor="alert-threshold">Login failures</label><input id="alert-threshold" className="form-input" type="number" min={1} max={1000} value={threshold} onChange={e => setThreshold(e.target.valueAsNumber)} disabled={busy || !admin} required /></div>
          <div className="form-group"><label className="form-label" htmlFor="alert-window">within minutes</label><input id="alert-window" className="form-input" type="number" min={1} max={1440} value={windowMinutes} onChange={e => setWindowMinutes(e.target.valueAsNumber)} disabled={busy || !admin} required /></div>
        </div>
        <div className="form-group"><label className="form-label" htmlFor="alert-recipients">Recipients (usernames, comma separated)</label><input id="alert-recipients" className="form-input" value={recipients} onChange={e => setRecipients(e.target.value)} disabled={busy || !admin} /></div>
        {admin && <div className="modal-footer"><button type="submit" className="primary-btn" disabled={busy}>Save</button></div>}
      </div>
    </form>}
  </div>;
}
