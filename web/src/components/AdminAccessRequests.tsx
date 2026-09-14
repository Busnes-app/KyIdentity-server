import { useEffect, useState } from 'react';
import { apiRequest, errorMessage } from '../api';
import { parseAccessRequestPage } from '../parsers';
import type { AccessRequest } from '../types';
import { describeInstant } from '../instant';
import { pageSize, Pager, useDirectoryPage } from './DirectoryPage';
import { isCancelled, useStepUp } from './StepUpPrompt';

const STATUSES = ['pending', 'approved', 'denied', 'cancelled', 'expired', 'all'] as const;

function duration(r: AccessRequest) {
  if (!r.durationSeconds) return 'no end date';
  const days = Math.round(r.durationSeconds / 86400);
  return days >= 1 ? `${days} day${days === 1 ? '' : 's'}` : `${Math.round(r.durationSeconds / 3600)} hours`;
}

/**
 * The inbox: every request for a global administrator, the owned apps' requests for a
 * delegate. Each decision spends a step-up grant; the server re-reads authority and
 * the app's policy before granting anything.
 */
export function AdminAccessRequests() {
  const [status, setStatus] = useState<(typeof STATUSES)[number]>('pending');
  const [offset, setOffset] = useState(0);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { requestGrant, stepUpPrompt } = useStepUp();
  const params = new URLSearchParams({ status, limit: String(pageSize), offset: String(offset) });
  const { page, error: loadError, reload } = useDirectoryPage(`/api/admin/access-requests?${params}`, parseAccessRequestPage);
  useEffect(() => { if (page && offset > 0 && offset >= page.total) setOffset(Math.max(0, offset - pageSize)); }, [page, offset]);

  const decide = async (r: AccessRequest, approve: boolean) => {
    setBusy(true); setError(null);
    const path = `/api/admin/access-requests/${encodeURIComponent(r.id)}/${approve ? 'approve' : 'deny'}`;
    try {
      const stepUpToken = await requestGrant(`${approve ? 'Approve' : 'Deny'} ${r.username}'s request for ${r.appName} (${duration(r)}).`, `POST ${path}`);
      await apiRequest(path, { method: 'POST', stepUpToken, body: JSON.stringify({ note: (notes[r.id] ?? '').trim() }) });
      reload();
    } catch (err) { if (!isCancelled(err)) setError(errorMessage(err, 'Decision refused')); } finally { setBusy(false); }
  };

  return <div className="admin-page">
    {stepUpPrompt}
    <div className="page-header"><div><h1 className="page-title">Access requests</h1>
      <p>Approving grants a direct assignment for the requested duration through the same path as a manual grant. Your authority and the app's policy are checked again when you decide.</p></div></div>
    {(error || loadError) && <div className="alert-box error" role="alert">{error || loadError} <button className="secondary-btn sm" onClick={reload}>Refresh</button></div>}
    <div className="form-group"><label className="form-label" htmlFor="request-status">Show</label>
      <select id="request-status" className="form-select" value={status} onChange={e => { const v = e.target.value; if ((STATUSES as readonly string[]).includes(v)) { setStatus(v as (typeof STATUSES)[number]); setOffset(0); } }}>
        {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}</select></div>
    <div className="table-card"><table className="admin-table">
      <thead><tr><th>User</th><th>App</th><th>Reason</th><th>Duration</th><th>Status</th><th>Decision</th></tr></thead>
      <tbody>{page?.items.map(r => <tr key={r.id}>
        <td>{r.username}</td><td>{r.appName}</td>
        <td style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxWidth: '24rem' }}>{r.reason}<div className="text-muted text-sm">asked {describeInstant(r.createdAt)}</div></td>
        <td>{duration(r)}</td>
        <td>{r.status}{r.decidedAt && <div className="text-muted text-sm">{describeInstant(r.decidedAt)}</div>}{r.decisionNote && <div className="text-muted text-sm">{r.decisionNote}</div>}</td>
        <td>{r.status === 'pending' ? <div className="action-buttons-wrap">
          <input className="form-input" placeholder="Note (optional)" maxLength={500} value={notes[r.id] ?? ''} disabled={busy} onChange={e => setNotes({ ...notes, [r.id]: e.target.value })} />
          <button className="primary-btn sm" disabled={busy} onClick={() => decide(r, true)}>Approve</button>
          <button className="secondary-btn sm" disabled={busy} onClick={() => decide(r, false)}>Deny</button>
        </div> : <span className="text-muted">—</span>}</td>
      </tr>)}</tbody>
    </table></div>
    {page?.items.length === 0 && <p className="empty-box">No {status === 'all' ? '' : status + ' '}requests.</p>}
    <Pager page={page} offset={offset} onChange={setOffset} />
  </div>;
}
