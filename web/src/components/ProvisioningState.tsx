import { useEffect, useState } from 'react';
import { ApiError, apiJson, errorMessage } from '../api';
import { parseProvisioningPage, parseReconcileJob, parseReconcileJobs, parseSuccess } from '../parsers';
import { pageSize, Pager, useDirectoryPage } from './DirectoryPage';
import { isCancelled, useStepUp } from './StepUpPrompt';
import type { DriftEntry, DriftReport, PairedSystem, ProvisioningRow, ReconcileJob } from '../types';

const observedLabel: Record<ProvisioningRow['observed'], string> = {
  '': 'Not listed yet', present_active: 'Active at target', present_inactive: 'Inactive at target', absent: 'Absent', unsupported: 'Unsupported',
};
const yesNo = (v: boolean) => (v ? 'Yes' : 'No');
const when = (iso?: string) => (iso ? new Date(iso).toLocaleString() : '');

function summary(r: DriftReport): string {
  if (!r.supported) return 'Verification unsupported for this connector';
  return `${r.listedUsers} listed · ${r.missingCount} missing · ${r.staleCount} stale · ${r.orphanedCount} orphaned · ${r.unrelated} unrelated${r.complete ? '' : ' · INCOMPLETE listing: nothing deactivated'}${r.repaired ? ' · repairs queued' : ''}`;
}

function Samples({ label, entries }: { label: string; entries: DriftEntry[] }) {
  if (entries.length === 0) return null;
  return <><strong>{label}</strong><ul>{entries.map(e => <li key={e.id}>{e.username ?? e.id} — {e.reason}</li>)}</ul></>;
}

function JobRow({ job }: { job: ReconcileJob }) {
  const r = job.result;
  return <tr>
    <td>{job.kind}</td><td>{job.status}</td><td>{job.requestedBy}</td><td>{when(job.createdAt)}</td><td>{when(job.finishedAt)}</td>
    <td>
      {r && summary(r)}
      {job.error && <div className="text-muted">{job.error}</div>}
      {r?.listingError && <div className="text-muted">{r.listingError}</div>}
      {r && r.supported && (r.missing.length + r.stale.length + r.orphaned.length > 0) && <details><summary>Sample entries</summary>
        <Samples label="Missing" entries={r.missing} /><Samples label="Stale" entries={r.stale} /><Samples label="Orphaned" entries={r.orphaned} />
      </details>}
    </td>
  </tr>;
}

export function ProvisioningState({ system, onClose }: { system: PairedSystem; onClose: () => void }) {
  const [jobs, setJobs] = useState<ReconcileJob[]>([]);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const { requestGrant, stepUpPrompt } = useStepUp();
  const scim = system.systemType === 'scim';
  const base = `/api/admin/systems/${encodeURIComponent(system.id)}`;
  const params = new URLSearchParams({ q: query, limit: String(pageSize), offset: String(offset) });
  const users = useDirectoryPage(`${base}/provisioning?${params}`, parseProvisioningPage);
  useEffect(() => { if (users.page && offset > 0 && offset >= users.page.total) setOffset(Math.max(0, offset - pageSize)); }, [users.page, offset]);

  async function loadJobs() {
    try { setJobs(await apiJson(`${base}/reconcile`, parseReconcileJobs)); }
    catch (err) { setMessage(errorMessage(err, 'Could not load reconciliation jobs')); }
  }
  useEffect(() => { void loadJobs(); }, [base]);
  function refresh() { users.reload(); void loadJobs(); }

  function failed(err: unknown, fallback: string) {
    if (isCancelled(err)) return;
    setMessage(err instanceof ApiError && err.code === 'reconcile_busy' ? 'A reconciliation is already queued or running.' : errorMessage(err, fallback));
  }
  async function preview() {
    setBusy(true);
    try { await apiJson(`${base}/reconcile/preview`, parseReconcileJob, { method: 'POST' }); setMessage('Preview queued. Refresh in a moment.'); await loadJobs(); }
    catch (err) { failed(err, 'Could not queue preview'); }
    finally { setBusy(false); }
  }
  async function repair() {
    setBusy(true);
    const path = `${base}/reconcile/repair`;
    try {
      const grant = await requestGrant(`Repair drift for '${system.name}'? Missing accounts are re-queued and orphaned managed accounts are deactivated.`, `POST ${path}`);
      await apiJson(path, parseReconcileJob, { method: 'POST', stepUpToken: grant });
      setMessage('Repair queued. Refresh in a moment.');
      await loadJobs();
    } catch (err) { failed(err, 'Could not queue repair'); }
    finally { setBusy(false); }
  }
  async function retry(userId: string) {
    setBusy(true);
    try { await apiJson(`${base}/provisioning/${encodeURIComponent(userId)}/retry`, parseSuccess, { method: 'POST' }); setMessage('Delivery re-queued.'); refresh(); }
    catch (err) { setMessage(errorMessage(err, 'Could not retry delivery')); }
    finally { setBusy(false); }
  }

  return <section className="table-card" aria-label={`Provisioning for ${system.name}`} style={{ padding: '1rem', marginBottom: '1rem' }}>
    {stepUpPrompt}
    <h3>Provisioning — {system.name}</h3>
    <p>Desired is what the directory wants now, Queued is the last state sent, Acknowledged is what the receiver confirmed, and Observed is what the last reconciliation listing saw at the target.{!scim && ' Verification is unsupported for signed webhooks: they expose no read contract.'}</p>
    <p role="status">{message}</p>
    <button className="secondary-btn sm" disabled={busy} onClick={() => void preview()}>Preview drift</button>{' '}
    <button className="secondary-btn sm" disabled={busy || !scim} onClick={() => void repair()}>Repair drift</button>{' '}
    <button className="secondary-btn sm" disabled={busy} onClick={refresh}>Refresh</button>{' '}
    <button className="secondary-btn sm" onClick={onClose}>Close</button>

    <h4>Reconciliation jobs</h4>
    {jobs.length === 0 ? <p>No reconciliation has run yet.</p> :
      <table className="admin-table"><thead><tr><th>Kind</th><th>Status</th><th>Requested by</th><th>Created</th><th>Finished</th><th>Summary</th></tr></thead>
        <tbody>{jobs.map(j => <JobRow key={j.id} job={j} />)}</tbody></table>}

    <h4>Users</h4>
    <div className="form-group"><label className="form-label" htmlFor="provisioning-search">Search users</label>
      <input id="provisioning-search" className="form-input" value={query} maxLength={200} onChange={e => { setQuery(e.target.value); setOffset(0); }} /></div>
    {users.error && <div className="alert-box error sm">{users.error}</div>}
    <table className="admin-table">
      <thead><tr><th>User</th><th>Desired</th><th>Queued</th><th>Acknowledged</th><th>Observed</th><th>Last delivery</th><th>Actions</th></tr></thead>
      <tbody>{users.page?.items.map(u => <tr key={u.userId}>
        <td>{u.displayName || u.username}<div className="text-muted">{u.username}</div></td>
        <td>{yesNo(u.desired)}</td>
        <td>{yesNo(u.recorded)}<div className="text-muted text-xs">rev {u.revision}</div></td>
        <td>{yesNo(u.acknowledged)}</td>
        <td>{observedLabel[u.observed]}{u.observedAt && <div className="text-muted">{when(u.observedAt)}</div>}</td>
        <td>
          {u.lastEvent ? <>{u.lastEvent.type} · {u.lastEvent.status}
            {u.lastEvent.error && <div className="text-muted">{u.lastEvent.error}</div>}
            {u.lastEvent.status === 'pending' && u.lastEvent.nextAttemptAt && <div className="text-muted">next attempt {when(u.lastEvent.nextAttemptAt)}</div>}
          </> : 'None'}
          {u.blocked && <div><span className="status-badge warn">Blocked</span></div>}
        </td>
        <td><button className="secondary-btn sm" disabled={busy} onClick={() => void retry(u.userId)}>Retry</button></td>
      </tr>)}</tbody>
    </table>
    <Pager page={users.page} offset={offset} onChange={setOffset} />
  </section>;
}
