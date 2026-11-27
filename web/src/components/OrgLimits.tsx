import { useEffect, useState } from 'react';
import { ApiError, apiJson, apiRequest, errorMessage, isRecord } from '../api';
import { isCancelled, useStepUp } from './StepUpPrompt';

export interface OrgLimitsData {
  max_seats: number;
  seats_used: number;
  storage_bytes: number;
  storage_per_seat_bytes: number;
  pool_bytes: number;
  used_bytes: number;
  revision: number;
  org_revision: number;
  status_reason: string;
  restore_generation: string;
  storage_usage: Record<string, { used_bytes: number; reported_at: number }>;
}
export function parseOrgLimits(v: unknown): OrgLimitsData {
  if (!isRecord(v)) throw new Error('Organisation limits are malformed');
  const keys = ['max_seats', 'seats_used', 'storage_bytes', 'storage_per_seat_bytes', 'pool_bytes', 'used_bytes', 'revision', 'org_revision'];
  for (const k of keys) if (typeof v[k] !== 'number' || !Number.isSafeInteger(v[k]) || v[k] < 0) throw new Error('Organisation limits are malformed');
  if (v.restore_generation !== undefined && typeof v.restore_generation !== 'string') throw new Error('Restore generation is malformed');
  if (typeof v.status_reason !== 'string' || !isRecord(v.storage_usage)) throw new Error('Organisation limits are malformed');
  const usage: OrgLimitsData['storage_usage'] = {};
  for (const [app, u] of Object.entries(v.storage_usage)) {
    if (!isRecord(u) || typeof u.used_bytes !== 'number' || !Number.isSafeInteger(u.used_bytes) || u.used_bytes < 0 || typeof u.reported_at !== 'number' || !Number.isSafeInteger(u.reported_at)) throw new Error('Storage report is malformed');
    usage[app] = { used_bytes: u.used_bytes, reported_at: u.reported_at };
  }
  // Each field was checked at the JSON boundary above.
  return { max_seats: Number(v.max_seats), seats_used: Number(v.seats_used), storage_bytes: Number(v.storage_bytes), storage_per_seat_bytes: Number(v.storage_per_seat_bytes), pool_bytes: Number(v.pool_bytes), used_bytes: Number(v.used_bytes), revision: Number(v.revision), org_revision: Number(v.org_revision), status_reason: v.status_reason, restore_generation: typeof v.restore_generation === 'string' ? v.restore_generation : '', storage_usage: usage };
}

export function OrgLimits({ onResumed }: { onResumed: () => void }) {
  const [data, setData] = useState<OrgLimitsData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [needsAck, setNeedsAck] = useState(false);
  const [ack, setAck] = useState(false);
  const { requestGrant, stepUpPrompt } = useStepUp();
  const load = async () => { try { setData(await apiJson('/api/admin/org/limits', parseOrgLimits)); setError(null); } catch (e) { setError(errorMessage(e)); } };
  useEffect(() => { void load(); }, []);
  const save = async (e: React.FormEvent) => {
    e.preventDefault(); if (!data) return; setBusy(true); setError(null);
    try {
      const path = '/api/admin/org/limits';
      const stepUpToken = await requestGrant('Change this organisation’s seats and storage pool.', `PUT ${path}`);
      await apiRequest(path, { method: 'PUT', stepUpToken, body: JSON.stringify({ max_seats: data.max_seats, storage_bytes: data.storage_bytes, storage_per_seat_bytes: data.storage_per_seat_bytes, storage_over_pool_ack: needsAck && ack }) });
      setNeedsAck(false); setAck(false); await load();
    } catch (e) {
      if (!isCancelled(e)) {
        if (e instanceof ApiError && e.code === 'storage_over_pool') setNeedsAck(true);
        setError(errorMessage(e, 'Could not save limits'));
      }
    } finally { setBusy(false); }
  };
  const resume = async () => {
    if (!data) return; setBusy(true); setError(null);
    try {
      const path = '/api/admin/org/resume';
      const stepUpToken = await requestGrant('Confirm billing, cancellations and erasures have been reconciled, and every app has replaced its organisation cache. Resume this organisation?', `POST ${path}`);
      await apiRequest(path, { method: 'POST', stepUpToken, body: JSON.stringify({ org_revision: data.org_revision, restore_generation: data.restore_generation }) }); onResumed(); await load();
    } catch (e) { if (!isCancelled(e)) setError(errorMessage(e)); } finally { setBusy(false); }
  };
  return <div className="settings-section"><div className="modal-body">
    <h2>Seats and storage</h2>
    {error && <div className="alert-box error" role="alert">{error}<button type="button" className="secondary-btn" disabled={busy} onClick={() => void load()}>Reload</button></div>}
    {!data && !error && <p role="status">Loading limits…</p>}
    {data && <>
      <p>{data.seats_used} seats in use. Reported storage: {data.used_bytes.toLocaleString()} bytes of {data.pool_bytes.toLocaleString()} bytes.</p>
      {Object.entries(data.storage_usage).length === 0 ? <p>No app has reported storage yet.</p> : <ul>{Object.entries(data.storage_usage).map(([app, u]) => <li key={app}>{app}: {u.used_bytes.toLocaleString()} bytes · reported {new Date(u.reported_at * 1000).toLocaleString()}</li>)}</ul>}
      <form onSubmit={e => void save(e)}>
        {(['max_seats', 'storage_bytes', 'storage_per_seat_bytes'] as const).map(key => <div className="form-group" key={key}>
          <label className="form-label" htmlFor={`org-${key}`}>{key === 'max_seats' ? 'Maximum seats' : key === 'storage_bytes' ? 'Base storage (bytes)' : 'Storage per seat (bytes)'}</label>
          <input className="form-input" id={`org-${key}`} type="number" required min={key === 'max_seats' ? 1 : 0} max={key === 'max_seats' ? 1000 : key === 'storage_bytes' ? 2 ** 50 : 2 ** 44} step="1" disabled={busy} value={Number.isNaN(data[key]) ? '' : data[key]} onChange={e => { setData({ ...data, [key]: e.target.valueAsNumber }); setAck(false); }} />
        </div>)}
        {needsAck && <div className="alert-box" role="alert"><label><input type="checkbox" checked={ack} disabled={busy} onChange={e => setAck(e.target.checked)} /> The account holder acknowledges that usage exceeds the new pool. After 7 days, apps refuse additions; reads, exports and deletion remain available.</label></div>}
        <button className="primary-btn" disabled={busy || needsAck && !ack}>Save seats and storage</button>
      </form>
      {data.status_reason === 'restore_reconciliation' && <div className="alert-box" role="status"><div><p>This organisation is suspended after a restore. Reconcile billing, cancellations and erasures, and replace every app’s organisation cache before resuming.</p><button className="secondary-btn" disabled={busy} onClick={() => void resume()}>Confirm reconciliation and resume</button></div></div>}
    </>}
    {stepUpPrompt}
  </div></div>;
}
