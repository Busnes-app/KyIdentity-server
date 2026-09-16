import { useEffect, useState } from 'react';
import { apiJson, apiRequest, errorMessage } from '../api';
import { parseSyncDeliveries, parseSyncReadBack } from '../parsers';
import { isCancelled, useStepUp } from './StepUpPrompt';
import type { PairedSystem } from '../types';

export function SyncDeliveries({ system, onClose }: { system: PairedSystem; onClose: () => void }) {
  const [attempts, setAttempts] = useState<ReturnType<typeof parseSyncDeliveries>>([]);
  const [message, setMessage] = useState('');
  const [allowCreateRetry, setAllowCreateRetry] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const { requestGrant, stepUpPrompt } = useStepUp();
  const base = `/api/admin/systems/${encodeURIComponent(system.id)}/deliveries`;
  async function refresh() {
    try { setAttempts(await apiJson(base, parseSyncDeliveries)); }
    catch (err) { setMessage(errorMessage(err, 'Could not load deliveries')); }
  }
  useEffect(() => { void refresh(); }, [base]);
  async function readBack(token: string) {
    setBusy(true);
    try { setMessage(await apiJson(`${base}/${encodeURIComponent(token)}/read-back`, parseSyncReadBack, { method: 'POST' })); }
    catch (err) { setMessage(errorMessage(err, 'Read-back failed')); }
    finally { setBusy(false); }
  }
  async function resume(token: string) {
    setBusy(true);
    const path = `${base}/${encodeURIComponent(token)}/resume`;
    try {
      const grant = await requestGrant('Resume this delivery after confirming the old request has finished?', `POST ${path}`);
      await apiRequest(path, { method: 'POST', stepUpToken: grant, body: JSON.stringify({ confirmedQuiescent: confirmed, allowCreateRetry }) });
      setConfirmed(false);
      setAllowCreateRetry(false);
      setMessage('Delivery released for retry. Refresh to see whether another attempt is blocked.');
      await refresh();
    } catch (err) { if (!isCancelled(err)) setMessage(errorMessage(err, 'Could not resume delivery')); }
    finally { setBusy(false); }
  }
  return <section className="table-card" aria-label={`Deliveries for ${system.name}`} style={{ padding: '1rem', marginBottom: '1rem' }}>
    {stepUpPrompt}
    <h3>In-flight and blocked deliveries — {system.name}</h3>
    <p>Expired attempts stay blocked because the remote write may still finish. Read-back is an observation, not proof that a write stopped.</p>
    <p>Before resuming: stop all KyIdentity workers, verify with the receiving service that the old request has finished, then restart one instance. Do not resume while an old worker or remote request can still write.</p>
    <label><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} /> I completed these steps and confirmed the old request has finished.</label>
    {system.systemType === 'scim' && <p><label><input type="checkbox" checked={allowCreateRetry} onChange={e => setAllowCreateRetry(e.target.checked)} /> The receiver also confirmed no account was created. Allow a fresh create if externalId lookup is still empty.</label></p>}
    <p role="status">{message}</p>
    <button className="secondary-btn sm" disabled={busy} onClick={() => void refresh()}>Refresh deliveries</button>{' '}
    <button className="secondary-btn sm" onClick={onClose}>Close deliveries</button>
    {attempts.length === 0 ? <p>No in-flight or blocked deliveries.</p> : <>
      <p>Showing up to 100 attempts, oldest first.</p>
      <table className="admin-table"><thead><tr><th>Resource ID</th><th>Event</th><th>Recovery available after</th><th>Actions</th></tr></thead>
        <tbody>{attempts.map(a => <tr key={a.token}><td>{a.userId}</td><td>{a.eventType}</td><td>{new Date(a.recoverAfter).toLocaleString()}</td><td>
          <button className="secondary-btn sm" disabled={busy} onClick={() => void readBack(a.token)}>Read remote state</button>{' '}
          <button className="secondary-btn sm" disabled={busy || !confirmed || Date.parse(a.recoverAfter) > Date.now()} onClick={() => void resume(a.token)}>Resume delivery</button>
        </td></tr>)}</tbody></table>
    </>}
  </section>;
}
