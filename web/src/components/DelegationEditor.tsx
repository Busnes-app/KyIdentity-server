import { useEffect, useState } from 'react';
import { apiAllPages, apiJson, errorMessage } from '../api';
import { parseAppRecordPage, parseDelegations } from '../parsers';
import type { AppRecord, Delegations, User } from '../types';
import { isCancelled, useStepUp } from './StepUpPrompt';
import { Modal } from './Modal';

function recordName(a: AppRecord) { return a.launcherName || a.clientName || a.systemName || a.id; }

/**
 * Delegated administration for one user. Global administrators alone set these; the
 * server reads them on every request, so a removal takes effect at once.
 */
export function DelegationEditor({ user, onClose }: { user: User; onClose: () => void }) {
  // null until the current delegations load: Save replaces them all, so saving over an
  // unloaded form would strip every power the user holds.
  const [d, setD] = useState<Delegations | null>(null);
  const [apps, setApps] = useState<AppRecord[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { requestGrant, stepUpPrompt } = useStepUp();
  const path = `/api/admin/users/${encodeURIComponent(user.id)}/delegations`;

  useEffect(() => {
    apiJson(path, parseDelegations).then(setD).catch(err => setError(errorMessage(err, 'Could not load delegations')));
    apiAllPages('/api/admin/app-registry', parseAppRecordPage).then(setApps).catch(err => setError(errorMessage(err, 'Could not load app connections')));
  }, [path]);

  const save = async () => {
    if (!d) return;
    setBusy(true); setError(null);
    try {
      const stepUpToken = await requestGrant(`Change what ${user.username} may administer.`, `PUT ${path}`);
      setD(await apiJson(path, parseDelegations, { method: 'PUT', stepUpToken, body: JSON.stringify(d) }));
      onClose();
    } catch (err) { if (!isCancelled(err)) setError(errorMessage(err, 'Change refused')); } finally { setBusy(false); }
  };
  const toggleApp = (id: string, on: boolean) => d && setD({ ...d, appOwner: on ? [...d.appOwner, id] : d.appOwner.filter(a => a !== id) });
  const locked = busy || !d;

  return <Modal title={`Delegation for ${user.username}`} onClose={onClose}>
  {stepUpPrompt}
    <div className="modal-body">
      {error && <div className="alert-box error sm" role="alert">{error}</div>}
      {user.role === 'admin' ? <p className="text-muted">Administrators hold every permission; delegation applies to ordinary users.</p> : !d ? (!error && <p className="text-muted">Loading…</p>) : <>
        <div className="form-group"><label><input type="checkbox" checked={d.helpdesk} disabled={locked} onChange={e => setD({ ...d, helpdesk: e.target.checked })} /> Helpdesk: reset MFA, revoke sessions and issue links for ordinary users, never for administrators</label></div>
        <div className="form-group"><label><input type="checkbox" checked={d.auditor} disabled={locked} onChange={e => setD({ ...d, auditor: e.target.checked })} /> Auditor: read every administration page, change nothing</label></div>
        <div className="form-group"><span className="form-label">App owner: manage grants and role mappings of these apps only</span>
          {apps?.length === 0 && <p className="text-muted">No app connections yet.</p>}
          {apps?.map(a => <div key={a.id}><label><input type="checkbox" checked={d.appOwner.includes(a.id)} disabled={locked} onChange={e => toggleApp(a.id, e.target.checked)} /> {recordName(a)}</label></div>)}
        </div>
      </>}
    </div>
    <div className="modal-footer">
      <button type="button" className="secondary-btn" disabled={busy} onClick={onClose}>Cancel</button>
      {user.role !== 'admin' && <button type="button" className="primary-btn" disabled={locked} onClick={save}>Save</button>}
      </div>
  </Modal>;
}
