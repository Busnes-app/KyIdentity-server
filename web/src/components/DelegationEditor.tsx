import { useEffect, useState } from 'react';
import { apiJson, errorMessage } from '../api';
import { parseAppRecordPage, parseDelegations } from '../parsers';
import type { AppRecord, Delegations, User } from '../types';
import { isCancelled, useStepUp } from './StepUpPrompt';

function recordName(a: AppRecord) { return a.launcherName || a.clientName || a.systemName || a.id; }

/**
 * Delegated administration for one user. Global administrators alone set these; the
 * server reads them on every request, so a removal takes effect at once.
 */
export function DelegationEditor({ user, onClose }: { user: User; onClose: () => void }) {
  const [d, setD] = useState<Delegations>({ helpdesk: false, auditor: false, appOwner: [] });
  const [apps, setApps] = useState<AppRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { requestGrant, stepUpPrompt } = useStepUp();
  const path = `/api/admin/users/${encodeURIComponent(user.id)}/delegations`;

  useEffect(() => {
    apiJson(path, parseDelegations).then(setD).catch(err => setError(errorMessage(err, 'Could not load delegations')));
    apiJson('/api/admin/app-registry?limit=100', parseAppRecordPage).then(p => setApps(p.items)).catch(() => setApps([]));
  }, [path]);

  const save = async () => {
    setBusy(true); setError(null);
    try {
      const stepUpToken = await requestGrant(`Change what ${user.username} may administer.`, `PUT ${path}`);
      setD(await apiJson(path, parseDelegations, { method: 'PUT', stepUpToken, body: JSON.stringify(d) }));
      onClose();
    } catch (err) { if (!isCancelled(err)) setError(errorMessage(err, 'Change refused')); } finally { setBusy(false); }
  };
  const toggleApp = (id: string, on: boolean) => setD({ ...d, appOwner: on ? [...d.appOwner, id] : d.appOwner.filter(a => a !== id) });

  return <div className="modal-backdrop">
    {stepUpPrompt}
    <div className="modal-card">
      <div className="modal-header"><h3>Delegation for {user.username}</h3><button className="close-btn" onClick={onClose} aria-label="Close">×</button></div>
      <div className="modal-body">
        {error && <div className="alert-box error sm" role="alert">{error}</div>}
        {user.role === 'admin' ? <p className="text-muted">Administrators hold every permission; delegation applies to ordinary users.</p> : <>
          <div className="form-group"><label><input type="checkbox" checked={d.helpdesk} disabled={busy} onChange={e => setD({ ...d, helpdesk: e.target.checked })} /> Helpdesk: reset MFA, revoke sessions and issue links for ordinary users, never for administrators</label></div>
          <div className="form-group"><label><input type="checkbox" checked={d.auditor} disabled={busy} onChange={e => setD({ ...d, auditor: e.target.checked })} /> Auditor: read every administration page, change nothing</label></div>
          <div className="form-group"><span className="form-label">App owner: manage grants and role mappings of these apps only</span>
            {apps.length === 0 && <p className="text-muted">No app connections yet.</p>}
            {apps.map(a => <div key={a.id}><label><input type="checkbox" checked={d.appOwner.includes(a.id)} disabled={busy} onChange={e => toggleApp(a.id, e.target.checked)} /> {recordName(a)}</label></div>)}
          </div>
        </>}
      </div>
      <div className="modal-footer">
        <button type="button" className="secondary-btn" disabled={busy} onClick={onClose}>Cancel</button>
        {user.role !== 'admin' && <button type="button" className="primary-btn" disabled={busy} onClick={save}>Save</button>}
      </div>
    </div>
  </div>;
}
