import { useEffect, useRef, useState } from 'react';
import { apiJson, apiRequest, errorMessage } from '../api';
import { parseEdgeSecret, parseProxyApps } from '../parsers';
import type { ProxyApp } from '../types';
import { Modal } from './Modal';
import { isCancelled, useStepUp } from './StepUpPrompt';

interface Draft { id?: string; name: string; host: string; loginHeader: string; bypass: string; hours: number }
const empty: Draft = { name: '', host: '', loginHeader: 'X-Ky-User', bypass: '', hours: 12 };

/**
 * Forward-auth proxy apps: KyIdentity answers the edge's auth_request for one exact host.
 * The edge secret is shown once; access and the MFA policy live on App connections.
 */
export function AdminProxyApps({ onClose }: { onClose: () => void }) {
  const [apps, setApps] = useState<ProxyApp[] | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [secret, setSecret] = useState<{ host: string; value: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const heading = useRef<HTMLHeadingElement | null>(null);
  const { requestGrant, stepUpPrompt } = useStepUp();
  const reload = () => apiJson('/api/admin/proxy-apps', parseProxyApps).then(setApps).catch(err => setError(errorMessage(err, 'Could not load proxy apps')));
  useEffect(() => { heading.current?.focus(); void reload(); }, []);

  const guard = async (fn: () => Promise<void>, failure: string) => {
    setBusy(true); setError(null);
    try { await fn(); await reload(); } catch (err) { if (!isCancelled(err)) setError(errorMessage(err, failure)); } finally { setBusy(false); }
  };
  const save = (e: React.FormEvent) => {
    e.preventDefault();
    if (!draft) return;
    const d = draft;
    void guard(async () => {
      const body = JSON.stringify({ name: d.name.trim(), host: d.host.trim(), loginHeader: d.loginHeader.trim(), sessionSeconds: Math.round(d.hours * 3600),
        bypass: d.bypass.split('\n').map(p => p.trim()).filter(Boolean) });
      if (d.id) {
        const path = `/api/admin/proxy-apps/${encodeURIComponent(d.id)}`;
        const stepUpToken = await requestGrant(`Change the edge settings for ${d.host}. A new host signs everyone out of it.`, `PUT ${path}`);
        await apiRequest(path, { method: 'PUT', stepUpToken, body });
      } else {
        const stepUpToken = await requestGrant(`Protect ${d.host} with KyIdentity. Its edge secret is shown once.`, 'POST /api/admin/proxy-apps');
        const value = await apiJson('/api/admin/proxy-apps', parseEdgeSecret, { method: 'POST', stepUpToken, body });
        setSecret({ host: d.host.trim(), value });
      }
      setDraft(null);
    }, 'Could not save the proxy app');
  };
  const rotate = (a: ProxyApp) => void guard(async () => {
    const path = `/api/admin/proxy-apps/${encodeURIComponent(a.id)}/secret`;
    const stepUpToken = await requestGrant(`Replace the edge secret for ${a.host}. The old one stops working within 30 seconds.`, `POST ${path}`);
    setSecret({ host: a.host, value: await apiJson(path, parseEdgeSecret, { method: 'POST', stepUpToken }) });
  }, 'Could not replace the secret');
  const remove = (a: ProxyApp) => {
    if (!confirm(`Delete the proxy app for ${a.host}? Everyone is signed out of it and the edge refuses every request until it is set up again.`)) return;
    void guard(() => apiRequest(`/api/admin/applications/${encodeURIComponent(a.id)}`, { method: 'DELETE' }).then(() => undefined), 'Could not delete the proxy app');
  };
  const set = (patch: Partial<Draft>) => setDraft(d => (d ? { ...d, ...patch } : d));

  return <div className="admin-page">
    <div className="page-header"><h1 className="page-title" ref={heading} tabIndex={-1}>Proxy apps</h1>
      <div className="action-buttons-wrap"><button className="secondary-btn" disabled={busy} onClick={onClose}>Back to app connections</button>
        <button className="primary-btn" disabled={busy} onClick={() => setDraft({ ...empty })}>Add proxy app</button></div></div>
    <div className="page-intro">
      <p>Protect a web app behind the edge proxy, including one with no single sign-on of its own. The edge asks KyIdentity on every request; each app host gets its own cookie, so no cookie is shared between apps.</p>
      <p className="text-muted">Assign users and groups, and choose the MFA policy, with Manage access and Authentication on App connections. New proxy apps require MFA and assigned users. Edge setup: docs/FORWARD-AUTH.md.</p>
    </div>
    <details className="settings-section"><summary>How the app takes the sign-in</summary>
      <ul>
        <li><strong>Header login.</strong> The app trusts a header the edge sets, such as <code>X-WEBAUTH-USER</code> or <code>Remote-User</code>. Set it as the login header below. Only safe when the app cannot be reached except through the edge.</li>
        <li><strong>OIDC.</strong> If the app supports OpenID Connect, register an OAuth client for it instead. Do not use a proxy app for it.</li>
        <li><strong>Gate only.</strong> KyIdentity decides who reaches the app, and the user still signs in to the app itself.</li>
      </ul>
    </details>
    {error && <div className="alert-box error" role="alert">{error}</div>}
    {apps === null && !error && <p role="status">Loading proxy apps…</p>}
    {apps?.length === 0 && <div className="list-empty"><h2>No proxy apps yet</h2><p>Add one to protect an app behind the edge.</p></div>}
    {Boolean(apps?.length) && <div className="table-card"><table className="admin-table"><thead><tr><th>App</th><th>Host</th><th>Login header</th><th>Bypass paths</th><th>Session</th><th>Actions</th></tr></thead>
      <tbody>{apps?.map(a => <tr key={a.id}>
        <td data-label="App">{a.name}</td><td data-label="Host"><code>{a.host}</code></td><td data-label="Login header"><code>{a.loginHeader}</code></td>
        <td data-label="Bypass paths">{a.bypass.length ? a.bypass.map(p => <div key={p}><code>{p}</code> <span className="ky-status" data-ky-status="warning">Not checked</span></div>) : <span className="text-muted">None</span>}</td>
        <td data-label="Session">{Math.round(a.sessionSeconds / 360) / 10} h</td>
        <td data-label="Actions"><div className="action-buttons-wrap">
          <button className="secondary-btn sm" disabled={busy} onClick={() => setDraft({ id: a.id, name: a.name, host: a.host, loginHeader: a.loginHeader, bypass: a.bypass.join('\n'), hours: a.sessionSeconds / 3600 })}>Edit</button>
          <button className="secondary-btn sm" disabled={busy} onClick={() => rotate(a)}>Replace secret</button>
          <button className="secondary-btn sm" disabled={busy} onClick={() => remove(a)}>Delete</button></div></td>
      </tr>)}</tbody></table></div>}
    {draft && <Modal title={draft.id ? `Edit ${draft.host}` : 'Add proxy app'} onClose={() => setDraft(null)}>
      <form className="modal-body" onSubmit={save}>
        {!draft.id && <div className="form-group"><label className="form-label" htmlFor="proxy-name">Name on the launcher</label>
          <input id="proxy-name" className="form-input" maxLength={100} required value={draft.name} disabled={busy} onChange={e => set({ name: e.target.value })} /></div>}
        <div className="form-group"><label className="form-label" htmlFor="proxy-host">Exact host</label>
          <input id="proxy-host" className="form-input" required placeholder="grafana.example.com" value={draft.host} disabled={busy} onChange={e => set({ host: e.target.value.toLowerCase() })} />
          <p className="text-muted">One host name, no scheme, port, path or wildcard.</p></div>
        <div className="form-group"><label className="form-label" htmlFor="proxy-header">Login header</label>
          <input id="proxy-header" className="form-input font-mono" required maxLength={64} value={draft.loginHeader} disabled={busy} onChange={e => set({ loginHeader: e.target.value })} />
          <div className="alert-box warn sm" role="note">The app must be reachable only through the edge proxy. Anyone who can reach it directly can send this header and be signed in as anyone.</div></div>
        <div className="form-group"><label className="form-label" htmlFor="proxy-bypass">Bypass path prefixes (one per line)</label>
          <textarea id="proxy-bypass" className="form-input font-mono" rows={3} placeholder="/api/health" value={draft.bypass} disabled={busy} onChange={e => set({ bypass: e.target.value })} />
          <div className="alert-box warn sm" role="note">KyIdentity does not check these paths. Anyone can open them, signed in or not, and they carry no user headers.</div></div>
        <div className="form-group"><label className="form-label" htmlFor="proxy-hours">Session length (hours)</label>
          <input id="proxy-hours" className="form-input" type="number" min={0.25} max={168} step={0.25} required value={draft.hours} disabled={busy} onChange={e => set({ hours: e.target.valueAsNumber })} /></div>
      <div className="modal-footer"><button type="button" className="secondary-btn" disabled={busy} onClick={() => setDraft(null)}>Cancel</button><button type="submit" className="primary-btn" disabled={busy}>{draft.id ? 'Save' : 'Add proxy app'}</button></div></form>
    </Modal>}
    {secret && <Modal title={`Edge secret for ${secret.host}`} onClose={() => setSecret(null)}>
      <div className="modal-body">
        <p>Put this in the edge's configuration for this host as the <code>X-Ky-Edge-Secret</code> header. It is shown once and stored only as a hash; replace it if it is lost.</p>
        <div className="form-group"><input className="form-input font-mono" readOnly value={secret.value} onFocus={e => e.currentTarget.select()} aria-label="Edge secret" /></div>
      </div>
      <div className="modal-footer"><button type="button" className="secondary-btn" onClick={() => navigator.clipboard?.writeText(secret.value)}>Copy</button><button type="button" className="primary-btn" onClick={() => setSecret(null)}>Close</button></div>
    </Modal>}
    {stepUpPrompt}
  </div>;
}
