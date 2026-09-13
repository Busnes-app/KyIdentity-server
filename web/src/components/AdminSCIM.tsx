import { useEffect, useState } from 'react';
import { apiJson, apiRequest, errorMessage } from '../api';
import { parseSCIMConnectors, parseSCIMToken, parseSCIMConnector } from '../parsers';
import type { SCIMConnector, SCIMToken } from '../types';
import { isCancelled, useStepUp } from './StepUpPrompt';

const when = (iso?: string) => (iso ? new Date(iso).toLocaleString() : 'never');

/**
 * Inbound SCIM connectors: an upstream directory that owns some accounts. Tokens are
 * shown once; a disconnect must say what happens to the accounts the upstream owned.
 */
export function AdminSCIM() {
  const [connectors, setConnectors] = useState<SCIMConnector[]>([]);
  const [endpoint, setEndpoint] = useState('');
  const [name, setName] = useState('');
  const [issued, setIssued] = useState<{ connector: SCIMConnector; token: SCIMToken & { token: string } } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { requestGrant, stepUpPrompt } = useStepUp();

  const reload = async () => {
    try {
      const page = await apiJson('/api/admin/scim-connectors', parseSCIMConnectors);
      setConnectors(page.connectors);
      setEndpoint(page.endpoint);
    } catch (err) { setError(errorMessage(err, 'Could not load connectors')); }
  };
  useEffect(() => { void reload(); }, []);

  const guard = async (fn: () => Promise<void>, failure: string) => {
    setBusy(true); setError(null);
    try { await fn(); await reload(); } catch (err) { if (!isCancelled(err)) setError(errorMessage(err, failure)); } finally { setBusy(false); }
  };

  const create = (e: React.FormEvent) => {
    e.preventDefault();
    void guard(async () => {
      const stepUpToken = await requestGrant(`Connecting '${name}' lets an upstream directory create and manage accounts here.`, 'POST /api/admin/scim-connectors');
      await apiJson('/api/admin/scim-connectors', parseSCIMConnector, { method: 'POST', stepUpToken, body: JSON.stringify({ name }) });
      setName('');
    }, 'Could not create the connector');
  };

  const issue = (c: SCIMConnector, scope: 'read' | 'write') => void guard(async () => {
    const path = `/api/admin/scim-connectors/${c.id}/tokens`;
    const stepUpToken = await requestGrant(`Issuing a ${scope} token for '${c.name}'. It is shown once.`, `POST ${path}`);
    const token = await apiJson(path, parseSCIMToken, { method: 'POST', stepUpToken, body: JSON.stringify({ scope }) });
    setIssued({ connector: c, token });
  }, 'Could not issue a token');

  const revoke = (c: SCIMConnector, t: SCIMToken) => {
    if (!confirm(`Revoke this ${t.scope} token for '${c.name}'? The upstream stops immediately.`)) return;
    void guard(() => apiRequest(`/api/admin/scim-connectors/${c.id}/tokens/${t.id}`, { method: 'DELETE' }).then(() => undefined), 'Could not revoke the token');
  };

  const toggle = (c: SCIMConnector) => void guard(async () => {
    const status = c.status === 'active' ? 'disabled' : 'active';
    const stepUpToken = await requestGrant(`${status === 'disabled' ? 'Pausing' : 'Resuming'} '${c.name}'.`, `PUT /api/admin/scim-connectors/${c.id}`);
    await apiRequest(`/api/admin/scim-connectors/${c.id}`, { method: 'PUT', stepUpToken, body: JSON.stringify({ name: c.name, status }) });
  }, 'Could not change the connector');

  const disconnect = (c: SCIMConnector) => {
    const choice = c.users === 0 ? 'keep' : prompt(`Disconnect '${c.name}'? It owns ${c.users} account${c.users === 1 ? '' : 's'}. Type KEEP to make them local accounts as they are, or DISABLE to sign them out and disable them first.`);
    if (choice === null) return;
    const users = choice.trim().toUpperCase() === 'DISABLE' ? 'disable' : choice.trim().toUpperCase() === 'KEEP' ? 'keep' : null;
    if (!users) { setError('Type KEEP or DISABLE to disconnect.'); return; }
    void guard(async () => {
      const stepUpToken = await requestGrant(`Disconnecting '${c.name}' and ${users === 'disable' ? 'disabling' : 'keeping'} its ${c.users} account(s).`, `DELETE /api/admin/scim-connectors/${c.id}`);
      await apiRequest(`/api/admin/scim-connectors/${c.id}`, { method: 'DELETE', stepUpToken, body: JSON.stringify({ users }) });
    }, 'Could not disconnect');
  };

  return (
    <div className="admin-page">
      <div className="page-header"><h1 className="page-title">Inbound SCIM</h1></div>
      <p>An upstream directory pushes users here over SCIM 2.0 at <code>{endpoint || '…'}</code> with a connector token. Accounts it creates are invited, never given a password, and its profile fields stay read-only locally; a local disable is an override the upstream cannot lift.</p>
      {error && <div className="alert-box error" role="alert">{error}</div>}
      <form className="settings-section" onSubmit={create}>
        <div className="form-row">
          <div className="form-group flex-1"><label className="form-label" htmlFor="scim-name">New connector name</label><input id="scim-name" className="form-input" value={name} onChange={e => setName(e.target.value)} disabled={busy} required /></div>
          <div className="form-group"><label className="form-label">&nbsp;</label><button type="submit" className="primary-btn" disabled={busy || !name.trim()}>Connect</button></div>
        </div>
      </form>
      <div className="device-list">
        {connectors.length === 0 ? <div className="empty-box"><p>No upstream directory is connected.</p></div> : connectors.map(c => (
          <div key={c.id} className="settings-section">
            <div className="section-header">
              <div className="section-title-wrap">
                <h2>{c.name} <span className={`status-badge ${c.status === 'active' ? 'active' : 'disabled'}`}>{c.status === 'active' ? 'Active' : 'Paused'}</span></h2>
                <p className="section-desc">{c.users} owned account{c.users === 1 ? '' : 's'} · created {when(c.createdAt)}</p>
              </div>
              <div className="action-buttons-wrap">
                <button className="secondary-btn sm" disabled={busy} onClick={() => issue(c, 'write')}>Issue write token</button>
                <button className="secondary-btn sm" disabled={busy} onClick={() => issue(c, 'read')}>Issue read token</button>
                <button className="secondary-btn sm" disabled={busy} onClick={() => toggle(c)}>{c.status === 'active' ? 'Pause' : 'Resume'}</button>
                <button className="secondary-btn sm" disabled={busy} onClick={() => disconnect(c)}>Disconnect</button>
              </div>
            </div>
            <table className="admin-table"><thead><tr><th>Token</th><th>Scope</th><th>Issued</th><th>Last used</th><th>Status</th><th></th></tr></thead><tbody>
              {c.tokens.length === 0 ? <tr><td colSpan={6} className="text-muted">No token issued yet; the upstream cannot connect.</td></tr> : c.tokens.map(t => (
                <tr key={t.id}>
                  <td className="font-mono">{t.id.slice(0, 8)}</td><td>{t.scope}</td><td>{when(t.createdAt)}</td><td>{when(t.lastUsedAt)}</td>
                  <td>{t.revokedAt ? `Revoked ${when(t.revokedAt)}` : 'Live'}</td>
                  <td className="text-right">{!t.revokedAt && <button className="secondary-btn sm" disabled={busy} onClick={() => revoke(c, t)}>Revoke</button>}</td>
                </tr>
              ))}
            </tbody></table>
          </div>
        ))}
      </div>
      {issued && (
        <div className="modal-backdrop"><div className="modal-card">
          <div className="modal-header"><h3>{issued.token.scope === 'write' ? 'Write' : 'Read'} token for {issued.connector.name}</h3><button className="close-btn" onClick={() => setIssued(null)} aria-label="Close">×</button></div>
          <div className="modal-body">
            <p>Paste this into the upstream directory as its Bearer token. It is shown once and stored only as a hash; issue another if it is lost.</p>
            <div className="form-group"><input className="form-input font-mono" readOnly value={issued.token.token} onFocus={e => e.currentTarget.select()} aria-label="Connector token" /></div>
            <p className="text-muted">SCIM base URL: <code>{endpoint}</code></p>
          </div>
          <div className="modal-footer"><button type="button" className="secondary-btn" onClick={() => navigator.clipboard?.writeText(issued.token.token)}>Copy</button><button type="button" className="primary-btn" onClick={() => setIssued(null)}>Close</button></div>
        </div></div>
      )}
      {stepUpPrompt}
    </div>
  );
}
