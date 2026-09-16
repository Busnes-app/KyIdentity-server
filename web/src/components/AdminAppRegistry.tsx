import { useEffect, useRef, useState } from 'react';
import { apiRequest, errorMessage } from '../api';
import { parseAppRecordPage } from '../parsers';
import type { AppRecord } from '../types';
import { pageSize, Pager, useDirectoryPage } from './DirectoryPage';
import { AdminAppAuthentication } from './AdminAppAuthentication';
import { AdminAppAccess } from './AdminAppAccess';
import { AdminAppRoles } from './AdminAppRoles';
import { isCancelled, useStepUp } from './StepUpPrompt';

function recordName(a: AppRecord) { return a.launcherName || a.clientName || a.systemName || a.id; }
function Connections({ app }: { app: AppRecord }) {
  return <div style={{ overflowWrap: 'anywhere' }}>
    {app.clientId && <p>OAuth: {app.clientName}<br /><code>{app.clientId}</code></p>}
    {app.launcherId && <p>Launcher: {app.launcherName}<br /><code>{app.launcherId}</code></p>}
    {app.systemId && <p>Provisioning: {app.systemName}<br /><code>{app.systemId}</code></p>}
  </div>;
}
function compatible(a: AppRecord, b: AppRecord) {
  return a.id !== b.id && !(a.clientId && b.clientId) && !(a.launcherId && b.launcherId) && !(a.systemId && b.systemId);
}

export function AdminAppRegistry({ onManageLaunchers }: { onManageLaunchers: () => void }) {
  const [authenticationApp, setAuthenticationApp] = useState<AppRecord | null>(null);
  const [accessApp, setAccessApp] = useState<AppRecord | null>(null);
  const [rolesApp, setRolesApp] = useState<AppRecord | null>(null);
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [target, setTarget] = useState<AppRecord | null>(null);
  const [source, setSource] = useState<AppRecord | null>(null);
  const selectionHeading = useRef<HTMLHeadingElement | null>(null);
  useEffect(() => { selectionHeading.current?.focus(); }, [target?.id, source?.id]);
  const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const { requestGrant, stepUpPrompt } = useStepUp();
  const params = new URLSearchParams({ q: query, limit: String(pageSize), offset: String(offset) });
  const { page, error, reload } = useDirectoryPage(`/api/admin/app-registry?${params}`, parseAppRecordPage);
  useEffect(() => { if (page && offset > 0 && offset >= page.total) setOffset(Math.max(0, offset - pageSize)); }, [page, offset]);
  const mutate = async (app: AppRecord, operation: 'link' | 'unlink', body: object, reason: string) => {
    setBusy(true); setMutationError(null);
    const path = `/api/admin/app-registry/${encodeURIComponent(app.id)}/${operation}`;
    try {
      const stepUpToken = await requestGrant(reason, `POST ${path}`);
      await apiRequest(path, { method: 'POST', stepUpToken, body: JSON.stringify(body) });
      setTarget(null); setSource(null); reload();
    } catch (err) {
      if (!isCancelled(err)) { setMutationError(errorMessage(err, 'Could not change app links')); setTarget(null); setSource(null); reload(); }
    } finally { setBusy(false); }
  };
  if (authenticationApp) return <AdminAppAuthentication app={authenticationApp} onClose={() => { setAuthenticationApp(null); reload(); }} />;
  if (accessApp) return <AdminAppAccess app={accessApp} onClose={() => { setAccessApp(null); reload(); }} onChanged={reload} />;
  if (rolesApp) return <AdminAppRoles app={rolesApp} onClose={() => { setRolesApp(null); reload(); }} />;
  return <div className="admin-page">
    <div className="page-header"><div><h1 className="page-title">App connections</h1><button className="secondary-btn" onClick={onManageLaunchers}>Manage launcher cards</button>
      <p>Link the OAuth client, launcher card, and provisioning connection that belong to the same app.</p>
      <p className="text-muted">Manage app access here. New apps require assignments; existing apps retain all-active-user access until you change it. Provisioning keeps its current scope.</p>
    </div></div>
    {(error || mutationError) && <div className="alert-box error" role="alert">{mutationError || error} <button className="secondary-btn sm" onClick={reload}>Refresh</button></div>}
    {target && <section className="settings-section" aria-label="Selected app">
      <div className="section-header"><h2 ref={selectionHeading} tabIndex={-1}>Link connections to {recordName(target)}</h2><button className="secondary-btn" disabled={busy} onClick={() => { setTarget(null); setSource(null); }}>Cancel selection</button></div>
      <div className="modal-body"><p>Retained app ID: <code style={{ overflowWrap: 'anywhere' }}>{target.id}</code></p><Connections app={target} />
        {source ? <><h3>Add connections from {recordName(source)}</h3><Connections app={source} />
          <p>Source app ID: <code style={{ overflowWrap: 'anywhere' }}>{source.id}</code></p>
          <p>Connection IDs and credentials are preserved. Linking requires matching access and authentication settings and no assignments on either app. Unlinking copies current access and authentication settings and assignments.</p>
          <div className="modal-footer"><button className="primary-btn" disabled={busy} onClick={() => mutate(target, 'link', { sourceId: source.id, targetRevision: target.revision, sourceRevision: source.revision }, `Link app ${source.id} (${recordName(source)}) into ${target.id} (${recordName(target)}).`)}>Confirm link</button>
          <button className="secondary-btn" disabled={busy} onClick={() => setSource(null)}>Choose another</button></div>
        </> : <p>Select a compatible app below. Each app can have one connection of each type.</p>}
      </div>
    </section>}
    {!source && <>
      <div className="form-group"><label className="form-label" htmlFor="app-record-search">Search connection names or IDs</label>
        <input id="app-record-search" className="form-input" maxLength={200} value={query} disabled={busy} onChange={e => { setQuery(e.target.value); setOffset(0); }} /></div>
      <div className="table-card"><table className="admin-table" style={{ minWidth: '36rem' }}><thead><tr><th>App ID</th><th>Connections</th><th>Access</th><th>Actions</th></tr></thead>
        <tbody>{page?.items.map(app => <tr key={app.id}>
          <td style={{ maxWidth: '14rem', overflowWrap: 'anywhere' }}><code>{app.id}</code></td><td><Connections app={app} /></td><td>{app.enabled ? (app.accessMode === 'all_active_users' ? 'All active users' : 'Assigned users only') : 'Disabled'}<button className="secondary-btn sm" disabled={busy} onClick={() => setAccessApp(app)}>Manage access</button>{app.clientId && <button className="secondary-btn sm" disabled={busy} onClick={() => setAuthenticationApp(app)}>Authentication</button>}<button className="secondary-btn sm" disabled={busy} onClick={() => setRolesApp(app)}>Roles</button></td>
          <td>{target ? <button className="secondary-btn sm" disabled={busy || !compatible(target, app)} onClick={() => setSource(app)}>{app.id === target.id ? 'Selected app' : compatible(target, app) ? 'Select connections' : 'Overlapping types'}</button>
            : <div className="action-buttons-wrap"><button className="secondary-btn sm" disabled={busy} onClick={() => { setTarget(app); setMutationError(null); }}>Link another connection</button>
              {[app.clientId, app.launcherId, app.systemId].filter(Boolean).length > 1 && (['client', 'launcher', 'system'] satisfies Array<'client' | 'launcher' | 'system'>).map(kind => {
                const id = kind === 'client' ? app.clientId : kind === 'launcher' ? app.launcherId : app.systemId;
                return id && <button key={kind} className="secondary-btn sm" disabled={busy} onClick={() => mutate(app, 'unlink', { kind, revision: app.revision }, `Unlink ${kind} ${id} from app ${app.id} (${recordName(app)}).`)}>Unlink {kind === 'system' ? 'provisioning' : kind}</button>;
              })}
            </div>}
          </td>
        </tr>)}</tbody></table></div>
      {page?.items.length === 0 && <p className="empty-box">No matching app connections. Add an OAuth client, launcher card, or suite connection to get started.</p>}
      <Pager page={page} offset={offset} onChange={setOffset} />
    </>}
    {stepUpPrompt}
  </div>;
}
