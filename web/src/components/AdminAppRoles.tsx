import { useEffect, useState } from 'react';
import { apiJson, apiRequest, errorMessage } from '../api';
import { parseAppRolesPage, parseGroupPage, parseUsers } from '../parsers';
import type { AppRecord, AppRole, DirectoryGroup, User } from '../types';
import { isCancelled, useStepUp } from './StepUpPrompt';

function recordName(a: AppRecord) { return a.launcherName || a.clientName || a.systemName || a.id; }

/**
 * Per-app roles and their explicit mappings. A role reaches a token only for this app,
 * under the fixed `roles` claim; every change here revokes the affected users' live
 * grants for the app, so the next sign-in carries the new set.
 */
export function AdminAppRoles({ app: initial, onClose }: { app: AppRecord; onClose: () => void }) {
  const [app, setApp] = useState<AppRecord>(initial);
  const [roles, setRoles] = useState<AppRole[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [groups, setGroups] = useState<DirectoryGroup[]>([]);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [pick, setPick] = useState<Record<string, { kind: 'users' | 'groups'; id: string }>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { requestGrant, stepUpPrompt } = useStepUp();
  const base = `/api/admin/app-registry/${encodeURIComponent(app.id)}`;

  const reload = async () => {
    try {
      const page = await apiJson(`${base}/roles`, parseAppRolesPage);
      setApp(page.app); setRoles(page.roles);
    } catch (err) { setError(errorMessage(err, 'Could not load roles')); }
  };
  useEffect(() => {
    void reload();
    apiJson('/api/admin/users', parseUsers).then(setUsers).catch(() => setUsers([]));
    apiJson('/api/admin/groups?limit=100', parseGroupPage).then(p => setGroups(p.items)).catch(() => setGroups([]));
  }, []);

  const mutate = async (reason: string, method: 'POST' | 'PUT' | 'DELETE', path: string, body?: object) => {
    setBusy(true); setError(null);
    try {
      const stepUpToken = await requestGrant(reason, `${method} ${path}`);
      await apiRequest(path, { method, stepUpToken, body: body ? JSON.stringify(body) : undefined });
      await reload();
      return true;
    } catch (err) { if (!isCancelled(err)) setError(errorMessage(err, 'Change refused')); return false; } finally { setBusy(false); }
  };

  const claimNote = 'Changing which claims this app receives revokes every live grant for it; users sign in again and get the new token shape.';
  return <div className="admin-page">
    <div className="page-header"><div><h1 className="page-title">Roles for {recordName(app)}</h1>
      <p>Roles are fixed names this app understands. Map groups or users to them; a token for this app carries exactly the roles the user holds here under the <code>roles</code> claim, and nothing about other apps. Mapping changes sign the affected users out of this app.</p></div>
      <button className="secondary-btn" disabled={busy} onClick={onClose}>Back to app connections</button></div>
    {error && <div className="alert-box error" role="alert">{error}</div>}

    <section className="settings-section">
      <div className="section-header"><div className="section-title-wrap"><h2>Claims</h2></div></div>
      <div className="form-group"><label><input type="checkbox" checked={app.legacyRoleClaim} disabled={busy} onChange={e => mutate(`${e.target.checked ? 'Keep' : 'Drop'} the legacy global role claim for ${recordName(app)}. ${claimNote}`, 'PUT', `${base}/claims`, { legacyRoleClaim: e.target.checked, groupsClaim: app.groupsClaim, revision: app.revision })} /> Include the legacy global <code>role</code> claim (compatibility for clients built before app roles; turn off once the app reads <code>roles</code>)</label></div>
      <div className="form-group"><label><input type="checkbox" checked={app.groupsClaim} disabled={busy} onChange={e => mutate(`${e.target.checked ? 'Add' : 'Remove'} the groups claim for ${recordName(app)}. ${claimNote}`, 'PUT', `${base}/claims`, { legacyRoleClaim: app.legacyRoleClaim, groupsClaim: e.target.checked, revision: app.revision })} /> Include a <code>groups</code> claim listing the assigned or role-mapped groups the user belongs to</label></div>
    </section>

    <form className="settings-section" onSubmit={async e => { e.preventDefault(); if (await mutate(`Create role '${name.trim()}' for ${recordName(app)}.`, 'POST', `${base}/roles`, { name: name.trim(), description: description.trim() })) { setName(''); setDescription(''); } }}>
      <div className="section-header"><div className="section-title-wrap"><h2>New role</h2></div></div>
      <div className="form-row">
        <div className="form-group flex-1"><label className="form-label" htmlFor="role-name">Name (letters, digits, _ . : -)</label><input id="role-name" className="form-input font-mono" value={name} maxLength={64} disabled={busy} onChange={e => setName(e.target.value)} required /></div>
        <div className="form-group flex-1"><label className="form-label" htmlFor="role-description">Description</label><input id="role-description" className="form-input" value={description} maxLength={512} disabled={busy} onChange={e => setDescription(e.target.value)} /></div>
        <div className="form-group"><label className="form-label">&nbsp;</label><button className="primary-btn" disabled={busy || !name.trim()}>Add role</button></div>
      </div>
    </form>

    {roles.length === 0 ? <p className="empty-box">No roles yet. Without roles the app's tokens carry an empty <code>roles</code> list{app.legacyRoleClaim ? ' plus the legacy global role' : ''}.</p> : roles.map(role => {
      const chosen = pick[role.id] ?? { kind: 'groups', id: '' };
      const mappedUsers = new Set(role.users.map(u => u.id)); const mappedGroups = new Set(role.groups.map(g => g.id));
      return <section key={role.id} className="settings-section">
        <div className="section-header"><div className="section-title-wrap"><h2><code>{role.name}</code></h2>{role.description && <p className="section-desc">{role.description}</p>}</div>
          <button className="secondary-btn sm" disabled={busy} onClick={() => mutate(`Delete role '${role.name}' from ${recordName(app)}; its ${role.users.length + role.groups.length} mapping(s) go with it.`, 'DELETE', `${base}/roles/${role.id}`)}>Delete role</button></div>
        <div className="device-list">
          {role.groups.map(g => <div key={g.id} className="device-card"><div className="device-info"><span className="device-name">Group: {g.name}</span></div><button className="secondary-btn sm" disabled={busy} onClick={() => mutate(`Unmap group '${g.name}' from role '${role.name}'.`, 'DELETE', `${base}/roles/${role.id}/assignments/groups/${g.id}`)}>Unmap</button></div>)}
          {role.users.map(u => <div key={u.id} className="device-card"><div className="device-info"><span className="device-name">User: {u.name}</span></div><button className="secondary-btn sm" disabled={busy} onClick={() => mutate(`Unmap user '${u.name}' from role '${role.name}'.`, 'DELETE', `${base}/roles/${role.id}/assignments/users/${u.id}`)}>Unmap</button></div>)}
          {role.groups.length + role.users.length === 0 && <div className="empty-box"><p>Nothing mapped; nobody holds this role.</p></div>}
        </div>
        <div className="form-row">
          <div className="form-group"><label className="form-label" htmlFor={`kind-${role.id}`}>Map a</label>
            <select id={`kind-${role.id}`} className="form-select" value={chosen.kind} disabled={busy} onChange={e => setPick({ ...pick, [role.id]: { kind: e.target.value === 'users' ? 'users' : 'groups', id: '' } })}><option value="groups">group</option><option value="users">user</option></select></div>
          <div className="form-group flex-1"><label className="form-label" htmlFor={`principal-${role.id}`}>to this role</label>
            <select id={`principal-${role.id}`} className="form-select" value={chosen.id} disabled={busy} onChange={e => setPick({ ...pick, [role.id]: { ...chosen, id: e.target.value } })}>
              <option value="">Choose…</option>
              {chosen.kind === 'groups' ? groups.filter(g => !mappedGroups.has(g.id)).map(g => <option key={g.id} value={g.id}>{g.name}</option>) : users.filter(u => !mappedUsers.has(u.id)).map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
            </select></div>
          <div className="form-group"><label className="form-label">&nbsp;</label><button className="secondary-btn" disabled={busy || !chosen.id} onClick={async () => { if (await mutate(`Map ${chosen.kind === 'groups' ? 'group' : 'user'} to role '${role.name}' for ${recordName(app)}.`, 'PUT', `${base}/roles/${role.id}/assignments/${chosen.kind}/${chosen.id}`)) setPick({ ...pick, [role.id]: { ...chosen, id: '' } }); }}>Map</button></div>
        </div>
      </section>;
    })}
    {stepUpPrompt}
  </div>;
}
