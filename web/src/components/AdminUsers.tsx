import React, { useEffect, useId, useRef, useState } from 'react';
import { Access, SessionInventory, User } from '../types';
import { DelegationEditor } from './DelegationEditor';
import { apiJson, apiRequest, errorMessage } from '../api';
import { isCancelled, useStepUp } from './StepUpPrompt';
import { Modal } from './Modal';
import { describeInstant, instantFromLocal, localInputValue, localZone } from '../instant';
import { parseAccountLink, parseMailSettings, parseSessionInventory, parseUsers } from '../parsers';
import type { AccountLink } from '../types';
import { SessionList } from './SessionList';
import { OffboardingView } from './OffboardingView';
import { PageHead } from './PageHead';
import { Users, Search, Plus, RefreshCw, KeyRound, LogOut, Trash2, Edit, CheckCircle, XCircle, Monitor, UserX, Link, Clock, UserCog } from 'lucide-react';

export interface UserFilter { query: string; role: 'all' | 'admin' | 'user'; status: 'all' | 'active' | 'pending' | 'disabled' }
const NO_FILTER: UserFilter = { query: '', role: 'all', status: 'all' };

/** The toolbar's view of the list: a case-insensitive match on account, name or email, plus role and status. */
export function filterUsers(users: readonly User[], { query, role, status }: UserFilter): User[] {
  const q = query.trim().toLowerCase();
  return users.filter(u =>
    (!q || [u.username, u.displayName, u.email].some(v => v?.toLowerCase().includes(q))) &&
    (role === 'all' || u.role === role) &&
    (status === 'all' || (u.pending ? 'pending' : u.status === 'active' ? 'active' : 'disabled') === status));
}

export const AdminUsers: React.FC<{ access?: Access; onManageGroups: (user: User) => void }> = ({ access, onManageGroups }) => {
  // Buttons hide as a convenience only; the server refuses what the actor may not do.
  const full = Boolean(access?.admin);
  const [users, setUsers] = useState<User[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  // Rows with a revoke, reset or delete in flight.
  const [busyIds, setBusyIds] = useState<ReadonlySet<string>>(new Set());
  const [delegating, setDelegating] = useState<User | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [sessionsUser, setSessionsUser] = useState<User | null>(null);
  const [inventory, setInventory] = useState<SessionInventory>({ sessions: [], apps: [], logouts: [] });
  // Whose sessions are on screen, so a late response for another user is dropped.
  const sessionsFor = useRef<string | null>(null);
  // Kept as id and name, not a User, so the view survives the row's deletion.
  const [offboarding, setOffboarding] = useState<{ id: string; username: string } | null>(null);
  // An issued activation or reset link, shown once for hand-over or mailing.
  const [issued, setIssued] = useState<{ user: User; link: AccountLink } | null>(null);
  const [mailConfigured, setMailConfigured] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);
  const [filter, setFilter] = useState<UserFilter>(NO_FILTER);
  const shown = users ? filterUsers(users, filter) : [];

  // Form State
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<'user' | 'admin'>('user');
  const [status, setStatus] = useState<'active' | 'disabled'>('active');
  const [endsAt, setEndsAt] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const fetchUsers = async () => {
    try {
      setUsers(await apiJson('/api/admin/users', parseUsers));
      setListError(null);
    } catch (err) {
      setListError(errorMessage(err, 'Could not load users'));
    }
  };

  // A cancelled step-up is not a failure; anything else is reported.
  const rowAction = async (id: string, failure: string, action: () => Promise<void>) => {
    setBusyIds((ids) => new Set(ids).add(id));
    try {
      await action();
    } catch (err) {
      if (!isCancelled(err)) alert(errorMessage(err, failure));
    } finally {
      setBusyIds((ids) => { const next = new Set(ids); next.delete(id); return next; });
    }
  };

  // Creating, editing, resetting MFA for, or deleting an account are all things a stolen
  // session must not be able to do on its own, so each one re-proves the operator first.
  const { requestGrant, stepUpPrompt } = useStepUp();

  useEffect(() => {
    fetchUsers();
    // Mail settings are an administrator read; a delegate gets manual links only.
    if (full) apiJson('/api/admin/mail', parseMailSettings).then((m) => setMailConfigured(m.configured)).catch(() => setMailConfigured(false));
  }, [full]);

  // A link is minted server-side and returned once; mailing it mints a fresh one that
  // retires the shown link, so nothing shown here stays valid behind the owner's back.
  const issueLink = async (u: User, send: boolean) => {
    const kind = u.pending ? 'activation' : 'reset';
    const path = `/api/admin/users/${u.id}/${kind}-link`;
    try {
      const grant = await requestGrant(`${send ? 'Mailing' : 'Issuing'} ${kind === 'activation' ? 'an activation' : 'a reset'} link for '${u.username}' lets whoever holds it set the password.`, `POST ${path}`);
      const link = await apiJson(path, parseAccountLink, { method: 'POST', stepUpToken: grant, body: JSON.stringify({ send }) });
      setCopiedLink(false);
      setIssued({ user: u, link });
    } catch (err) {
      if (isCancelled(err)) return;
      alert(errorMessage(err, `Failed to issue the ${kind} link`));
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setSubmitting(true);

    try {
      const grant = await requestGrant(
        `Creating '${username || 'a new account'}' adds an account to this directory` +
          (role === 'admin' ? ', with administrator rights.' : '.') + (password ? '' : ' It stays pending until its activation link sets a password.'), 'POST /api/admin/users');
      const created = await apiJson('/api/admin/users', (v) => parseUsers({ users: [(v as { user: unknown }).user] })[0]!, {
        method: 'POST',
        body: JSON.stringify({ username, displayName, email, password, role, status }),
        stepUpToken: grant,
      });
      setShowCreateModal(false);
      resetForm();
      fetchUsers();
      if (created.pending) await issueLink(created, false);
    } catch (err) {
      if (isCancelled(err)) return;
      setFormError(errorMessage(err, 'Failed to create user'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleUpdateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedUser) return;
    setFormError(null);
    setSubmitting(true);

    try {
      const grant = await requestGrant(
        `Changing '${selectedUser.username}' can alter their password, role, or access.`, `PUT /api/admin/users/${selectedUser.id}`);
      await apiRequest(`/api/admin/users/${selectedUser.id}`, {
        method: 'PUT',
        body: JSON.stringify({ displayName, email, role, status, password: password || undefined, endsAt: instantFromLocal(endsAt) ?? '' }),
        stepUpToken: grant,
      });
      setShowEditModal(false);
      resetForm();
      fetchUsers();
    } catch (err) {
      if (isCancelled(err)) return;
      setFormError(errorMessage(err, 'Failed to update user'));
    } finally {
      setSubmitting(false);
    }
  };

  const resetForm = () => {
    setUsername('');
    setDisplayName('');
    setEmail('');
    setPassword('');
    setRole('user');
    setStatus('active');
    setSelectedUser(null);
    setFormError(null);
  };

  const openEditModal = (u: User) => {
    setSelectedUser(u);
    setUsername(u.username);
    setDisplayName(u.displayName || u.username);
    setEmail(u.email);
    setPassword('');
    setRole(u.role);
    setStatus(u.status || 'active');
    setEndsAt(localInputValue(u.endsAt));
    setShowEditModal(true);
  };

  const handleResetMFA = async (u: User) => {
    if (!confirm(`Are you sure you want to reset MFA for '${u.username}'? This will revoke active sessions and require re-enrollment.`)) return;

    // The server fails closed rather than reporting an unearned success, so a failure
    // message means nothing was changed.
    await rowAction(u.id, 'Failed to reset MFA', async () => {
      const grant = await requestGrant(
        `Resetting MFA for '${u.username}' removes every factor protecting that account.`, `POST /api/admin/users/${u.id}/reset-mfa`);
      await apiRequest(`/api/admin/users/${u.id}/reset-mfa`, { method: 'POST', stepUpToken: grant });
      alert(`MFA reset successfully for ${u.username}`);
      fetchUsers();
    });
  };

  // Session and app revocation stay step-up free on purpose: shrinking access during an
  // incident must not wait on a second prompt. The server audits each one.
  const loadSessions = async (u: User) => {
    try {
      const next = await apiJson(`/api/admin/users/${u.id}/sessions`, parseSessionInventory);
      if (sessionsFor.current === u.id) setInventory(next);
    } catch (err) {
      if (sessionsFor.current === u.id) alert(errorMessage(err, 'Failed to load sessions'));
    }
  };

  const openSessions = (u: User) => {
    sessionsFor.current = u.id;
    setInventory({ sessions: [], apps: [], logouts: [] });
    setSessionsUser(u);
    loadSessions(u);
  };

  const closeSessions = () => {
    sessionsFor.current = null;
    setSessionsUser(null);
  };

  const revokeFor = async (u: User, path: string, method: 'DELETE' | 'POST', failure: string) => {
    try {
      await apiRequest(path, { method });
      loadSessions(u);
    } catch (err) {
      alert(errorMessage(err, failure));
    }
  };

  const handleRevokeSessions = async (u: User) => {
    if (!confirm(`Revoke all active sessions for '${u.username}'?`)) return;

    await rowAction(u.id, 'Failed to revoke sessions', async () => {
      await apiRequest(`/api/admin/users/${u.id}/revoke-sessions`, { method: 'POST' });
      alert(`Sessions revoked for ${u.username}`);
      if (sessionsFor.current === u.id) loadSessions(u);
    });
  };

  const handleDeleteUser = async (u: User) => {
    if (!confirm(`Permanently delete account '${u.username}'? This will also replicate deletion to paired products.`)) return;

    await rowAction(u.id, 'Failed to delete user', async () => {
      const grant = await requestGrant(`Deleting '${u.username}' cannot be undone from here.`, `DELETE /api/admin/users/${u.id}`);
      await apiRequest(`/api/admin/users/${u.id}`, { method: 'DELETE', stepUpToken: grant });
      fetchUsers();
      setOffboarding({ id: u.id, username: u.username });
    });
  };

  return (
    <div className="admin-page">
      {stepUpPrompt}
      <PageHead
        title="Users"
        lede="Every account that can sign in here, with its role and current status."
        action={full && <button
          type="button"
          className="ky-page-action"
          onClick={() => {
            resetForm();
            setShowCreateModal(true);
          }}
        >
          <Plus aria-hidden="true" />
          <span>Create user</span>
        </button>}
      />
      {listError && <div className="alert-box error" role="alert">{listError}<button className="secondary-btn sm" onClick={fetchUsers}>Retry</button></div>}

      <div className="list-toolbar" role="search" aria-label="Filter users">
        <div className="list-toolbar-search">
          <Search size={16} aria-hidden="true" />
          <input type="search" className="form-input" aria-label="Search users" placeholder="Search account, name or email"
            value={filter.query} onChange={(e) => setFilter({ ...filter, query: e.target.value })} />
        </div>
        <select className="form-select" aria-label="Role" value={filter.role} onChange={(e) => setFilter({ ...filter, role: e.target.value as UserFilter['role'] })}>
          <option value="all">All roles</option>
          <option value="admin">Administrator</option>
          <option value="user">User</option>
        </select>
        <select className="form-select" aria-label="Status" value={filter.status} onChange={(e) => setFilter({ ...filter, status: e.target.value as UserFilter['status'] })}>
          <option value="all">All statuses</option>
          <option value="active">Active</option>
          <option value="pending">Pending</option>
          <option value="disabled">Disabled</option>
        </select>
        {users && <p className="list-toolbar-count" aria-live="polite">{shown.length === users.length ? `${users.length} users` : `${shown.length} of ${users.length} users`}</p>}
      </div>

      <div className="table-card">
        <table className="admin-table users-table">
          <thead>
            <tr>
              <th>Account</th>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th className="text-right"><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {users && shown.length === 0 && (
              <tr>
                <td colSpan={5} className="list-no-match">
                  No users match these filters. <button type="button" className="text-btn" onClick={() => setFilter(NO_FILTER)}>Clear filters</button>
                </td>
              </tr>
            )}
            {shown.map((u) => {
              const busy = busyIds.has(u.id);
              return (
                <tr key={u.id}>
                  <td data-label="Account">
                    <span className="cell-title">{u.displayName || u.username}{u.sourceConnectorId && <span className="status-badge warn" title={`Managed by an inbound SCIM connector (external id ${u.externalId ?? ''})`}> SCIM</span>}</span>
                    {u.displayName && u.displayName !== u.username && <span className="cell-meta font-mono">{u.username}</span>}
                  </td>
                  <td data-label="Email" className="text-muted">{u.email}</td>
                  <td data-label="Role">
                    {u.role === 'admin' ? 'Administrator' : 'User'}
                  </td>
                  <td data-label="Status">
                    {u.pending ? (
                      <span className="status-badge warn">
                        <Clock size={12} aria-hidden="true" /> Pending
                      </span>
                    ) : u.status === 'active' ? (
                      <span className="status-badge active">
                        <CheckCircle size={12} aria-hidden="true" /> Active
                      </span>
                    ) : (
                      <span className="status-badge disabled">
                        <XCircle size={12} aria-hidden="true" /> Disabled
                      </span>
                    )}
                    {u.endsAt && <div className="text-muted text-sm">Ends {describeInstant(u.endsAt)}</div>}
                  </td>
                  <td data-label="Actions" className="text-right">
                    <UserRowActions u={u} full={full} busy={busy} act={{
                      groups: onManageGroups, edit: openEditModal, delegate: setDelegating, resetMFA: handleResetMFA,
                      sessions: openSessions, revoke: handleRevokeSessions, link: (x) => issueLink(x, false),
                      offboarding: (x) => setOffboarding({ id: x.id, username: x.username }), remove: handleDeleteUser,
                    }} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {issued && (
        <Modal title={`${issued.link.kind === 'activation' ? 'Activation link' : 'Password reset link'} for ${issued.user.username}`} onClose={() => setIssued(null)}>
          <div className="modal-body">
            {issued.link.delivery === 'email' ? (
              <p>Sent to {issued.user.email}. It expires {new Date(issued.link.expiresAt).toLocaleString()}; any earlier link no longer works.</p>
            ) : (
              <>
                <p>Hand this to {issued.user.displayName || issued.user.username} over a channel you trust. It is shown once, expires {new Date(issued.link.expiresAt).toLocaleString()}, and any earlier link no longer works.</p>
                <div className="form-group">
                  <input className="form-input font-mono" readOnly value={issued.link.link ?? ''} onFocus={(e) => e.currentTarget.select()} aria-label="Account link" />
                </div>
              </>
            )}
          </div>
          <div className="modal-footer">
            {issued.link.delivery === 'manual' && <button type="button" className="secondary-btn" onClick={() => { navigator.clipboard?.writeText(issued.link.link ?? ''); setCopiedLink(true); }}>{copiedLink ? 'Copied' : 'Copy link'}</button>}
            {issued.link.delivery === 'manual' && mailConfigured && <button type="button" className="secondary-btn" onClick={() => issueLink(issued.user, true)}>Mail a new link instead</button>}
            <button type="button" className="primary-btn" onClick={() => setIssued(null)}>Close</button>
          </div>
        </Modal>
      )}

      {offboarding && <OffboardingView userId={offboarding.id} username={offboarding.username} onClose={() => setOffboarding(null)} />}
      {delegating && <DelegationEditor user={delegating} onClose={() => setDelegating(null)} />}

      {sessionsUser && (
        <Modal title={`Sessions for ${sessionsUser.username}`} onClose={closeSessions}>
          <div className="modal-body">
            <SessionList
              sessions={inventory.sessions}
              apps={inventory.apps}
              logouts={inventory.logouts}
              onRetryLogout={(d) => revokeFor(sessionsUser, `/api/admin/users/${sessionsUser.id}/logouts/${d.id}/retry`, 'POST', 'Failed to retry sign-out notification')}
              onRevokeSession={(s) => {
                if (confirm('Sign out this session?')) revokeFor(sessionsUser, `/api/admin/users/${sessionsUser.id}/sessions/${s.id}`, 'DELETE', 'Failed to revoke session');
              }}
              onRevokeApp={(a) => {
                if (confirm(`Revoke ${a.clientName} tokens for '${sessionsUser.username}'? The app may keep its own login until it next checks in.`)) {
                  revokeFor(sessionsUser, `/api/admin/users/${sessionsUser.id}/apps/${encodeURIComponent(a.clientId)}/revoke`, 'POST', 'Failed to revoke app access');
                }
              }}
            />
          </div>
          <div className="modal-footer">
            <button type="button" className="secondary-btn" disabled={busyIds.has(sessionsUser.id)} onClick={() => handleRevokeSessions(sessionsUser)}>
              Revoke everything
            </button>
            <button type="button" className="primary-btn" onClick={closeSessions}>
              Close
            </button>
          </div>
        </Modal>
      )}

      {/* Create User Modal */}
      {showCreateModal && (
        <Modal title="Create a user" onClose={() => setShowCreateModal(false)}>
          <form onSubmit={handleCreateUser} className="modal-body">
            {formError && <div className="alert-box error sm">{formError}</div>}

            <div className="form-group">
              <label className="form-label">Username</label>
              <input
                type="text"
                className="form-input"
                placeholder="e.g. bob"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoFocus
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Display name</label>
              <input
                type="text"
                className="form-input"
                placeholder="e.g. Bob Builder"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Email</label>
              <input
                type="email"
                className="form-input"
                placeholder="bob@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Initial password (min 12 chars; leave blank to invite with an activation link)</label>
              <input
                type="password"
                className="form-input"
                placeholder="Blank: the user chooses one through a link"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            <div className="form-row">
              <div className="form-group flex-1">
                <label className="form-label">Role</label>
                <select
                  className="form-select"
                  value={role}
                  onChange={(e) => setRole(e.target.value as User['role'])}
                >
                  <option value="user">User</option>
                  <option value="admin">Administrator</option>
                </select>
              </div>
              <div className="form-group flex-1">
                <label className="form-label">Status</label>
                <select
                  className="form-select"
                  value={status}
                  onChange={(e) => setStatus(e.target.value === 'disabled' ? 'disabled' : 'active')}
                >
                  <option value="active">Active</option>
                  <option value="disabled">Disabled</option>
                </select>
              </div>
            </div>

            <div className="modal-footer">
              <button type="button" className="secondary-btn" onClick={() => setShowCreateModal(false)}>
                Cancel
              </button>
              <button type="submit" className="primary-btn" disabled={submitting}>
                {submitting ? <RefreshCw className="spin" size={14} /> : <span>Create and replicate</span>}
              </button>
            </div>
          </form>
        </Modal>
      )}

      {/* Edit User Modal */}
      {showEditModal && selectedUser && (
        <Modal title={`Edit ${selectedUser.username}`} onClose={() => setShowEditModal(false)}>
          <form onSubmit={handleUpdateUser} className="modal-body">
            {formError && <div className="alert-box error sm">{formError}</div>}
            {selectedUser.sourceConnectorId && <p className="text-muted">Name and email are managed by the upstream directory. Disabling here is an override the upstream cannot lift.</p>}

            <div className="form-group">
              <label className="form-label">Display name</label>
              <input
                type="text"
                className="form-input"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                readOnly={Boolean(selectedUser.sourceConnectorId)}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Email</label>
              <input
                type="email"
                className="form-input"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                readOnly={Boolean(selectedUser.sourceConnectorId)}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label">Reset password (leave blank to keep current)</label>
              <input
                type="password"
                className="form-input"
                placeholder="New password (optional)"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            <div className="form-row">
              <div className="form-group flex-1">
                <label className="form-label">Role</label>
                <select
                  className="form-select"
                  value={role}
                  onChange={(e) => setRole(e.target.value as User['role'])}
                >
                  <option value="user">User</option>
                  <option value="admin">Administrator</option>
                </select>
              </div>
              <div className="form-group flex-1">
                <label className="form-label">Status</label>
                <select
                  className="form-select"
                  value={status}
                  onChange={(e) => setStatus(e.target.value === 'disabled' ? 'disabled' : 'active')}
                >
                  <option value="active">Active</option>
                  <option value="disabled">Disabled</option>
                </select>
              </div>
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="user-ends-at">Account end date (optional, {localZone()})</label>
              <input id="user-ends-at" type="datetime-local" className="form-input" value={endsAt} onChange={(e) => setEndsAt(e.target.value)} />
              {instantFromLocal(endsAt) && <p className="text-muted text-sm">Ends at {describeInstant(instantFromLocal(endsAt)!)}. Sessions and app access end then; the account is disabled, not deleted.</p>}
            </div>

            <div className="modal-footer">
              <button type="button" className="secondary-btn" onClick={() => setShowEditModal(false)}>
                Cancel
              </button>
              <button type="submit" className="primary-btn" disabled={submitting}>
                {submitting ? <RefreshCw className="spin" size={14} /> : <span>Save changes</span>}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};

type RowAction = (user: User) => void;

/** Every action stays one disclosure away, labelled; delete is set apart. Nothing renders when
 *  the viewer may act on none of them (a delegate looking at an administrator). */
export const UserRowActions: React.FC<{
  u: User; full: boolean; busy: boolean;
  act: Record<'groups' | 'edit' | 'delegate' | 'resetMFA' | 'sessions' | 'revoke' | 'link' | 'offboarding' | 'remove', RowAction>;
}> = ({ u, full, busy, act }) => {
  const menuId = useId();
  if (!full && u.role === 'admin') return null;
  return (
    <div className="row-actions">
      <button type="button" className="secondary-btn sm" popoverTarget={menuId}>Manage<span className="sr-only"> {u.username}</span></button>
      <div id={menuId} popover="auto" className="row-actions-menu" role="group" aria-label={`Actions for ${u.username}`} onClickCapture={event => {
        if (event.target instanceof Element && event.target.closest('button')) event.currentTarget.hidePopover();
      }}>
        {full && <button className="row-action" onClick={() => act.groups(u)} aria-label={`Manage groups for ${u.username}`}>
          <Users size={15} />Groups
        </button>}
        {full && <button className="row-action" disabled={busy} onClick={() => act.edit(u)}>
          <Edit size={15} />Edit user
        </button>}
        {full && <button className="row-action" onClick={() => act.delegate(u)} aria-label={`Delegated administration for ${u.username}`}>
          <UserCog size={15} />Delegated administration
        </button>}
        <button className="row-action" disabled={busy} onClick={() => act.resetMFA(u)}>
          <KeyRound size={15} />Reset MFA
        </button>
        <button className="row-action" onClick={() => act.sessions(u)} aria-label={`Sessions and apps for ${u.username}`}>
          <Monitor size={15} />Sessions and apps
        </button>
        <button className="row-action" disabled={busy} onClick={() => act.revoke(u)}>
          <LogOut size={15} />Revoke sessions
        </button>
        <button className="row-action" onClick={() => act.link(u)} aria-label={`${u.pending ? 'Activation' : 'Password reset'} link for ${u.username}`}>
          <Link size={15} />{u.pending ? 'Activation link' : 'Password reset link'}
        </button>
        <button className="row-action" onClick={() => act.offboarding(u)} aria-label={`Offboarding status for ${u.username}`}>
          <UserX size={15} />Offboarding status
        </button>
        {full && <button className="row-action danger" disabled={busy} onClick={() => act.remove(u)}>
          <Trash2 size={15} />Delete user
        </button>}
      </div>
    </div>
  );
};
