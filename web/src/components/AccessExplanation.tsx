import { useEffect, useState } from 'react';
import { apiJson, errorMessage } from '../api';
import { parseAccessExplanation } from '../parsers';
import type { AccessExplanation as Explanation } from '../types';
import { describeInstant } from '../instant';

const REASONS: Record<string, string> = {
  user_disabled: 'The account is disabled.',
  account_ended: 'The account has passed its end date.',
  app_disabled: 'The app is disabled.',
  client_disabled: 'The OAuth client is disabled.',
  all_active_users: 'The app admits every active user.',
  direct_assignment: 'A direct assignment grants access.',
  group_assignment: 'A group assignment grants access.',
  not_assigned: 'No assignment grants access.',
  grants_expired: 'Every assignment that granted access has expired.',
};

/** Why one user can or cannot open one app, from the rows that decide it. */
export function AccessExplanation({ appId, userId, username, onClose }: { appId: string; userId: string; username: string; onClose: () => void }) {
  const [e, setE] = useState<Explanation | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiJson(`/api/admin/app-registry/${encodeURIComponent(appId)}/access-users/${encodeURIComponent(userId)}/explain`, parseAccessExplanation).then(setE).catch(err => setError(errorMessage(err, 'Could not explain access')));
  }, [appId, userId]);
  return <div className="modal-backdrop">
    <div className="modal-card">
      <div className="modal-header"><h3>Access for {username}</h3><button className="close-btn" onClick={onClose} aria-label="Close">×</button></div>
      <div className="modal-body">
        {error && <div className="alert-box error" role="alert">{error}</div>}
        {e && <>
          <p><b>{e.allowed ? 'Allowed' : 'Denied'}</b> to {e.appName}. {REASONS[e.reason] ?? e.reason}</p>
          <p className="text-muted text-sm">Policy: {e.accessMode === 'all_active_users' ? 'all active users' : 'assigned users only'}, app {e.appEnabled ? 'enabled' : 'disabled'}, client {e.clientEnabled ? 'enabled' : 'disabled'}; account {e.userStatus}{e.userEndsAt ? `, ends ${describeInstant(e.userEndsAt)}` : ''}. Revisions: access {e.revision}, authentication {e.authenticationRevision}, roles {e.roleRevision}.</p>
          {e.accessEndsAt && <p className="text-muted text-sm">Access ends {describeInstant(e.accessEndsAt)}.</p>}
          <h4>Grants</h4>
          {e.grants.length === 0 ? <p className="text-muted">None.</p> : <ul>{e.grants.map((g, i) => <li key={i}>{g.kind === 'direct' ? 'Direct assignment' : `Group ${g.groupName}`}{g.sourceConnectorId ? ' (membership managed upstream)' : ''}{g.expiresAt ? ` until ${describeInstant(g.expiresAt)}` : ''}{g.live ? '' : ' (expired)'}</li>)}</ul>}
          <h4>Roles for this app</h4>
          {e.roles.length === 0 ? <p className="text-muted">None.</p> : <ul>{e.roles.map((r, i) => <li key={i}><code>{r.role}</code> {r.via === 'group' ? `via group ${r.groupName}` : 'assigned directly'}</li>)}</ul>}
          <h4>Authentication policy</h4>
          <p className="text-muted text-sm">Mode {e.authentication.mode}{e.authentication.mode === 'max_age' ? ` (${e.authentication.primaryMaxAge}s)` : ''}, factor {e.authentication.factor}{e.authentication.factorMaxAge ? ` within ${e.authentication.factorMaxAge}s` : ''}.</p>
        </>}
      </div>
      <div className="modal-footer"><button type="button" className="secondary-btn" onClick={onClose}>Close</button></div>
    </div>
  </div>;
}
