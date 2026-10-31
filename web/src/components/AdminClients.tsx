import React, { useEffect, useId, useState } from 'react';

// Mirrors the server's registration policy. The server is the authority; this only keeps
// the form from offering a choice the API will reject.
const SUITE_CLIENT_IDS = ['kypost', 'kydns', 'kypasswords', 'kynotes', 'kybookmarks'];

const isSuiteClient = (id: string) => SUITE_CLIENT_IDS.includes(id.trim().toLowerCase());
import { OAuthClient } from '../types';
import { apiJson, apiRequest, errorMessage, isRecord } from '../api';
import { isCancelled, useStepUp } from './StepUpPrompt';
import { Modal } from './Modal';
import { parseCreatedClientSecret, parseOAuthClients, parseOIDCIssuer } from '../parsers';
import { Plus, Trash2, CheckCircle, XCircle, AlertTriangle, KeyRound, MoreHorizontal, LayoutGrid } from 'lucide-react';
import { PageHead } from './PageHead';

export const AdminClients: React.FC = () => {
  const [clients, setClients] = useState<OAuthClient[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [issuer, setIssuer] = useState('');
  const [detailsClient, setDetailsClient] = useState<OAuthClient | null>(null);
  const [launcherClient, setLauncherClient] = useState<OAuthClient | null>(null);
  const [showModal, setShowModal] = useState(false);

  const [clientId, setClientId] = useState('');
  const [clientName, setClientName] = useState('');
  const [clientType, setClientType] = useState<'public' | 'confidential'>('confidential');
  const [redirectUris, setRedirectUris] = useState('');
  const [postLogoutUris, setPostLogoutUris] = useState('');
  const [backchannelUri, setBackchannelUri] = useState('');
  const [launchUrl, setLaunchUrl] = useState('');
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);
  const [createdClientId, setCreatedClientId] = useState<string | null>(null);
  const [secretWasRotated, setSecretWasRotated] = useState(false);

  const fetchClients = async () => {
    try {
      const [nextClients, nextIssuer] = await Promise.all([
        apiJson('/api/admin/clients', parseOAuthClients),
        apiJson('/.well-known/openid-configuration', parseOIDCIssuer),
      ]);
      setClients(nextClients);
      setIssuer(nextIssuer);
      setListError(null);
    } catch (err) {
      setListError(errorMessage(err, 'Could not load OAuth clients'));
    }
  };

  useEffect(() => {
    fetchClients();
  }, []);

  const applyPreset = (presetId: string, presetName: string, defaultPath: string, autoLoginPath?: string) => {
    setClientId(presetId);
    setClientName(presetName);
    setClientType('confidential');
    const domainPrefix = presetId === 'kypasswords' ? 'passwords' : presetId === 'kypost' ? 'mail' : presetId === 'kydns' ? 'dns' : presetId === 'kybookmarks' ? 'bookmarks' : presetId === 'kynotes' ? 'notes' : presetId;
    // HTTPS only, and no loopback. A registered redirect URI is a destination the server
    // will hand an authorization code to, so pre-filling http://localhost:PORT means any
    // process that can bind that port on the user's machine collects codes for this
    // client. Add a loopback URI by hand for local development if you genuinely need one.
    const uris = [
      `https://${domainPrefix}.example.com${defaultPath}`,
      `https://${presetId}.example.com${defaultPath}`,
    ];
    if (defaultPath !== '/api/auth/oidc/callback') {
      uris.push(`https://${domainPrefix}.example.com/api/auth/oidc/callback`);
    }
    setRedirectUris(uris.join('\n'));
    if (autoLoginPath) {
      setLaunchUrl(`https://${domainPrefix}.example.com${autoLoginPath}`);
    } else {
      setLaunchUrl('');
    }
  };

  // Typing a suite service ID pins the client type, matching the server's rule.
  const suiteLocked = isSuiteClient(clientId);

  // Registering a client mints a secret and deleting one revokes every integration using it.
  // Neither should be reachable from a session cookie alone.
  const { requestGrant, stepUpPrompt } = useStepUp();

  const handleCreateClient = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!clientName || !redirectUris) return;

    const uris = redirectUris
      .split('\n')
      .map((u) => u.trim())
      .filter((u) => u.length > 0);

    try {
      const grant = await requestGrant(
        `Registering '${clientName}' issues a client secret that can request tokens for your users.`, 'POST /api/admin/clients');
      const data = await apiRequest('/api/admin/clients', {
        method: 'POST',
        stepUpToken: grant,
        body: JSON.stringify({
          clientId: clientId.trim() || undefined,
          clientName,
          clientType: suiteLocked ? 'confidential' : clientType,
          redirectUris: uris,
          postLogoutRedirectUris: postLogoutUris.split('\n').map((u) => u.trim()).filter((u) => u.length > 0),
          backchannelLogoutUri: backchannelUri.trim() || undefined,
          launchUrl: launchUrl.trim() || undefined,
          allowedScopes: ['openid', 'profile', 'email'],
        }),
      });

      const client = isRecord(data) && isRecord(data.client) ? data.client : {};
      setCreatedClientId(typeof client.id === 'string' ? client.id : clientId.trim());
      setCreatedSecret(
        isRecord(data) && typeof data.clientSecret === 'string' && data.clientSecret
          ? data.clientSecret
          : null
      );
      fetchClients();
    } catch (err) {
      if (isCancelled(err)) return;
      alert(errorMessage(err, 'Failed to create client'));
    }
  };

  /**
   * Issues a replacement secret for a client whose current one is lost or exposed.
   *
   * A secret is shown once, so without this the only recovery is delete-and-recreate, which
   * drops the registration every downstream service is configured against. Rotating revokes
   * the client's outstanding tokens server-side, so sign-in through it stays broken until
   * the new secret is in place.
   */
  const handleRotateSecret = async (client: OAuthClient) => {
    if (
      !confirm(
        `Issue a new secret for '${client.clientName}'?\n\nThe current secret stops working immediately and every token this client has issued is revoked. Sign-in through it stays broken until the new secret is configured there.`
      )
    )
      return;
    try {
      const grant = await requestGrant(
        `Rotating '${client.id}' revokes its current secret and every token issued under it.`, `PUT /api/admin/clients/${client.id}`);
      const secret = await apiJson(`/api/admin/clients/${client.id}`, parseCreatedClientSecret, {
        method: 'PUT',
        stepUpToken: grant,
        body: JSON.stringify({ rotateSecret: true }),
      });
      if (!secret) throw new Error('The server rotated nothing; the old secret is still in force');
      setCreatedClientId(client.id);
      setCreatedSecret(secret);
      setSecretWasRotated(true);
      setShowModal(true);
      fetchClients();
    } catch (err) {
      if (isCancelled(err)) return;
      alert(errorMessage(err, 'Failed to rotate client secret'));
    }
  };

  const handleDeleteClient = async (id: string) => {
    if (!confirm('Are you sure you want to delete this OAuth/OIDC client?')) return;
    try {
      const grant = await requestGrant(
        `Deleting '${id}' immediately breaks every sign-in that goes through it.`, `DELETE /api/admin/clients/${id}`);
      await apiRequest(`/api/admin/clients/${id}`, { method: 'DELETE', stepUpToken: grant });
      fetchClients();
    } catch (err) {
      if (isCancelled(err)) return;
      alert(errorMessage(err, 'Failed to delete client'));
    }
  };

  const resetForm = () => {
    setClientId('');
    setClientName('');
    setClientType('confidential');
    setRedirectUris('');
    setPostLogoutUris('');
    setBackchannelUri('');
    setLaunchUrl('');
    setCreatedSecret(null);
    setCreatedClientId(null);
    setSecretWasRotated(false);
    setShowModal(false);
  };

  return (
    <div className="admin-page">
      {stepUpPrompt}
      <PageHead
        title="OAuth clients"
        lede="Apps that send people here to sign in, with the addresses they may return to."
        action={<button type="button" className="ky-page-action" onClick={() => setShowModal(true)}>
          <Plus aria-hidden="true" />
          <span>Register client</span>
        </button>}
      />
      {listError && <div className="alert-box error" role="alert">{listError}<button className="secondary-btn sm" onClick={fetchClients}>Retry</button></div>}

      {clients?.length === 0 ? (
        <div className="list-empty">
          <h2>No OAuth clients yet</h2>
          <p>Register a client for each app that should sign people in through KyIdentity.</p>
        </div>
      ) : (
        <div className="table-card">
          <table className="admin-table clients-table">
            <thead>
              <tr>
                <th>Client</th>
                <th>Client ID</th>
                <th>Redirect URIs</th>
                <th>Status</th>
                <th className="text-right"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {clients?.map((c) => (
                <tr key={c.id}>
                  <td data-label="Client">
                    <span className="cell-title">{c.clientName}</span>
                    <span className="cell-meta">{c.clientType === 'confidential' ? 'Confidential' : 'Public'}</span>
                  </td>
                  <td data-label="Client ID" className="font-mono">{c.id}</td>
                  <td data-label="Redirect URIs" className="tabular">{c.redirectUris.length === 1 ? '1 URI' : `${c.redirectUris.length} URIs`}</td>
                  <td data-label="Status">
                    {c.enabled ? (
                      <span className="status-badge active">
                        <CheckCircle size={12} aria-hidden="true" /> Enabled
                      </span>
                    ) : (
                      <span className="status-badge disabled">
                        <XCircle size={12} aria-hidden="true" /> Disabled
                      </span>
                    )}
                  </td>
                  <td data-label="Actions" className="text-right">
                    <ClientRowActions
                      client={c}
                      onManage={() => setDetailsClient(c)}
                      onLauncher={() => setLauncherClient(c)}
                      onRotate={() => handleRotateSecret(c)}
                      onDelete={() => handleDeleteClient(c.id)}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {launcherClient && (
        <ClientLauncherDialog client={launcherClient} onClose={() => setLauncherClient(null)} onSaved={() => { setLauncherClient(null); fetchClients(); }} />
      )}

      {detailsClient && (
        <Modal title={`${detailsClient.clientName} connection details`} onClose={() => setDetailsClient(null)} className="client-details-modal" closeOnBackdrop>
          <div className="modal-body">
            <dl className="connection-details">
              {([
                ['Client ID', detailsClient.id],
                ['Authorization URL', `${issuer}/oauth/authorize`],
                ['Access token URL', `${issuer}/oauth/token`],
                ['Resource URL', `${issuer}/oauth/userinfo`],
                ['Logout URL', `${issuer}/oauth/logout`],
                ['Redirect URIs', detailsClient.redirectUris],
                ['Post-logout redirect URIs', detailsClient.postLogoutRedirectUris, 'None registered; sign-out ends on the KySignOn page'],
                ['Back-channel logout URI', detailsClient.backchannelLogoutUri, 'None; this app is not told when a login ends'],
                ['User identifier', 'username'],
                ['Scope', detailsClient.allowedScopes.join(' ')],
                ['Auth style', 'In params'],
              ] as [string, string | string[] | undefined, string?][]).map(([label, value, empty]) => {
                const values = (Array.isArray(value) ? value : [value]).filter((v): v is string => Boolean(v));
                return <React.Fragment key={label}>
                  <dt>{label}</dt>
                  <dd>{values.length === 0 ? <span className="muted-value">{empty ?? 'None'}</span>
                    : values.length === 1 ? <code>{values[0]}</code>
                    : <ul>{values.map(v => <li key={v}><code>{v}</code></li>)}</ul>}</dd>
                </React.Fragment>;
              })}
            </dl>
          </div>
        </Modal>
      )}

      {showModal && (
        <Modal title={secretWasRotated ? 'New client secret' : 'Register an OAuth client'} onClose={resetForm}>
          {!createdClientId ? (
            <form onSubmit={handleCreateClient} className="modal-body">
              <div className="form-group">
                <label className="form-label">Quick app preset</label>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="secondary-btn sm"
                    onClick={() => applyPreset('kydns', 'KyDNS Server', '/auth/sso/callback', '/auth/sso/login')}
                  >
                    + KyDNS
                  </button>
                  <button
                    type="button"
                    className="secondary-btn sm"
                    onClick={() => applyPreset('kypost', 'KyPost Mail Server', '/api/auth/oidc/callback', '/api/auth/oidc/login')}
                  >
                    + KyPost
                  </button>
                  <button
                    type="button"
                    className="secondary-btn sm"
                    onClick={() => applyPreset('kypasswords', 'KyPasswords Vault', '/api/auth/oidc/callback', '/api/auth/oidc/login')}
                  >
                    + KyPasswords
                  </button>
                  <button
                    type="button"
                    className="secondary-btn sm"
                    onClick={() => applyPreset('kybookmarks', 'KyBookmarks', '/api/auth/oidc/callback', '/api/auth/oidc/login')}
                  >
                    + KyBookmarks
                  </button>
                  <button
                    type="button"
                    className="secondary-btn sm"
                    onClick={() => applyPreset('kynotes', 'KyNotes', '/api/auth/oidc/callback', '/api/auth/oidc/login')}
                  >
                    + KyNotes
                  </button>
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Client ID (optional)</label>
                <input
                  type="text"
                  className="form-input font-mono"
                  placeholder="e.g. kydns (auto-generated if empty)"
                  value={clientId}
                  onChange={(e) => setClientId(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label className="form-label">Client name</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. KyDNS Server"
                  value={clientName}
                  onChange={(e) => setClientName(e.target.value)}
                  autoFocus
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Client type</label>
                <select
                  className="form-select"
                  value={suiteLocked ? 'confidential' : clientType}
                  disabled={suiteLocked}
                  onChange={(e) => setClientType(e.target.value === 'confidential' ? 'confidential' : 'public')}
                >
                  <option value="confidential">Confidential — server-side, gets a client secret (recommended)</option>
                  <option value="public">Public — no client secret, PKCE only</option>
                </select>

                {suiteLocked && (
                  <div className="alert-box sm" style={{ alignItems: 'flex-start' }}>
                    <CheckCircle size={16} />
                    <span>
                      <strong>{clientId.trim()}</strong> is a KySecurity suite service. It runs
                      server-side and can hold a secret, so it is always confidential.
                    </span>
                  </div>
                )}

                {!suiteLocked && clientType === 'public' && (
                  <div className="alert-box warn" role="alert" style={{ alignItems: 'flex-start' }}>
                    <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: '0.15rem' }} />
                    <span>
                      <strong>No client secret will be issued.</strong> Anyone who obtains an
                      authorization code for this client can redeem it if they also have the PKCE
                      verifier. Choose this only for a single-page app or a native app, which
                      cannot keep a secret. Any server-side service should be confidential.
                    </span>
                  </div>
                )}
              </div>

              <div className="form-group">
                <label className="form-label">Allowed redirect URIs (one per line)</label>
                <textarea
                  className="form-textarea font-mono"
                  rows={3}
                  placeholder="https://dns.example.com/auth/sso/callback"
                  value={redirectUris}
                  onChange={(e) => setRedirectUris(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Post-logout redirect URIs (optional, one per line)</label>
                <textarea
                  className="form-textarea font-mono"
                  rows={2}
                  placeholder="https://dns.example.com/signed-out"
                  value={postLogoutUris}
                  onChange={(e) => setPostLogoutUris(e.target.value)}
                />
                <span className="muted" style={{ fontSize: '0.75rem', marginTop: '0.25rem', display: 'block' }}>
                  Where the app may send the browser after it asks KySignOn to sign the user out. Exact match only.
                </span>
              </div>

              <div className="form-group">
                <label className="form-label">Back-channel logout URI (optional)</label>
                <input
                  type="url"
                  className="form-input font-mono"
                  placeholder="https://dns.example.com/auth/backchannel-logout"
                  value={backchannelUri}
                  onChange={(e) => setBackchannelUri(e.target.value)}
                />
                <span className="muted" style={{ fontSize: '0.75rem', marginTop: '0.25rem', display: 'block' }}>
                  KySignOn POSTs a signed logout token here when a login ends. Public HTTPS only; without it the app is never told.
                </span>
              </div>

              <div className="form-group">
                <label className="form-label">Launch URL (optional deep link for the launcher)</label>
                <input
                  type="url"
                  className="form-input font-mono"
                  placeholder="e.g. https://dns.example.com/auth/sso/login or https://grafana.example.com/login/generic_oauth"
                  value={launchUrl}
                  onChange={(e) => setLaunchUrl(e.target.value)}
                />
                <span className="muted" style={{ fontSize: '0.75rem', marginTop: '0.25rem', display: 'block' }}>
                  If provided, clicking the app tile in the KyIdentity launcher will open this exact auto-login URL.
                </span>
              </div>

              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={resetForm}>
                  Cancel
                </button>
                <button type="submit" className="primary-btn">
                  Register client
                </button>
              </div>
            </form>
          ) : (
            <div className="modal-body text-center">
              <div className="alert-box success">
                <CheckCircle size={16} />
                <span>
                  {secretWasRotated
                    ? 'Secret rotated. The previous secret and every token issued under it are now revoked.'
                    : 'Client registered. Assign access under App connections before users can sign in.'}
                </span>
              </div>

              <div className="form-group mt-3 text-left">
                <label className="form-label">Client ID</label>
                <input type="text" className="form-input font-mono" value={createdClientId} readOnly />
              </div>

              {createdSecret && (
                <div className="form-group text-left">
                  <label className="form-label">Client secret (shown once)</label>
                  <input type="text" className="form-input font-mono" value={createdSecret} readOnly />
                </div>
              )}

              <div className="modal-footer mt-4">
                <button className="primary-btn" onClick={resetForm}>
                  Done
                </button>
              </div>
            </div>
          )}
        </Modal>
      )}
    </div>
  );
};

/** "Manage" opens the connection details; the rarer, riskier actions sit behind the ⋯ menu. */
const ClientRowActions: React.FC<{ client: OAuthClient; onManage: () => void; onLauncher: () => void; onRotate: () => void; onDelete: () => void }> = ({ client, onManage, onLauncher, onRotate, onDelete }) => {
  const menuId = useId();
  return (
    <div className="row-actions">
      <button type="button" className="secondary-btn sm" onClick={onManage}>Manage<span className="sr-only"> {client.clientName}</span></button>
      <button type="button" className="icon-btn sm" popoverTarget={menuId} aria-label={`More actions for ${client.clientName}`}>
        <MoreHorizontal size={16} aria-hidden="true" />
      </button>
      <div id={menuId} popover="auto" className="row-actions-menu" role="group" aria-label={`More actions for ${client.clientName}`} onClickCapture={event => {
        if (event.target instanceof Element && event.target.closest('button')) event.currentTarget.hidePopover();
      }}>
        <button type="button" className="row-action" onClick={onLauncher}>
          <LayoutGrid size={15} aria-hidden="true" />Launcher card
        </button>
        {client.clientType === 'confidential' && <button type="button" className="row-action" onClick={onRotate}>
          <KeyRound size={15} aria-hidden="true" />Rotate secret
        </button>}
        <button type="button" className="row-action danger" onClick={onDelete}>
          <Trash2 size={15} aria-hidden="true" />Delete client
        </button>
      </div>
    </div>
  );
};

type Audience = 'everyone' | 'admins';

const AUDIENCES: [Audience, string, string][] = [
  ['everyone', 'Everyone with access', 'Anyone who may open the app.'],
  ['admins', "This app's administrators", "Holders of the app's administrator role, or KyIdentity administrators when it has none."],
];

/** The launcher fields to send: only those the admin changed, so an untouched unset value stays unset. */
export function launcherChanges(client: OAuthClient, name: string, audience: Audience): { launcherName?: string; launcherAudience?: Audience } {
  const changes: { launcherName?: string; launcherAudience?: Audience } = {};
  if (name.trim() !== client.launcherName) changes.launcherName = name.trim();
  if (audience !== (client.launcherAudience || 'everyone')) changes.launcherAudience = audience;
  return changes;
}

/** How the client's card reads on the launcher and who sees it. It never changes access. */
const ClientLauncherDialog: React.FC<{ client: OAuthClient; onClose: () => void; onSaved: () => void }> = ({ client, onClose, onSaved }) => {
  const [name, setName] = useState(client.launcherName);
  const [audience, setAudience] = useState<Audience>(client.launcherAudience || 'everyone');
  const [error, setError] = useState<string | null>(null);
  const save = async (event: React.FormEvent) => {
    event.preventDefault();
    const changes = launcherChanges(client, name, audience);
    if (Object.keys(changes).length === 0) return onClose();
    try {
      await apiRequest(`/api/admin/clients/${encodeURIComponent(client.id)}/launcher`, { method: 'PUT', body: JSON.stringify(changes) });
      onSaved();
    } catch (err) {
      setError(errorMessage(err, 'Could not save the launcher card'));
    }
  };
  return (
    <Modal title={`Launcher card for ${client.clientName}`} onClose={onClose} closeOnBackdrop>
      <form className="modal-body" onSubmit={save}>
        {error && <p className="alert-box error" role="alert">{error}</p>}
        <div className="form-group">
          <label className="form-label" htmlFor="launcher-name">Card name</label>
          <input id="launcher-name" className="form-input" value={name} onChange={(e) => setName(e.target.value)} maxLength={128} placeholder={client.clientName} autoFocus />
          <p className="form-hint">Leave empty to use the client name.</p>
        </div>
        <fieldset className="launcher-layout">
          <legend className="form-label">Shown to</legend>
          {AUDIENCES.map(([value, label, hint]) => (
            <label key={value}>
              <input type="radio" name="launcher-audience" value={value} checked={audience === value} onChange={() => setAudience(value)} />
              <span><b>{label}</b><small>{hint}</small></span>
            </label>
          ))}
        </fieldset>
        <p className="form-hint">Hiding the card does not remove access: people can still sign in to the app.</p>
        <div className="modal-footer">
          <button type="button" className="secondary-btn" onClick={onClose}>Cancel</button>
          <button type="submit" className="primary-btn">Save</button>
        </div>
      </form>
    </Modal>
  );
};
