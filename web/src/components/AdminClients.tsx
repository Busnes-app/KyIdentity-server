import React, { useEffect, useState } from 'react';

// Mirrors the server's registration policy. The server is the authority; this only keeps
// the form from offering a choice the API will reject.
const SUITE_CLIENT_IDS = ['kypost', 'kydns', 'kypasswords', 'kynotes', 'kybookmarks'];

const isSuiteClient = (id: string) => SUITE_CLIENT_IDS.includes(id.trim().toLowerCase());
import { OAuthClient } from '../types';
import { apiJson, apiRequest, errorMessage, isRecord } from '../api';
import { isCancelled, useStepUp } from './StepUpPrompt';
import { parseCreatedClientSecret, parseOAuthClients, parseOIDCIssuer } from '../parsers';
import { Plus, Trash2, CheckCircle, AlertTriangle, Info, KeyRound } from 'lucide-react';

export const AdminClients: React.FC = () => {
  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [issuer, setIssuer] = useState('');
  const [detailsClient, setDetailsClient] = useState<OAuthClient | null>(null);
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
    } catch {
      // A failed refresh leaves the previous list on screen.
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
      <div className="page-header">
        <div>
          <h1 className="page-title">OAuth clients</h1>
        </div>
        <button className="primary-btn sm" onClick={() => setShowModal(true)}>
          <Plus size={14} />
          <span>Register Client</span>
        </button>
      </div>

      <div className="table-card">
        <table className="admin-table">
          <thead>
            <tr>
              <th>Client Name</th>
              <th>Client ID</th>
              <th>Type</th>
              <th>Redirect URIs</th>
              <th>Status</th>
              <th className="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {clients.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center py-5 text-muted">
                  No OAuth clients registered yet.
                </td>
              </tr>
            ) : (
              clients.map((c) => {
                return (
                  <tr key={c.id}>
                    <td className="font-bold text-white">{c.clientName}</td>
                    <td className="font-mono text-cyan text-sm">{c.id}</td>
                    <td>
                      <span className="font-mono badge-type">{c.clientType.toUpperCase()}</span>
                    </td>
                    <td className="font-mono text-sm text-muted">
                      {c.redirectUris.map((uri) => (
                        <div key={uri}>{uri}</div>
                      ))}
                    </td>
                    <td>
                      <span className="status-badge active">
                        <CheckCircle size={12} /> Enabled
                      </span>
                    </td>
                    <td className="text-right">
                      <div className="action-buttons-wrap">
                        <button
                          className="icon-btn"
                          onClick={() => setDetailsClient(c)}
                          title="Show connection details"
                          aria-label={`Show connection details for ${c.clientName}`}
                        >
                          <Info size={15} />
                        </button>
                        {c.clientType === 'confidential' && (
                          <button
                            className="icon-btn"
                            onClick={() => handleRotateSecret(c)}
                            title="Issue a new client secret"
                          >
                            <KeyRound size={15} />
                          </button>
                        )}
                        <button
                          className="icon-btn danger"
                          onClick={() => handleDeleteClient(c.id)}
                          title="Delete Client"
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {detailsClient && (
        <div className="modal-backdrop" onMouseDown={() => setDetailsClient(null)}>
          <div className="modal-card client-details-modal" onMouseDown={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h3>{detailsClient.clientName} connection details</h3>
              <button
                className="close-btn"
                onClick={() => setDetailsClient(null)}
                aria-label="Close connection details"
              >
                ×
              </button>
            </div>
            <div className="modal-body connection-details">
              {[
                ['Client ID', detailsClient.id],
                ['Authorization URL', `${issuer}/oauth/authorize`],
                ['Access token URL', `${issuer}/oauth/token`],
                ['Resource URL', `${issuer}/oauth/userinfo`],
                ['Logout URL', `${issuer}/oauth/logout`],
                ['Post-logout redirect URIs', detailsClient.postLogoutRedirectUris.join(' ') || 'None registered; sign-out ends on the KySignOn page'],
                ['Back-channel logout URI', detailsClient.backchannelLogoutUri || 'None; this app is not told when a login ends'],
                ['User identifier', 'username'],
                ['Scope', detailsClient.allowedScopes.join(' ')],
                ['Auth Style', 'In Params'],
              ].map(([label, value]) => (
                <div className="form-group" key={label}>
                  <label className="form-label">{label}</label>
                  <input className="form-input font-mono" value={value} readOnly />
                </div>
              ))}
              <div className="form-group">
                <label className="form-label">Redirect URL</label>
                {detailsClient.redirectUris.map((uri) => (
                  <input className="form-input font-mono" value={uri} readOnly key={uri} />
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {showModal && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>{secretWasRotated ? 'New Client Secret' : 'Register OAuth / OIDC Client'}</h3>
              <button className="close-btn" onClick={resetForm}>
                ×
              </button>
            </div>
            {!createdClientId ? (
              <form onSubmit={handleCreateClient} className="modal-body">
                <div className="form-group">
                  <label className="form-label">Quick App Preset</label>
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
                  <label className="form-label">Client ID (optional identifier)</label>
                  <input
                    type="text"
                    className="form-input font-mono"
                    placeholder="e.g. kydns (auto-generated if empty)"
                    value={clientId}
                    onChange={(e) => setClientId(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Client Name</label>
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
                  <label className="form-label">Client Type</label>
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
                  <label className="form-label">Allowed Redirect URIs (one per line)</label>
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
                  <label className="form-label">Auto-Login / Launch URL (optional deep link for launcher)</label>
                  <input
                    type="url"
                    className="form-input font-mono"
                    placeholder="e.g. https://dns.urlxl.com/auth/sso/login or https://grafana.example.com/login/generic_oauth"
                    value={launchUrl}
                    onChange={(e) => setLaunchUrl(e.target.value)}
                  />
                  <span className="muted" style={{ fontSize: '0.75rem', marginTop: '0.25rem', display: 'block' }}>
                    If provided, clicking the app tile in the KySignOn launcher will open this exact auto-login URL.
                  </span>
                </div>

                <div className="modal-footer">
                  <button type="button" className="secondary-btn" onClick={resetForm}>
                    Cancel
                  </button>
                  <button type="submit" className="primary-btn">
                    Register Client
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
                    <label className="form-label">Client Secret (Shown once)</label>
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
          </div>
        </div>
      )}
    </div>
  );
};
