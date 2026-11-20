import React, { useEffect, useId, useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { apiJson, errorMessage } from '../api';
import { parseAccountLink, parseActiveDirectory, parseAgentToken, parseCreatedSystem, parseSuccess } from '../parsers';
import { isCancelled, useStepUp } from './StepUpPrompt';
import type { ActiveDirectory, ADPasswordState, ADPasswordStatus, ADSettingsInput, PairedSystem } from '../types';

type RequestGrant = (reason: string, operation: string) => Promise<string>;

export const blankAD: ADSettingsInput = { ldapsUrl: '', bindPassword: '', bindDn: '', baseDn: '', caPem: '', agentPublicKey: '', passwordTtlMinutes: 1440 };

export const passwordStates: Record<ADPasswordState, { status: 'success' | 'warning' | 'danger'; word: string }> = {
  current: { status: 'success', word: 'In directory' },
  locked: { status: 'warning', word: 'Locked until the user sets a password' },
  pending: { status: 'warning', word: 'Waiting for agent' },
  stale: { status: 'warning', word: 'Older password in directory' },
  rejected: { status: 'danger', word: 'Rejected by directory' },
  missing: { status: 'warning', word: 'Password not yet in directory' },
};

const errorWords: Record<string, string> = {
  password_policy: 'Directory password policy refused it',
  decrypt_failed: 'Agent could not decrypt it',
  replay_refused: 'Agent refused an out-of-order entry',
  user_not_found: 'Account not in directory yet',
  directory_error: 'Directory error',
  expired: 'Expired before the agent applied it',
  agent_key_replaced: 'Agent key replaced',
  restored: 'Discarded by a restore',
};

/** The users who cannot sign in to a domain PC with their KyIdentity password yet. */
export const needsRequest = (p: ADPasswordStatus) => p.state === 'missing' || p.state === 'stale' || p.state === 'rejected';

export async function createActiveDirectory(name: string, ad: ADSettingsInput, requestGrant: RequestGrant) {
  const grant = await requestGrant(`Connecting '${name || 'this directory'}' writes directory accounts and passwords to it.`, 'POST /api/admin/systems');
  const { ldapsUrl, bindPassword, ...activeDirectory } = ad;
  return apiJson('/api/admin/systems', parseCreatedSystem, {
    method: 'POST', stepUpToken: grant,
    body: JSON.stringify({ name, systemType: 'active_directory', callbackUrl: ldapsUrl.trim(), bearerToken: bindPassword, activeDirectory }),
  });
}

/** Mails the user a reset link; setting a new password queues it for the directory. */
export async function sendPasswordRequest(user: Pick<ADPasswordStatus, 'userId' | 'username'>, requestGrant: RequestGrant) {
  const path = `/api/admin/users/${encodeURIComponent(user.userId)}/reset-link`;
  const grant = await requestGrant(`Mail '${user.username}' a link to set a new password? Whoever holds it can set the password.`, `POST ${path}`);
  return apiJson(path, parseAccountLink, { method: 'POST', stepUpToken: grant, body: JSON.stringify({ send: true }) });
}

/** The connection fields shared by the add form and the settings panel. The bind password is never pre-filled. */
export function ADFields({ value, onChange, passwordSet }: { value: ADSettingsInput; onChange: (v: ADSettingsInput) => void; passwordSet: boolean }) {
  const id = useId();
  const text = (key: Exclude<keyof ADSettingsInput, 'passwordTtlMinutes'>) => ({
    id: id + key, value: value[key],
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => onChange({ ...value, [key]: e.target.value }),
  });
  return <>
    <div className="form-group">
      <label className="form-label" htmlFor={id + 'ldapsUrl'}>LDAPS URL</label>
      <input className="form-input font-mono" type="url" placeholder="ldaps://dc1.example.org" required pattern="ldaps://.+" {...text('ldapsUrl')} />
      <span className="muted">LDAPS only; plain LDAP and StartTLS are refused.</span>
    </div>
    <div className="form-group">
      <label className="form-label" htmlFor={id + 'caPem'}>CA or DC certificate (PEM)</label>
      <textarea className="form-textarea font-mono" rows={4} placeholder="-----BEGIN CERTIFICATE-----" required {...text('caPem')} />
      <span className="muted">KyIdentity trusts only this certificate for the domain controller, not the system store.</span>
    </div>
    <div className="form-group">
      <label className="form-label" htmlFor={id + 'bindDn'}>Bind DN</label>
      <input className="form-input font-mono" placeholder="CN=kyidentity-sync,CN=Users,DC=example,DC=org" required {...text('bindDn')} />
    </div>
    <div className="form-group">
      <label className="form-label" htmlFor={id + 'bindPassword'}>{passwordSet ? 'Replace bind password' : 'Bind password'}</label>
      {passwordSet && <span className="muted">Bind password: set</span>}
      <input className="form-input" type="password" autoComplete="new-password" required={!passwordSet} maxLength={1024} {...text('bindPassword')} />
      <span className="muted">{passwordSet ? 'Leave blank to keep the current password.' : 'Stored encrypted. The saved password is never displayed.'}</span>
    </div>
    <div className="form-group">
      <label className="form-label" htmlFor={id + 'baseDn'}>OU (base DN)</label>
      <input className="form-input font-mono" placeholder="OU=KyIdentity,DC=example,DC=org" required {...text('baseDn')} />
      <span className="muted">Accounts and groups are created in, and only touched inside, this OU.</span>
    </div>
    <div className="form-group">
      <label className="form-label" htmlFor={id + 'agentPublicKey'}>Agent public key (optional)</label>
      <input className="form-input font-mono" placeholder="x25519:…" {...text('agentPublicKey')} />
      <span className="muted">Printed by <code>kyidentity-dc-agent init</code> on the domain controller. Passwords are sealed to it.</span>
    </div>
    <div className="form-group">
      <label className="form-label" htmlFor={id + 'ttl'}>Password lifetime in minutes</label>
      <input id={id + 'ttl'} className="form-input" type="number" min={10} max={1440} step={1} required value={value.passwordTtlMinutes}
        onChange={(e) => onChange({ ...value, passwordTtlMinutes: Math.trunc(Number(e.target.value)) })} />
      <span className="muted">How long a sealed password waits for the agent (10–1440).</span>
    </div>
  </>;
}

/** A new agent token, shown once. */
export function IssuedAgentToken({ token }: { token: string }) {
  const [copied, setCopied] = useState(false);
  return <div className="pin-box" role="status">
    <span className="pairing-token-text font-mono">{token}</span>
    <button type="button" className="secondary-btn sm" onClick={() => { void navigator.clipboard.writeText(token); setCopied(true); }}>
      {copied ? <Check size={13} /> : <Copy size={13} />}<span>{copied ? 'Copied token' : 'Copy agent token'}</span>
    </button>
    <span className="muted">Copy it to the DC agent now. It will not be shown again.</span>
  </div>;
}

export function DirectoryPasswords({ passwords, busy, onRequest }: { passwords: ADPasswordStatus[]; busy: boolean; onRequest: (p: ADPasswordStatus) => void }) {
  const blocked = passwords.filter(needsRequest).length;
  if (passwords.length === 0) return <p>No managed users yet.</p>;
  return <>
    <p>{blocked === 0 ? 'Every managed user can sign in to a PC.' : <strong>{blocked} {blocked === 1 ? 'user cannot' : 'users cannot'} sign in to a PC yet.</strong>}</p>
    <table className="admin-table app-records-table">
      <thead><tr><th>User</th><th>Directory password</th><th>Detail</th><th><span className="sr-only">Actions</span></th></tr></thead>
      <tbody>{passwords.map((p) => <tr key={p.userId}>
        <td data-label="User"><div>{p.displayName || p.username}<span className="cell-meta">{p.username}</span></div></td>
        <td data-label="Directory password"><span className="ky-status" data-ky-status={passwordStates[p.state].status}>{passwordStates[p.state].word}</span></td>
        <td data-label="Detail"><div>
          {p.lastError && <span className="cell-meta">{errorWords[p.lastError] ?? p.lastError}</span>}
          {p.deliveredAt && <span className="cell-meta">Applied {new Date(p.deliveredAt).toLocaleString()}</span>}
          {p.state === 'pending' && p.expiresAt && <span className="cell-meta">Expires {new Date(p.expiresAt).toLocaleString()}</span>}
        </div></td>
        <td data-label={needsRequest(p) ? 'Actions' : undefined} className="text-right">
          {needsRequest(p) && <button type="button" className="secondary-btn sm" disabled={busy} onClick={() => onRequest(p)}>Send password-change request</button>}
        </td>
      </tr>)}</tbody>
    </table>
  </>;
}

/** Per-connector settings, agent token and directory passwords for an Active Directory row. */
export function ActiveDirectoryPanel({ system, onClose, onTest }: { system: PairedSystem; onClose: () => void; onTest: () => void }) {
  const [data, setData] = useState<ActiveDirectory | null>(null);
  const [form, setForm] = useState<ADSettingsInput>(blankAD);
  const [token, setToken] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const { requestGrant, stepUpPrompt } = useStepUp();
  const path = `/api/admin/systems/${encodeURIComponent(system.id)}/active-directory`;

  async function load() {
    try {
      const d = await apiJson(path, parseActiveDirectory);
      const { bindDn, baseDn, caPem, agentPublicKey, passwordTtlMinutes } = d.settings;
      setData(d);
      setForm({ ldapsUrl: d.ldapsUrl, bindPassword: '', bindDn, baseDn, caPem, agentPublicKey, passwordTtlMinutes });
    } catch (err) { setMessage(errorMessage(err, 'Could not load the directory connector')); }
  }
  useEffect(() => { void load(); }, [path]);

  async function run(work: () => Promise<string>) {
    setBusy(true);
    try { setMessage(await work()); }
    catch (err) { if (!isCancelled(err)) setMessage(errorMessage(err, 'The request failed')); }
    finally { setBusy(false); }
  }
  const save = (e: React.FormEvent) => { e.preventDefault(); void run(async () => {
    const grant = await requestGrant(`Update the directory connection for '${system.name}'?`, `PUT ${path}`);
    await apiJson(path, parseSuccess, { method: 'PUT', stepUpToken: grant, body: JSON.stringify(form) });
    await load();
    return 'Settings saved.';
  }); };
  const issueToken = () => void run(async () => {
    const tokenPath = `${path}/agent-token`;
    const grant = await requestGrant(`${data?.settings.agentTokenSet ? 'Replace' : 'Issue'} the agent token for '${system.name}'? An existing agent stops until it gets the new token.`, `POST ${tokenPath}`);
    setToken(await apiJson(tokenPath, parseAgentToken, { method: 'POST', stepUpToken: grant }));
    await load();
    return '';
  });
  const request = (p: ADPasswordStatus) => void run(async () => {
    await sendPasswordRequest(p, requestGrant);
    return `Password-change request mailed to ${p.username}.`;
  });

  return <section className="table-card" aria-label={`Active Directory for ${system.name}`} style={{ padding: '1rem', marginBottom: '1rem' }}>
    {stepUpPrompt}
    <h3>Active Directory — {system.name}</h3>
    <p role="status">{message}</p>
    <button className="secondary-btn sm" disabled={busy} onClick={onTest}>Test connection</button>{' '}
    <button className="secondary-btn sm" disabled={busy || !data} onClick={issueToken}>{data?.settings.agentTokenSet ? 'Replace agent token' : 'Issue agent token'}</button>{' '}
    <button className="secondary-btn sm" disabled={busy} onClick={() => void load()}>Refresh</button>{' '}
    <button className="secondary-btn sm" onClick={onClose}>Close</button>
    {token && <IssuedAgentToken token={token} />}
    {data && <>
      <div className="form-group">
        <label className="form-label" htmlFor={`signing-${system.id}`}>KyIdentity signing key</label>
        <input id={`signing-${system.id}`} className="form-input font-mono" readOnly value={data.entrySigningKey} />
        <span className="muted">Put this in the agent configuration as <code>kyidentitySigningKey</code>; the agent refuses entries it does not sign.</span>
      </div>
      <h4>Directory passwords</h4>
      <DirectoryPasswords passwords={data.passwords} busy={busy} onRequest={request} />
      <details className="settings-section">
        <summary>Connection settings</summary>
        <form onSubmit={save}>
          <ADFields value={form} onChange={setForm} passwordSet />
          <button type="submit" className="primary-btn sm" disabled={busy}>Save settings</button>
        </form>
      </details>
    </>}
  </section>;
}
