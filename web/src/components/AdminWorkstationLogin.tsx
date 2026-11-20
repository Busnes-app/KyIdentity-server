import { useEffect, useRef, useState } from 'react';
import { apiJson, errorMessage } from '../api';
import { parseWorkstationApp, parseWorkstationApps } from '../parsers';
import type { WorkstationApps } from '../types';
import { days, himmelblauConf, unusableGroups, xcredsProfile } from '../workstation';
import { Modal } from './Modal';
import { isCancelled, useStepUp } from './StepUpPrompt';

interface Draft { clientId: string; name: string; grant: boolean; minutes: number; days: number; mac: boolean; password: boolean }

/**
 * Workstation login: Linux desktops sign in through Himmelblau's generic OIDC mode with the
 * device grant, Macs through XCreds with the code flow. Who may sign in is the app's
 * assigned groups (Manage access).
 */
export function AdminWorkstationLogin({ onClose, onManageAccess }: { onClose: () => void; onManageAccess: (clientId: string) => void }) {
  const [data, setData] = useState<WorkstationApps | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [newName, setNewName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState('');
  const heading = useRef<HTMLHeadingElement | null>(null);
  // Profile UUIDs, stable while the page is open.
  const profileIds = useRef<Record<string, { profile: string; payload: string }>>({});
  const idsFor = (clientId: string) => (profileIds.current[clientId] ??= { profile: crypto.randomUUID().toUpperCase(), payload: crypto.randomUUID().toUpperCase() });
  const { requestGrant, stepUpPrompt } = useStepUp();
  const reload = () => apiJson('/api/admin/workstation-apps', parseWorkstationApps).then(setData).catch(err => setError(errorMessage(err, 'Could not load workstation apps')));
  useEffect(() => { heading.current?.focus(); void reload(); }, []);

  const guard = async (fn: () => Promise<void>, failure: string) => {
    setBusy(true); setError(null);
    try { await fn(); await reload(); } catch (err) { if (!isCancelled(err)) setError(errorMessage(err, failure)); } finally { setBusy(false); }
  };
  const create = (e: React.FormEvent) => {
    e.preventDefault();
    const name = newName.trim();
    void guard(async () => {
      const stepUpToken = await requestGrant(`Add the workstation login app "${name}". Device sign-in stays off until you turn it on.`, 'POST /api/admin/workstation-apps');
      await apiJson('/api/admin/workstation-apps', parseWorkstationApp, { method: 'POST', stepUpToken, body: JSON.stringify({ clientName: name }) });
      setNewName('');
    }, 'Could not add the workstation app');
  };
  const save = (e: React.FormEvent) => {
    e.preventDefault();
    if (!draft) return;
    const d = draft;
    void guard(async () => {
      const path = `/api/admin/workstation-apps/${encodeURIComponent(d.clientId)}`;
      const stepUpToken = await requestGrant(`Change workstation login for ${d.name}. A shorter offline window shortens sessions already open; 0 ends them.`, `PUT ${path}`);
      await apiJson(path, parseWorkstationApp, { method: 'PUT', stepUpToken, body: JSON.stringify({ deviceGrantEnabled: d.grant, deviceCodeTtl: Math.round(d.minutes * 60), offlineWindow: Math.round(d.days * 86400), requirePassword: d.password, macSignIn: d.mac }) });
      setDraft(null);
    }, 'Could not save the settings');
  };
  const copy = (key: string, text: string) => { void navigator.clipboard?.writeText(text); setCopied(key); };
  const set = (patch: Partial<Draft>) => setDraft(d => (d ? { ...d, ...patch } : d));

  return <div className="admin-page">
    <div className="page-header"><h1 className="page-title" ref={heading} tabIndex={-1}>Workstation login</h1>
      <div className="action-buttons-wrap"><button className="secondary-btn" disabled={busy} onClick={onClose}>Back to app connections</button></div></div>
    <div className="page-intro">
      <p>Let people sign in to Linux desktops (through Himmelblau) and Macs (through XCreds) with their KyIdentity account. A Linux desktop shows a short code that the person approves here. A Mac shows the KyIdentity sign-in page at its login window.</p>
      <p className="text-muted">Only members of the groups you assign under Manage access may sign in. Setup, break-glass and the offline trade-off: docs/WORKSTATION-LOGIN.md.</p>
    </div>
    {error && <div className="alert-box error" role="alert">{error}</div>}
    <form className="settings-section inline-form" onSubmit={create}>
      <div className="form-row">
        <div className="form-group flex-1"><label className="form-label" htmlFor="ws-name">New workstation app</label>
          <input id="ws-name" className="form-input" maxLength={128} required placeholder="Linux desktops" value={newName} disabled={busy} onChange={e => setNewName(e.target.value)} /></div>
        <button className="primary-btn" type="submit" disabled={busy || !newName.trim()}>Add</button>
      </div>
    </form>
    {data === null && !error && <p role="status">Loading workstation apps…</p>}
    {data?.apps.length === 0 && <div className="list-empty"><h2>No workstation apps yet</h2><p>Add one to get a himmelblau.conf for Linux desktops or an XCreds profile for Macs.</p></div>}
    {data?.apps.map(app => {
      const conf = himmelblauConf(data.issuer, app);
      const profile = xcredsProfile(data.issuer, app, idsFor(app.clientId));
      const bad = unusableGroups(app.groups);
      return <section key={app.clientId} className="settings-section" aria-labelledby={`ws-${app.clientId}`}>
        <div className="section-header"><h2 id={`ws-${app.clientId}`}>{app.clientName}</h2>
          <div className="action-buttons-wrap">
            <button className="secondary-btn sm" disabled={busy} onClick={() => onManageAccess(app.clientId)}>Manage access</button>
            <button className="secondary-btn sm" disabled={busy} onClick={() => setDraft({ clientId: app.clientId, name: app.clientName, grant: app.deviceGrantEnabled, minutes: app.deviceCodeTtl / 60, days: days(app.offlineWindow), mac: app.macSignIn, password: app.requirePassword })}>Edit settings</button>
          </div></div>
        <div className="modal-body">
        <dl className="connection-details">
          <dt>Device sign-in</dt><dd>{app.deviceGrantEnabled ? <span className="ky-status" data-ky-status="success">On</span> : <span className="ky-status">Off</span>}</dd>
          <dt>Code lifetime</dt><dd>{app.deviceCodeTtl / 60} minutes</dd>
          <dt>Mac sign-in</dt><dd>{app.macSignIn ? <span className="ky-status" data-ky-status="success">On</span> : <span className="ky-status">Off</span>}</dd>
          <dt>Require password</dt><dd>{app.requirePassword ? 'Yes: every sign-in types a password' : 'No'}</dd>
          <dt>Offline window</dt><dd>{app.offlineWindow ? `${days(app.offlineWindow)} days` : 'None: each sign-in needs KyIdentity'}</dd>
          <dt>Groups</dt><dd>{app.groups.length ? app.groups.join(', ') : <span className="text-muted">None assigned</span>}</dd>
          <dt>Client ID</dt><dd><code className="cell-id">{app.clientId}</code></dd>
        </dl>
        <h3>Linux desktops</h3>
        {!app.deviceGrantEnabled && <div className="alert-box warn sm" role="note">Device sign-in is off. Turn it on with Edit settings before desktops can sign in.</div>}
        {bad.length > 0 && <div className="alert-box warn sm" role="note">Himmelblau cannot match {bad.map(g => `"${g}"`).join(', ')}: a group name with a colon, comma or outer space is left out of pam_allow_groups. Rename it to use it here.</div>}
        <div className="form-group"><label className="form-label" htmlFor={`conf-${app.clientId}`}>/etc/himmelblau/himmelblau.conf</label>
          <textarea id={`conf-${app.clientId}`} className="form-input font-mono" readOnly rows={conf.split('\n').length} value={conf} onFocus={e => e.currentTarget.select()} />
          <div className="action-buttons-wrap"><button className="secondary-btn sm" onClick={() => copy(`${app.clientId}:conf`, conf)}>Copy</button>{copied === `${app.clientId}:conf` && <span role="status" className="text-muted">Copied</span>}</div></div>
        <div className="alert-box sm" role="note"><p>Then run <code>sudo aad-tool configure-pam</code>. Keep <code>pam_unix</code> in the PAM stack and one local administrator account with a password: it still signs in when KyIdentity or the network is down.</p></div>
        <h3>Macs</h3>
        {!app.macSignIn ? <div className="alert-box sm" role="note">Mac sign-in is off. Turn it on with Edit settings to get an XCreds profile for this app.</div> : <>
          {!app.requirePassword && <div className="alert-box warn sm" role="note">Turn on Require password at sign-in. XCreds sets the Mac's password from the one typed on the KyIdentity sign-in page; a passkey or push sign-in leaves it nothing to set.</div>}
          <div className="form-group"><label className="form-label" htmlFor={`xcreds-${app.clientId}`}>XCreds configuration profile (.mobileconfig)</label>
            <textarea id={`xcreds-${app.clientId}`} className="form-input font-mono" readOnly rows={12} value={profile} onFocus={e => e.currentTarget.select()} />
            <div className="action-buttons-wrap"><button className="secondary-btn sm" onClick={() => copy(`${app.clientId}:xcreds`, profile)}>Copy</button>{copied === `${app.clientId}:xcreds` && <span role="status" className="text-muted">Copied</span>}</div></div>
          <div className="alert-box sm" role="note"><p>Install XCreds 5.9 or later, then this profile (save it as <code>KyIdentity.mobileconfig</code>; install it with your MDM or in System Settings). The Mac must trust KyIdentity's certificate. Keep one local administrator account with a password: it still signs in when KyIdentity or the network is down.</p></div>
        </>}
        </div>
      </section>;
    })}
    {draft && <Modal title={`Settings for ${draft.name}`} onClose={() => setDraft(null)}>
      <form className="modal-body" onSubmit={save}>
        <div className="form-group"><label><input type="checkbox" checked={draft.grant} disabled={busy} onChange={e => set({ grant: e.target.checked })} /> Allow device sign-in</label></div>
        <div className="form-group"><label><input type="checkbox" checked={draft.mac} disabled={busy} onChange={e => set({ mac: e.target.checked })} /> Allow Mac sign-in (XCreds)</label>
          <p className="text-muted">Registers the redirect XCreds uses, <code>{'http://127.0.0.1/xcreds'}</code>. Turning it off stops new Mac sign-ins; open sessions keep refreshing until revoked.</p></div>
        <div className="form-group"><label><input type="checkbox" checked={draft.password} disabled={busy} onChange={e => set({ password: e.target.checked })} /> Require a password at sign-in</label>
          <p className="text-muted">Every sign-in to this app types a password, even in a browser that is already signed in; MFA after it still works. Needed for Macs. Linux desktops cannot approve codes while it is on.</p></div>
        <div className="form-group"><label className="form-label" htmlFor="ws-ttl">Code lifetime (minutes)</label>
          <input id="ws-ttl" className="form-input" type="number" min={2} max={15} step={1} required value={draft.minutes} disabled={busy} onChange={e => set({ minutes: e.target.valueAsNumber })} />
          <p className="text-muted">How long a code shown on a desktop can be approved: 2 to 15 minutes.</p></div>
        <div className="form-group"><label className="form-label" htmlFor="ws-window">Offline window (days)</label>
          <input id="ws-window" className="form-input" type="number" min={0} max={30} step={1} required value={draft.days} disabled={busy} onChange={e => set({ days: e.target.valueAsNumber })} />
          <p className="text-muted">How long a desktop's sign-in lasts without reaching KyIdentity, from its last check: 0 to 30 days. 0 means every sign-in needs KyIdentity and no PIN is set up.</p>
          <div className="alert-box warn sm" role="note">A desktop that is offline keeps accepting its cached sign-in until it reaches KyIdentity again; disabling someone takes effect at their next online sign-in.</div></div>
        <div className="modal-footer"><button type="button" className="secondary-btn" disabled={busy} onClick={() => setDraft(null)}>Cancel</button><button type="submit" className="primary-btn" disabled={busy}>Save</button></div>
      </form>
    </Modal>}
    {stepUpPrompt}
  </div>;
}
