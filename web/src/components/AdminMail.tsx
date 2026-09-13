import { useEffect, useState } from 'react';
import { apiJson, errorMessage } from '../api';
import { parseMailSettings, parseSuccess } from '../parsers';
import type { MailSettings } from '../types';
import { isCancelled, useStepUp } from './StepUpPrompt';

const empty: MailSettings = { host: '', port: 587, username: '', from: '', security: 'starttls', hasPassword: false, configured: false };

/** SMTP settings for activation and reset links. The password is write-only. */
export function AdminMail() {
  const [settings, setSettings] = useState<MailSettings>(empty);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { requestGrant, stepUpPrompt } = useStepUp();

  const reload = async () => {
    try { setSettings(await apiJson('/api/admin/mail', parseMailSettings)); } catch (err) { setError(errorMessage(err, 'Could not load mail settings')); }
  };
  useEffect(() => { void reload(); }, []);

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError(null); setNotice(null);
    try {
      const stepUpToken = await requestGrant('Changing mail delivery decides where activation and reset links are sent.', 'PUT /api/admin/mail');
      setSettings(await apiJson('/api/admin/mail', parseMailSettings, { method: 'PUT', stepUpToken, body: JSON.stringify({ ...settings, password: password || undefined }) }));
      setPassword('');
      setNotice('Saved.');
    } catch (err) { if (!isCancelled(err)) setError(errorMessage(err, 'Could not save mail settings')); } finally { setBusy(false); }
  };

  const clear = async () => {
    if (!confirm('Stop sending mail? Activation and reset links must then be handed over manually.')) return;
    setBusy(true); setError(null); setNotice(null);
    try {
      const stepUpToken = await requestGrant('Turning mail delivery off.', 'PUT /api/admin/mail');
      setSettings(await apiJson('/api/admin/mail', parseMailSettings, { method: 'PUT', stepUpToken, body: JSON.stringify({ host: '' }) }));
      setNotice('Mail delivery is off.');
    } catch (err) { if (!isCancelled(err)) setError(errorMessage(err, 'Could not clear mail settings')); } finally { setBusy(false); }
  };

  const test = async () => {
    setBusy(true); setError(null); setNotice(null);
    try {
      await apiJson('/api/admin/mail/test', parseSuccess, { method: 'POST' });
      setNotice('A test message was accepted by the relay. Check your inbox.');
    } catch (err) { setError(errorMessage(err, 'The test message was not sent')); } finally { setBusy(false); }
  };

  const set = (patch: Partial<MailSettings>) => setSettings({ ...settings, ...patch });
  return (
    <div className="admin-page">
      <div className="page-header"><h1 className="page-title">Mail delivery</h1></div>
      <p>Activation and password reset links are mailed through this relay. Without it, administrators hand links over themselves and users cannot request a reset on their own. Only TLS transports are offered.</p>
      {error && <div className="alert-box error" role="alert">{error}</div>}
      {notice && <div className="alert-box" role="status">{notice}</div>}
      <form className="settings-section" onSubmit={save}>
        <div className="modal-body">
          <div className="form-row">
            <div className="form-group flex-1"><label className="form-label" htmlFor="mail-host">SMTP host</label><input id="mail-host" className="form-input" value={settings.host} onChange={e => set({ host: e.target.value })} disabled={busy} required /></div>
            <div className="form-group"><label className="form-label" htmlFor="mail-port">Port</label><input id="mail-port" className="form-input" type="number" min={1} max={65535} value={settings.port} onChange={e => set({ port: e.target.valueAsNumber })} disabled={busy} required /></div>
            <div className="form-group"><label className="form-label" htmlFor="mail-security">Transport</label>
              <select id="mail-security" className="form-select" value={settings.security} onChange={e => set({ security: e.target.value === 'tls' ? 'tls' : 'starttls' })} disabled={busy}>
                <option value="starttls">STARTTLS (587)</option><option value="tls">TLS (465)</option>
              </select></div>
          </div>
          <div className="form-group"><label className="form-label" htmlFor="mail-from">From address</label><input id="mail-from" className="form-input" type="text" placeholder="KySignOn <id@example.com>" value={settings.from} onChange={e => set({ from: e.target.value })} disabled={busy} required /></div>
          <div className="form-row">
            <div className="form-group flex-1"><label className="form-label" htmlFor="mail-user">Username</label><input id="mail-user" className="form-input" autoComplete="off" value={settings.username} onChange={e => set({ username: e.target.value })} disabled={busy} /></div>
            <div className="form-group flex-1"><label className="form-label" htmlFor="mail-pass">Password{settings.hasPassword ? ' (stored; leave blank to keep)' : ''}</label><input id="mail-pass" className="form-input" type="password" autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} disabled={busy} /></div>
          </div>
          <div className="modal-footer">
            {settings.configured && <button type="button" className="secondary-btn" disabled={busy} onClick={clear}>Turn off</button>}
            {settings.configured && <button type="button" className="secondary-btn" disabled={busy} onClick={test}>Send test to me</button>}
            <button type="submit" className="primary-btn" disabled={busy}>Save</button>
          </div>
        </div>
      </form>
      {stepUpPrompt}
    </div>
  );
}
