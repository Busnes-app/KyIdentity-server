import { useState, type FormEvent } from 'react';
import { apiRequest, errorMessage } from '../api';
import { useStepUp, isCancelled } from './StepUpPrompt';
import { Brand } from './Sidebar';

export function PasswordChangeView({ onChanged, onLogout }: { onChanged: () => Promise<void>; onLogout: () => Promise<void> }) {
  const [current, setCurrent] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const { requestGrant, stepUpPrompt } = useStepUp();
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (password !== confirmation) { setError('The new passwords do not match.'); return; }
    if (password === current) { setError('Choose a different password.'); return; }
    setBusy(true); setError('');
    try {
      const stepUpToken = await requestGrant('Replace your bootstrap password to continue.', 'POST /api/user/password');
      await apiRequest('/api/user/password', { method: 'POST', stepUpToken, body: JSON.stringify({ currentPassword: current, newPassword: password }) });
      setCurrent(''); setPassword(''); setConfirmation('');
      await onChanged();
    } catch (err) {
      if (!isCancelled(err)) setError(errorMessage(err, 'Password not changed. Try again.'));
    } finally { setBusy(false); }
  }
  return <main className="login-page">
    <aside className="login-intro"><Brand /><h1>Secure your administrator account.</h1></aside>
    <div className="login-col"><section className="login-card">
      <form onSubmit={submit} className="login-form">
        <h2>Replace your bootstrap password</h2>
        <p className="text-muted">Choose your own password before administering KyIdentity or signing in to an application.</p>
        <div className="form-group">
          <label className="form-label" htmlFor="bootstrap-current">Current password</label>
          <input id="bootstrap-current" className="form-input" type="password" autoComplete="current-password" value={current} onChange={e => setCurrent(e.target.value)} required disabled={busy}/>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="bootstrap-new">New password</label>
          <input id="bootstrap-new" className="form-input" type="password" autoComplete="new-password" minLength={12} maxLength={1024} value={password} onChange={e => setPassword(e.target.value)} required disabled={busy}/>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="bootstrap-confirm">Confirm new password</label>
          <input id="bootstrap-confirm" className="form-input" type="password" autoComplete="new-password" minLength={12} maxLength={1024} value={confirmation} onChange={e => setConfirmation(e.target.value)} required disabled={busy}/>
        </div>
        {error && <p className="alert-box error" role="alert">{error}</p>}
        <button className="primary-btn full-width" disabled={busy}>{busy ? 'Changing password…' : 'Change password'}</button>
        <button type="button" className="text-btn" onClick={onLogout} disabled={busy}>Sign out</button>
      </form>
      {stepUpPrompt}
    </section></div>
  </main>;
}
