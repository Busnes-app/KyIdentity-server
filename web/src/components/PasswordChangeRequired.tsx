import React, { useState } from 'react';
import { apiRequest, errorMessage } from '../api';
import { User } from '../types';
import { AuthFrame } from './AuthFrame';
import { DeviceSettings } from './DeviceSettings';
import { isCancelled, useStepUp } from './StepUpPrompt';
import { AlertCircle } from 'lucide-react';

/**
 * The step-up dialog takes the given password, and the spent grant is the server's proof of
 * it, so the form does not ask for it a second time (issue #136).
 */
export async function changeGivenPassword(newPassword: string, requestGrant: (reason: string, operation: string) => Promise<string>): Promise<void> {
  const stepUpToken = await requestGrant('Enter the password you were given to confirm it is you.', 'POST /api/user/password');
  await apiRequest('/api/user/password', { method: 'POST', stepUpToken, body: JSON.stringify({ newPassword }) });
}

/**
 * Shown instead of everything else while the account must replace a password it was
 * given (the bootstrap password, or one an administrator set). The server refuses every
 * other API and app sign-in until the change succeeds.
 */
export const PasswordChangeRequired: React.FC<{ user: User; onChanged: () => void; onLogout: () => void }> = ({ user, onChanged, onLogout }) => {
  const { requestGrant, stepUpPrompt } = useStepUp();
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [factors, setFactors] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (next !== confirm) { setError('The two new passwords do not match.'); return; }
    setBusy(true);
    try {
      await changeGivenPassword(next, requestGrant);
      onChanged();
    } catch (err) {
      if (!isCancelled(err)) setError(errorMessage(err, 'Password not changed'));
    } finally {
      setBusy(false);
    }
  };

  // A sign-in with a recovery code cannot step up for a password change; replacing the
  // lost factor first is the way through.
  if (factors) return <div className="shell"><main className="main-content" style={{ gridColumn: '1 / -1' }}>
    <button className="secondary-btn" onClick={() => setFactors(false)}>Back to choosing a password</button>
    <DeviceSettings user={user} onUserUpdate={() => {}} />
  </main></div>;

  return (
    <AuthFrame after={stepUpPrompt}>
      {error && <div className="alert-box error" role="alert"><AlertCircle size={16} aria-hidden="true" /><span>{error}</span></div>}
      <form onSubmit={submit}>
        <h2>Choose a new password</h2>
        <p className="ky-auth-note">You signed in as {user.username} with a password someone gave you. Replace it before you continue; your apps open once you have.</p>
        <p className="ky-auth-note">Use 12 to 1024 characters. Every other session is signed out.</p>
        <div className="ky-auth-field">
          <label htmlFor="forced-new">New password</label>
          <input id="forced-new" type="password" autoComplete="new-password" minLength={12} maxLength={1024} value={next} onChange={(e) => setNext(e.target.value)} disabled={busy} autoFocus required />
        </div>
        <div className="ky-auth-field">
          <label htmlFor="forced-confirm">Repeat new password</label>
          <input id="forced-confirm" type="password" autoComplete="new-password" minLength={12} maxLength={1024} value={confirm} onChange={(e) => setConfirm(e.target.value)} disabled={busy} required />
        </div>
        <button type="submit" className="ky-auth-submit" disabled={busy}>Set new password</button>
        <button type="button" className="ky-auth-link" onClick={() => setFactors(true)}>Signed in with a recovery code? Replace your factor first</button>
        <button type="button" className="ky-auth-link" onClick={onLogout}>Sign out</button>
      </form>
    </AuthFrame>
  );
};
