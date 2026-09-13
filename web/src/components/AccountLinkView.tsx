import React, { useState } from 'react';
import { apiJson, errorMessage } from '../api';
import { parseSuccess } from '../parsers';
import { Brand } from './Sidebar';
import { AlertCircle } from 'lucide-react';

/**
 * The page an activation or reset link opens. Opening it spends nothing; only submitting
 * the form redeems the token, so a mail scanner that follows the link changes nothing.
 */
export const AccountLinkView: React.FC<{ kind: 'activation' | 'reset' }> = ({ kind }) => {
  const token = new URLSearchParams(window.location.search).get('token') ?? '';
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const title = kind === 'activation' ? 'Choose your password' : 'Choose a new password';

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirm) { setError('The two passwords do not match.'); return; }
    setBusy(true);
    setError(null);
    try {
      await apiJson(kind === 'activation' ? '/api/auth/activate' : '/api/auth/password/reset', parseSuccess, {
        method: 'POST', body: JSON.stringify({ token, password }),
      });
      setDone(true);
    } catch (err) {
      setError(errorMessage(err, 'This link could not be used'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-page">
      <aside className="login-intro"><Brand /><h1>Sign in once, then open everything.</h1></aside>
      <div className="login-col">
        <div className="login-card">
          {error && <div className="alert-box error" role="alert"><AlertCircle size={16} /><span>{error}</span></div>}
          {done ? (
            <div className="login-form">
              <h2>{kind === 'activation' ? 'Your account is ready' : 'Password changed'}</h2>
              <p className="text-muted">{kind === 'activation' ? 'Sign in with your username and the password you just chose.' : 'Every other session was signed out. Sign in with your new password.'}</p>
              <a className="primary-btn full-width" href="/">Sign in</a>
            </div>
          ) : !token ? (
            <div className="login-form"><h2>Missing link</h2><p className="text-muted">Open the full link you were given.</p></div>
          ) : (
            <form onSubmit={submit} className="login-form">
              <h2>{title}</h2>
              <p className="text-muted">At least 12 characters. {kind === 'reset' ? 'Your second factor stays as it is.' : ''}</p>
              <div className="form-group">
                <label className="form-label" htmlFor="new-password">New password</label>
                <input id="new-password" type="password" className="form-input" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} minLength={12} autoFocus required />
              </div>
              <div className="form-group">
                <label className="form-label" htmlFor="confirm-password">Repeat password</label>
                <input id="confirm-password" type="password" className="form-input" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} minLength={12} required />
              </div>
              <button type="submit" className="primary-btn full-width" disabled={busy}>{kind === 'activation' ? 'Activate account' : 'Set new password'}</button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};
