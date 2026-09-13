import React, { useState, useEffect } from 'react';
import { ApiError, apiJson, apiRequest, isRecord, errorMessage } from '../api';
import { parseAuthStep, parseBeginLogin, parsePushStatus, parseSuccess } from '../parsers';
import { sameOriginPath } from '../returnTo';
import { getPasskeyAssertion, isPasskeySupported } from '../webauthn';
import type { User } from '../types';
import { ScanFace, RefreshCw, AlertCircle } from 'lucide-react';
import { Brand } from './Sidebar';

interface LoginViewProps {
  onLoginSuccess: (user: User) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({ onLoginSuccess }) => {
  const interaction = new URLSearchParams(window.location.search).get('interaction');
  const [interactionDetails, setInteractionDetails] = useState<{ appName: string; username: string; requiresMFA: boolean; requiresPasskey: boolean } | null>(null);
  const [username, setUsername] = useState('');
  useEffect(() => {
    if (!interaction) return;
    let active = true;
    apiJson('/api/auth/authorization/' + encodeURIComponent(interaction), value => {
      if (!isRecord(value) || typeof value.appName !== 'string' || typeof value.username !== 'string' || typeof value.requiresMFA !== 'boolean' || typeof value.requiresPasskey !== 'boolean') throw new Error('Invalid sign-in request');
      return { appName: value.appName, username: value.username, requiresMFA: value.requiresMFA, requiresPasskey: value.requiresPasskey };
    }).then(details => { if (active) { setInteractionDetails(details); setUsername(details.username); } })
      .catch(err => { if (active) setError(errorMessage(err, 'Could not load sign-in request')); });
    return () => { active = false; };
  }, [interaction]);
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [authorizationRestarted, setAuthorizationRestarted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // MFA State
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaToken, setMfaToken] = useState('');
  const [mfaMode, setMfaMode] = useState<'push' | 'totp' | 'recovery' | 'webauthn'>('push');
  const [mfaMethods, setMfaMethods] = useState<string[]>([]);
  const [totpCode, setTotpCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [challengeId, setChallengeId] = useState('');
  const [matchDigits, setMatchDigits] = useState('');
  const [forgot, setForgot] = useState(false);
  const [forgotSent, setForgotSent] = useState(false);

  // return_to is only ever a same-origin path (the server sends the /oauth/authorize URL
  // it was asked for). Following anything else would bounce the user off the trusted
  // sign-in origin the moment they authenticate, which is a phisher's ideal ending.
  const returnTo = sameOriginPath(new URLSearchParams(window.location.search).get('return_to'));

  // The answer is the same whether or not the account exists or mail is configured.
  const handleForgotSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username) return;
    setLoading(true);
    setError(null);
    try {
      await apiJson('/api/auth/password/forgot', parseSuccess, { method: 'POST', body: JSON.stringify({ identifier: username }) });
      setForgotSent(true);
    } catch (err) {
      setError(errorMessage(err, 'Could not request a reset'));
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) return;

    setLoading(true);
    setError(null);

    try {
      const resp = await apiJson('/api/auth/login', parseAuthStep, {
        method: 'POST',
        body: JSON.stringify({ username, password, interaction: interaction ?? '' }),
      });

      if (resp.mfaRequired) {
        setMfaRequired(true);
        setMfaToken(resp.mfaToken ?? '');
        setMfaMethods(resp.mfaMethods);
        if (resp.challengeId && resp.matchDigits) {
          setChallengeId(resp.challengeId);
          setMatchDigits(resp.matchDigits);
        }
        if (resp.mfaMethods.includes('webauthn') && (isPasskeySupported() || resp.mfaMethods.length === 1)) {
          setMfaMode('webauthn');
        } else if (resp.challengeId && resp.matchDigits) {
          setMfaMode('push');
        } else {
          setMfaMode('totp');
        }
      } else if (resp.success) {
        finishLogin(resp.user, resp.restartAuthorization);
      }
    } catch (err) {
      setError(errorMessage(err, 'Authentication failed'));
    } finally {
      setLoading(false);
    }
  };

  const finishLogin = (user: User | undefined, restartAuthorization = false) => {
    if (!user) {
      setError('The server reported a successful sign-in but returned no account');
      return;
    }
    if (user.enrollment?.restricted) { window.location.href = '/'; return; }
    if (restartAuthorization) {
      setMfaRequired(false);
      setAuthorizationRestarted(true);
      return;
    }
    if (interaction) {
      window.location.href = '/oauth/authorize?interaction=' + encodeURIComponent(interaction);
    } else if (returnTo) {
      window.location.href = returnTo;
    } else {
      onLoginSuccess(user);
    }
  };

  // Push Challenge Poller
  useEffect(() => {
    if (!mfaRequired || mfaMode !== 'push' || !challengeId || !mfaToken) return;

    let isMounted = true;
    const timeout = setTimeout(() => {
      if (!isMounted) return;
      setError('Push challenge expired. Please try again or use TOTP.');
      setMfaMode('totp');
    }, 5 * 60 * 1000);
    const interval = setInterval(async () => {
      try {
        const status = await apiJson('/api/auth/mfa/push/poll', parsePushStatus, {
          method: 'POST',
          body: JSON.stringify({ mfaToken, challengeId }),
        });

        if (!isMounted) return;

        if (status === 'approved') {
          clearInterval(interval);
          clearTimeout(timeout);
          // Complete login
          const finish = await apiJson('/api/auth/mfa/push/finish', parseAuthStep, {
            method: 'POST',
            body: JSON.stringify({ mfaToken, challengeId }),
          });
          if (finish.success) {
            finishLogin(finish.user, finish.restartAuthorization);
          }
        } else if (status === 'denied' || status === 'expired') {
          clearInterval(interval);
          clearTimeout(timeout);
          setError(`Push challenge ${status}. Please try again or use TOTP.`);
          setMfaMode('totp');
        }
      } catch (err) {
        if (!isMounted) return;
        const expired =
          (err instanceof ApiError && err.code === 'invalid_mfa_token') ||
          errorMessage(err, '').toLowerCase().includes('expired');
        if (expired) {
          clearInterval(interval);
          clearTimeout(timeout);
          setError('Push challenge expired. Please sign in again or use another MFA method.');
          setMfaMode('totp');
        }
      }
    }, 2000);

    return () => {
      isMounted = false;
      clearInterval(interval);
      clearTimeout(timeout);
    };
  }, [mfaRequired, mfaMode, challengeId, mfaToken]);

  const handleTOTPSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpCode || totpCode.length < 6) return;

    setLoading(true);
    setError(null);

    try {
      const resp = await apiJson('/api/auth/mfa/totp/verify', parseAuthStep, {
        method: 'POST',
        body: JSON.stringify({ mfaToken, code: totpCode }),
      });
      if (resp.success) {
        finishLogin(resp.user, resp.restartAuthorization);
      }
    } catch (err) {
      setError(errorMessage(err, 'Invalid TOTP code'));
    } finally {
      setLoading(false);
    }
  };

  const submitPasskey = async () => {
    setError(null);
    setLoading(true);

    try {
      const begun = await apiJson('/api/auth/mfa/webauthn/begin', parseBeginLogin, {
        method: 'POST',
        body: JSON.stringify({ mfaToken }),
      });
      const assertion = await getPasskeyAssertion(begun);
      const resp = await apiJson('/api/auth/mfa/webauthn/verify', parseAuthStep, {
        method: 'POST',
        body: JSON.stringify({ mfaToken, ...assertion }),
      });
      if (resp.success) {
        finishLogin(resp.user, resp.restartAuthorization);
      }
    } catch (err) {
      setError(errorMessage(err, 'Passkey sign-in failed'));
    } finally {
      setLoading(false);
    }
  };

  const handleRecoverySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!recoveryCode) return;

    setLoading(true);
    setError(null);

    try {
      const resp = await apiJson('/api/auth/mfa/recovery/verify', parseAuthStep, {
        method: 'POST',
        body: JSON.stringify({ mfaToken, code: recoveryCode }),
      });
      if (resp.success) {
        finishLogin(resp.user, resp.restartAuthorization);
      }
    } catch (err) {
      setError(errorMessage(err, 'Invalid recovery code'));
    } finally {
      setLoading(false);
    }
  };

  const cancelInteraction = async () => {
    setLoading(true);
    try {
      await apiRequest('/api/auth/authorization/cancel', { method: 'POST', body: JSON.stringify({ interaction }) });
      window.location.href = '/';
    } catch (err) {
      setError(errorMessage(err, 'Could not cancel sign-in'));
      setLoading(false);
    }
  };

  const canUseWebauthn = mfaMethods.includes('webauthn') && isPasskeySupported();
  const spinner = <RefreshCw className="spin" size={16} />;

  if (authorizationRestarted) return (
    <div className="login-page"><div className="login-col"><div className="login-card">
      <h1>You’re signed in</h1>
      <p role="status">The application’s sign-in request expired or was cancelled. Return to the application and start sign-in again.</p>
      <a className="primary-btn" href="/">Go to your dashboard</a>
    </div></div></div>
  );

  return (
    <div className="login-page">
      <aside className="login-intro">
        <Brand />
        <h1>Sign in once, then open everything.</h1>
      </aside>

      <div className="login-col">
        <div className="login-card">
          {error && (
            <div className="alert-box error" role="alert">
              <AlertCircle size={16} />
              <span>{error}</span>
            </div>
          )}

          {interaction && <button type="button" className="text-btn" onClick={cancelInteraction}>Cancel sign-in</button>}

          {!mfaRequired && forgot && (
            <form onSubmit={handleForgotSubmit} className="login-form">
              <h2>Reset your password</h2>
              {forgotSent ? (
                <p className="text-muted">If that account exists and mail delivery is set up, a reset link is on its way and stays valid for 30 minutes. Otherwise ask an administrator for a link.</p>
              ) : (
                <>
                  <p className="text-muted">Enter your username or email address.</p>
                  <div className="form-group">
                    <label className="form-label" htmlFor="forgot-identifier">Username or email</label>
                    <input id="forgot-identifier" type="text" className="form-input" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus required />
                  </div>
                  <button type="submit" className="primary-btn full-width" disabled={loading}>{loading ? spinner : 'Send reset link'}</button>
                </>
              )}
              <button type="button" className="text-btn" onClick={() => { setForgot(false); setForgotSent(false); setError(null); }}>Back to sign in</button>
            </form>
          )}

          {!mfaRequired && !forgot && (
            <form onSubmit={handlePasswordSubmit} className="login-form">
              <h2>{interaction ? 'Verify your sign-in' : 'Sign in'}</h2>
              {interactionDetails && <p className="text-muted">Continue to {interactionDetails.appName}. {interactionDetails.requiresPasskey ? 'Use your password and an enrolled passkey. Other factors do not meet this request.' : interactionDetails.requiresMFA ? 'Use your password and an enrolled authenticator or passkey. Recovery codes do not meet this request.' : 'Enter your password and complete any enrolled second factor.'}</p>}
              <div className="form-group">
                <label className="form-label" htmlFor="username">Username</label>
                <input
                  id="username"
                  type="text"
                  className="form-input font-mono"
                  autoComplete="username"
                  readOnly={Boolean(interactionDetails?.username)}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoFocus
                  required
                />
              </div>
              <div className="form-group">
                <label className="form-label" htmlFor="password">Password</label>
                <input
                  id="password"
                  type="password"
                  className="form-input"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
              <button type="submit" className="primary-btn full-width" disabled={loading || Boolean(interaction && !interactionDetails)}>
                {loading ? spinner : 'Sign in'}
              </button>
              {!interaction && <button type="button" className="text-btn" onClick={() => { setForgot(true); setError(null); }}>Forgot your password?</button>}
            </form>
          )}

          {mfaRequired && mfaMode === 'webauthn' && (
            <div className="login-form">
              <h2>Use a passkey</h2>
              {!isPasskeySupported() && <p role="alert">This browser cannot use passkeys. Open the application in a browser with passkey support.</p>}
              <p className="text-muted">Your browser will ask for a fingerprint, face, or security key.</p>
              <div className="match"><ScanFace size={56} /></div>
              <button type="button" className="primary-btn full-width" onClick={submitPasskey} disabled={loading || !isPasskeySupported()}>
                {loading ? spinner : 'Continue with passkey'}
              </button>
              <div className="mfa-alt-links">
                {matchDigits && (
                  <button type="button" className="text-btn" onClick={() => setMfaMode('push')}>Approve on your phone instead</button>
                )}
                {!interactionDetails?.requiresPasskey && mfaMethods.includes('totp') && <button type="button" className="text-btn" onClick={() => setMfaMode('totp')}>Enter a six-digit code</button>}
                {!interactionDetails?.requiresMFA && <button type="button" className="text-btn" onClick={() => setMfaMode('recovery')}>Use a recovery code</button>}
              </div>
            </div>
          )}

          {mfaRequired && mfaMode === 'push' && (
            <div className="login-form">
              <h2>Check your phone</h2>
              <p className="text-muted">Open KySecurity Authenticator and tap the number you see here.</p>
              <div className="match" aria-live="polite">
                <b>{matchDigits}</b>
                <span>Only one of the numbers on your phone matches.</span>
              </div>
              <div className="wait"><i />Waiting for approval.</div>
              <div className="mfa-alt-links">
                {canUseWebauthn && (
                  <button type="button" className="text-btn" onClick={() => setMfaMode('webauthn')}>Use a passkey instead</button>
                )}
                {!interactionDetails?.requiresPasskey && mfaMethods.includes('totp') && <button type="button" className="text-btn" onClick={() => setMfaMode('totp')}>Enter a six-digit code</button>}
              </div>
            </div>
          )}

          {mfaRequired && mfaMode === 'totp' && (
            <form onSubmit={handleTOTPSubmit} className="login-form">
              <h2>Enter your six-digit code</h2>
              <div className="form-group">
                <input
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  className="form-input text-center text-mono text-large"
                  placeholder="000000"
                  aria-label="Six-digit code"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  autoFocus
                  required
                />
              </div>
              <button type="submit" className="primary-btn full-width" disabled={loading || totpCode.length < 6}>
                {loading ? spinner : 'Continue'}
              </button>
              <div className="mfa-alt-links">
                {canUseWebauthn && (
                  <button type="button" className="text-btn" onClick={() => setMfaMode('webauthn')}>Use a passkey instead</button>
                )}
                {matchDigits && (
                  <button type="button" className="text-btn" onClick={() => setMfaMode('push')}>Approve on your phone instead</button>
                )}
                {!interactionDetails?.requiresMFA && <button type="button" className="text-btn" onClick={() => setMfaMode('recovery')}>Use a recovery code</button>}
              </div>
            </form>
          )}

          {mfaRequired && mfaMode === 'recovery' && (
            <form onSubmit={handleRecoverySubmit} className="login-form">
              <h2>Use a recovery code</h2>
              <p className="text-muted">Each code works once.</p>
              <div className="form-group">
                <input
                  type="text"
                  className="form-input text-center text-mono"
                  placeholder="XXXX-XXXX"
                  aria-label="Recovery code"
                  value={recoveryCode}
                  onChange={(e) => setRecoveryCode(e.target.value)}
                  autoFocus
                  required
                />
              </div>
              <button type="submit" className="primary-btn full-width" disabled={loading || !recoveryCode}>
                {loading ? spinner : 'Continue'}
              </button>
              <div className="mfa-alt-links">
                {canUseWebauthn && (
                  <button type="button" className="text-btn" onClick={() => setMfaMode('webauthn')}>Use a passkey instead</button>
                )}
                {!interactionDetails?.requiresPasskey && mfaMethods.includes('totp') && <button type="button" className="text-btn" onClick={() => setMfaMode('totp')}>Enter a six-digit code</button>}
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};
