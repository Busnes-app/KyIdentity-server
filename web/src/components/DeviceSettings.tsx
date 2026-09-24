import React, { useEffect, useState, useRef } from 'react';
import { NativeDevice, Passkey, SessionInventory, User } from '../types';
import { apiJson, apiRequest, errorMessage, isStepUpRequired } from '../api';
import {
  parseBeginRegistration,
  parseDevices,
  parsePairingToken,
  parsePasskeys,
  parseRecoveryCodes,
  parseSessionInventory,
  parseSuccess,
  parseTOTPSetup,
} from '../parsers';
import { createPasskey, isPasskeySupported } from '../webauthn';
import QRCode from 'qrcode';
import { useStepUp, isCancelled } from './StepUpPrompt';
import { SessionList } from './SessionList';
import {
  Smartphone,
  ScanFace,
  ShieldAlert,
  Trash2,
  CheckCircle,
  Clock,
  Copy,
  Check,
  Plus,
} from 'lucide-react';

/** Which account-security change the step-up prompt is currently gating. */
type PendingAction = 'totp' | 'recovery-codes' | 'passkey-enroll' | 'passkey-delete';

interface DeviceSettingsProps {
  user: User;
  onUserUpdate: () => void;
}

export const DeviceSettings: React.FC<DeviceSettingsProps> = ({ user, onUserUpdate }) => {
  const restricted = Boolean(user.enrollment?.restricted);
  const permitted = (method: string) => !restricted || Boolean(user.enrollment?.allowedMethods.includes(method));
  const [devices, setDevices] = useState<NativeDevice[]>([]);
  const [pairDeviceIdsBefore, setPairDeviceIdsBefore] = useState<Set<string>>(new Set());

  // Passkey State
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [passkeyName, setPasskeyName] = useState('');
  const [passkeyError, setPasskeyError] = useState<string | null>(null);
  const [passkeyBusy, setPasskeyBusy] = useState(false);

  // Device Pairing State
  const [showPairModal, setShowPairModal] = useState(false);
  const [pairPin, setPairPin] = useState('');
  const [pairExpiresAt, setPairExpiresAt] = useState<number | null>(null);
  const [pairStartedAt, setPairStartedAt] = useState<number | null>(null);
  const [countdown, setCountdown] = useState(90);
  const qrCanvasRef = useRef<HTMLCanvasElement | null>(null);

  // TOTP Setup State
  const [showTotpModal, setShowTotpModal] = useState(false);
  const [totpSecret, setTotpSecret] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [totpError, setTotpError] = useState<string | null>(null);
  const totpCanvasRef = useRef<HTMLCanvasElement | null>(null);

  // Recovery Codes Modal
  const [showRecoveryModal, setShowRecoveryModal] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);

  const { requestGrant, stepUpPrompt } = useStepUp();

  const [pwCurrent, setPwCurrent] = useState('');
  const [pwNew, setPwNew] = useState('');
  const [pwConfirm, setPwConfirm] = useState('');
  const [pwBusy, setPwBusy] = useState(false);
  const [pwError, setPwError] = useState<string | null>(null);
  const [pwDone, setPwDone] = useState(false);
  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwError(null); setPwDone(false);
    if (pwNew !== pwConfirm) { setPwError('The two new passwords do not match.'); return; }
    setPwBusy(true);
    try {
      const stepUpToken = await requestGrant('Changing your password signs out every other session and app.', 'POST /api/user/password');
      await apiRequest('/api/user/password', { method: 'POST', stepUpToken, body: JSON.stringify({ currentPassword: pwCurrent, newPassword: pwNew }) });
      setPwCurrent(''); setPwNew(''); setPwConfirm(''); setPwDone(true);
      loadSessions();
    } catch (err) {
      if (!isCancelled(err)) setPwError(errorMessage(err, 'Password not changed'));
    } finally {
      setPwBusy(false);
    }
  };

  const [inventory, setInventory] = useState<SessionInventory>({ sessions: [], apps: [], logouts: [] });
  const loadSessions = async () => {
    try {
      setInventory(await apiJson('/api/user/sessions', parseSessionInventory));
    } catch {
      // A failed refresh leaves the previous list on screen; nothing is lost.
    }
  };

  const handleRevokeSession = async (id: string, current: boolean) => {
    if (!confirm(current ? 'Sign out of this browser?' : 'Sign out that session?')) return;
    try {
      await apiRequest(`/api/user/sessions/${id}`, { method: 'DELETE' });
      // The server cleared this browser's cookies; the app must stop treating it as signed in.
      if (current) window.dispatchEvent(new CustomEvent('kyidentity:unauthorized'));
      else loadSessions();
    } catch (err) {
      alert(errorMessage(err, 'Failed to sign out session'));
    }
  };

  const handleRevokeOthers = async () => {
    if (!confirm('Sign out every other browser session? This one stays signed in.')) return;
    try {
      await apiRequest('/api/user/sessions/revoke-others', { method: 'POST' });
      loadSessions();
    } catch (err) {
      alert(errorMessage(err, 'Failed to sign out other sessions'));
    }
  };

  const fetchDevices = async () => {
    try {
      setDevices(await apiJson('/api/user/devices', parseDevices));
    } catch {
      // A failed refresh leaves the previous list on screen; nothing is lost.
    }
  };

  const closePairModal = () => {
    setShowPairModal(false);
    setPairStartedAt(null);
    fetchDevices();
  };

  const loadPasskeys = async () => {
    try {
      setPasskeys(await apiJson('/api/user/passkeys', parsePasskeys));
    } catch {
      // A failed refresh leaves the previous list on screen; nothing is lost.
    }
  };

  useEffect(() => {
    fetchDevices();
    loadPasskeys();
    loadSessions();
  }, []);

  // 90s Countdown Timer for Device Pairing
  useEffect(() => {
    if (!showPairModal || !pairExpiresAt) return;

    const interval = setInterval(() => {
      const remaining = Math.max(0, Math.floor((pairExpiresAt - Date.now()) / 1000));
      setCountdown(remaining);
      if (remaining <= 0) {
        clearInterval(interval);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [showPairModal, pairExpiresAt]);

  useEffect(() => {
    if (!showPairModal || !pairStartedAt || !pairExpiresAt) return;

    const interval = setInterval(async () => {
      if (Date.now() >= pairExpiresAt) {
        clearInterval(interval);
        return;
      }
      try {
        const nextDevices = await apiJson('/api/user/devices', parseDevices);
        setDevices(nextDevices);
        const paired = nextDevices.some((dev) => {
          if (!pairDeviceIdsBefore.has(dev.id) && dev.pushToken) return true;
          const seenAt = new Date(dev.lastSeenAt || dev.createdAt).getTime();
          return Boolean(dev.pushToken) && Number.isFinite(seenAt) && seenAt >= pairStartedAt - 2000;
        });
        if (paired) {
          closePairModal();
          onUserUpdate();
        }
      } catch {
        // Keep the QR/PIN visible; the normal countdown still expires it.
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [showPairModal, pairStartedAt, pairExpiresAt, pairDeviceIdsBefore, onUserUpdate]);

  const handleStartDevicePairing = async () => {
    try {
      const stepUpToken = await requestGrant('Pair a phone that can approve sign-ins.', 'POST /api/user/devices/pairing-token');
      setShowPairModal(true);
      setPairStartedAt(Date.now());
      setPairDeviceIdsBefore(new Set(devices.map((dev) => dev.id)));
      const data = await apiJson('/api/user/devices/pairing-token', parsePairingToken, { method: 'POST', stepUpToken });
      setPairPin(data.pinCode);
      const exp = new Date(data.expiresAt).getTime();
      setPairExpiresAt(exp);
      setCountdown(Math.floor((exp - Date.now()) / 1000));

      if (qrCanvasRef.current && data.qrPayload) {
        QRCode.toCanvas(qrCanvasRef.current, data.qrPayload, {
          width: 200,
          margin: 1,
          color: { dark: '#0d0f14', light: '#4deeea' },
        });
      }
    } catch (err) {
      if (!isCancelled(err)) alert(errorMessage(err, 'Failed to generate pairing token'));
      closePairModal();
    }
  };

  const requestStepUp = async (action: PendingAction, passkeyId?: string) => {
    const operations = {
      totp: 'POST /api/user/mfa/totp/enable',
      'recovery-codes': 'POST /api/user/recovery-codes',
      'passkey-enroll': 'POST /api/user/passkeys/register/finish',
      'passkey-delete': `DELETE /api/user/passkeys/${passkeyId}`,
    };
    const reasons = {
      totp: 'Re-enter your credentials to set up or replace your authenticator.',
      'recovery-codes': 'New recovery codes invalidate the ones you already stored.',
      'passkey-enroll': 'Adding a passkey creates a new sign-in credential for this account.',
      'passkey-delete': 'Removing a passkey revokes that credential immediately.',
    };
    try {
      const grant = await requestGrant(reasons[action], operations[action]);
      if (action === 'totp') await startTOTPSetup(grant);
      else if (action === 'recovery-codes') await generateRecoveryCodes(grant);
      else if (action === 'passkey-enroll') await enrollPasskey(grant);
      else if (passkeyId) await deletePasskey(grant, passkeyId);
    } catch (err) {
      if (!isCancelled(err)) alert(errorMessage(err, 'Re-authentication failed'));
    }
  };

  // The grant is held only for as long as this flow runs, and is spent by the enable step.
  const [totpGrant, setTotpGrant] = useState('');

  const startTOTPSetup = async (grant: string) => {
    setShowTotpModal(true);
    setTotpError(null);
    setTotpGrant(grant);
    try {
      const data = await apiJson('/api/user/mfa/totp/setup', parseTOTPSetup, {
        method: 'POST',
        stepUpToken: grant,
      });
      setTotpSecret(data.secret);

      if (totpCanvasRef.current) {
        QRCode.toCanvas(totpCanvasRef.current, data.uri, {
          width: 200,
          margin: 1,
          color: { dark: '#0d0f14', light: '#4deeea' },
        });
      }
    } catch (err) {
      setTotpError(errorMessage(err, 'Failed to initialize TOTP'));
    }
  };

  const handleEnableTOTP = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpCode || totpCode.length < 6) return;

    try {
      const codes = await apiJson('/api/user/mfa/totp/enable', parseRecoveryCodes, {
        method: 'POST',
        body: JSON.stringify({ secret: totpSecret, code: totpCode }),
        stepUpToken: totpGrant,
      });
      setShowTotpModal(false);
      setTotpGrant('');
      setRecoveryCodes(codes);
      setShowRecoveryModal(true);
      onUserUpdate();
    } catch (err) {
      if (isStepUpRequired(err)) {
        setShowTotpModal(false);
        setTotpGrant('');
        requestStepUp('totp');
        return;
      }
      setTotpError(errorMessage(err, 'Invalid code'));
    }
  };

  const generateRecoveryCodes = async (grant: string) => {
    try {
      const codes = await apiJson('/api/user/recovery-codes', parseRecoveryCodes, {
        method: 'POST',
        stepUpToken: grant,
      });
      setRecoveryCodes(codes);
      setShowRecoveryModal(true);
    } catch (err) {
      if (isStepUpRequired(err)) {
        requestStepUp('recovery-codes');
        return;
      }
      alert(errorMessage(err, 'Failed to generate recovery codes'));
    }
  };

  const enrollPasskey = async (grant: string) => {
    setPasskeyError(null);
    setPasskeyBusy(true);
    try {
      const begun = await apiJson('/api/user/passkeys/register/begin', parseBeginRegistration, {
        method: 'POST',
        body: JSON.stringify({ name: passkeyName || 'Passkey' }),
        stepUpToken: grant,
      });
      const finished = await createPasskey(begun);
      await apiJson('/api/user/passkeys/register/finish', parseSuccess, {
        method: 'POST',
        body: JSON.stringify({ ...finished, name: passkeyName || 'Passkey' }),
        stepUpToken: grant,
      });
      setPasskeyName('');
      await loadPasskeys();
      onUserUpdate();
    } catch (err) {
      if (isStepUpRequired(err)) {
        requestStepUp('passkey-enroll');
        return;
      }
      setPasskeyError(errorMessage(err, 'Could not enrol that passkey'));
    } finally {
      setPasskeyBusy(false);
    }
  };

  const handleAddPasskey = () => {
    requestStepUp('passkey-enroll');
  };

  const deletePasskey = async (grant: string, id: string) => {
    try {
      await apiRequest(`/api/user/passkeys/${id}`, { method: 'DELETE', stepUpToken: grant });
      await loadPasskeys();
      onUserUpdate();
    } catch (err) {
      if (isStepUpRequired(err)) {
        requestStepUp('passkey-delete', id);
        return;
      }
      setPasskeyError(errorMessage(err, 'Failed to remove passkey'));
    }
  };

  const handleRemovePasskey = (id: string) => {
    if (!confirm('Remove this passkey? You will no longer be able to sign in with it.')) return;
    requestStepUp('passkey-delete', id);
  };

  const handleDeleteDevice = async (deviceId: string) => {
    if (!confirm('Are you sure you want to disconnect this device?')) return;
    try {
      await apiRequest(`/api/user/devices/${deviceId}`, { method: 'DELETE' });
      fetchDevices();
    } catch (err) {
      alert(errorMessage(err, 'Failed to delete device'));
    }
  };

  const copyRecoveryCodes = () => {
    navigator.clipboard.writeText(recoveryCodes.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="settings-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Security and devices</h1>
        </div>
      </div>

      <div className="settings-section">
        <div className="section-header">
          <div className="section-title-wrap">
            <h2>Phones that approve sign-ins</h2>
          </div>
          <button className="secondary-btn sm" disabled={!permitted('push')} onClick={handleStartDevicePairing}>
            <Plus size={14} />
            <span>Pair a phone</span>
          </button>
        </div>

        <div className="device-list">
          {devices.length === 0 ? (
            <div className="empty-box">
              <Smartphone size={32} className="empty-icon" />
              <p>No phones paired yet.</p>
            </div>
          ) : (
            devices.map((dev) => (
              <div key={dev.id} className="device-card">
                <div className="device-icon-box">
                  <Smartphone size={20} className="icon-cyan" />
                </div>
                <div className="device-info">
                  <span className="device-name">{dev.deviceName}</span>
                  <span className="device-id-mono">{dev.deviceIdentifier}</span>
                </div>
                <div className="device-status">
                  <span className="badge-approver">
                    <CheckCircle size={12} /> Push approver
                  </span>
                </div>
                <button
                  className="icon-danger-btn"
                  onClick={() => handleDeleteDevice(dev.id)}
                  disabled={restricted}
                  title="Remove Device"
                >
                  <Trash2 size={16} />
                </button>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="settings-section">
        <div className="section-header">
          <div className="section-title-wrap">
            <h2>Passkeys</h2>
          </div>
          {isPasskeySupported() ? (
            <button className="secondary-btn sm" onClick={handleAddPasskey} disabled={passkeyBusy || !permitted('webauthn')}>
              <Plus size={14} />
              <span>Add passkey</span>
            </button>
          ) : (
            <span className="text-muted text-sm">Not supported by this browser</span>
          )}
        </div>

        {isPasskeySupported() && (
          <div className="form-group">
            <label className="form-label" htmlFor="passkey-name">
              Name (optional)
            </label>
            <input
              id="passkey-name"
              type="text"
              className="form-input"
              placeholder="e.g. YubiKey, MacBook Touch ID"
              value={passkeyName}
              onChange={(e) => setPasskeyName(e.target.value)}
              maxLength={64}
            />
          </div>
        )}

        {passkeyError && (
          <div className="alert-box error sm" role="alert">
            {passkeyError}
          </div>
        )}

        <div className="device-list">
          {passkeys.length === 0 ? (
            <div className="empty-box">
              <ScanFace size={32} className="empty-icon" />
              <p>No passkeys yet.</p>
            </div>
          ) : (
            passkeys.map((pk) => (
              <div key={pk.id} className="device-card">
                <div className="device-icon-box">
                  <ScanFace size={20} className="icon-cyan" />
                </div>
                <div className="device-info">
                  <span className="device-name">{pk.name}</span>
                  <span className="device-id-mono">
                    Added {new Date(pk.createdAt).toLocaleString()}
                    {' · '}
                    {pk.lastUsedAt ? `Last used ${new Date(pk.lastUsedAt).toLocaleString()}` : 'Never used'}
                  </span>
                </div>
                <div className="device-status">
                  {pk.backupState ? (
                    <span
                      className="badge-approver"
                      title="This passkey is stored in your account provider's cloud (e.g. iCloud Keychain, Google Password Manager) and may be available on your other devices."
                    >
                      <CheckCircle size={12} /> Synced
                    </span>
                  ) : (
                    <span
                      className="badge-type"
                      title="This passkey is bound to this device only and will not appear on your other devices."
                    >
                      Device-bound
                    </span>
                  )}
                </div>
                <button
                  className="icon-danger-btn"
                  onClick={() => handleRemovePasskey(pk.id)}
                  disabled={restricted}
                  title="Remove Passkey"
                  aria-label={`Remove passkey ${pk.name}`}
                >
                  <Trash2 size={16} />
                </button>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="settings-section">
        <div className="section-header">
          <div className="section-title-wrap">
            <h2>Six-digit codes</h2>
            <p className="section-desc">{user.mfaMethods?.includes('totp') ? 'Configured.' : 'Not configured.'}</p>
          </div>
          <button className="secondary-btn sm" disabled={!permitted('totp')} onClick={() => requestStepUp('totp')}>
            <span>{user.mfaMethods?.includes('totp') ? 'Replace' : 'Set up'}</span>
          </button>
        </div>
      </div>

      <div className="settings-section">
        <div className="section-header">
          <div className="section-title-wrap">
            <h2>Recovery codes</h2>
          </div>
          <button className="secondary-btn sm" disabled={restricted} onClick={() => requestStepUp('recovery-codes')}>
            <span>Generate new codes</span>
          </button>
        </div>
      </div>

      <div className="settings-section">
        <div className="section-header">
          <div className="section-title-wrap">
            <h2>Password</h2>
          </div>
        </div>
        <form onSubmit={handleChangePassword} className="password-change-form">
          {pwError && <div className="alert-box error" role="alert">{pwError}</div>}
          {pwDone && <div className="alert-box" role="status">Password changed. Every other session and app was signed out.</div>}
          <div className="form-row">
            <div className="form-group flex-1"><label className="form-label" htmlFor="pw-current">Current password</label><input id="pw-current" type="password" className="form-input" autoComplete="current-password" value={pwCurrent} onChange={(e) => setPwCurrent(e.target.value)} disabled={pwBusy} required /></div>
            <div className="form-group flex-1"><label className="form-label" htmlFor="pw-new">New password</label><input id="pw-new" type="password" className="form-input" autoComplete="new-password" minLength={12} value={pwNew} onChange={(e) => setPwNew(e.target.value)} disabled={pwBusy} required /></div>
            <div className="form-group flex-1"><label className="form-label" htmlFor="pw-confirm">Repeat new password</label><input id="pw-confirm" type="password" className="form-input" autoComplete="new-password" minLength={12} value={pwConfirm} onChange={(e) => setPwConfirm(e.target.value)} disabled={pwBusy} required /></div>
          </div>
          <button type="submit" className="secondary-btn sm" disabled={pwBusy || restricted}><span>Change password</span></button>
        </form>
      </div>

      <div className="settings-section">
        <div className="section-header">
          <div className="section-title-wrap">
            <h2>Where you are signed in</h2>
          </div>
          <button className="secondary-btn sm" disabled={inventory.sessions.length < 2} onClick={handleRevokeOthers}>
            <span>Sign out other sessions</span>
          </button>
        </div>
        <SessionList sessions={inventory.sessions} apps={inventory.apps} logouts={inventory.logouts} onRevokeSession={(sess) => handleRevokeSession(sess.id, sess.current)} />
      </div>

      {/* Device Pairing Modal (90s Ephemeral Key / QR) */}
      {stepUpPrompt}

      {showPairModal && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Pair KySecurity Authenticator</h3>
              <button className="close-btn" onClick={closePairModal}>
                ×
              </button>
            </div>
            <div className="modal-body text-center">
              <p className="modal-desc">
                Open the <strong>KySecurity Authenticator</strong> app on your mobile device and scan the QR code or enter the pairing PIN.
              </p>
              <p className="modal-desc">
                This adds a different device without removing the paired devices listed above. Pairing the same device identifier updates that device.
              </p>

              <div className="qr-container">
                <canvas ref={qrCanvasRef} />
              </div>

              <div className="pin-box">
                <span className="pin-label">PAIRING PIN</span>
                <span className="pin-digits">{pairPin || '••••••'}</span>
              </div>

              <div className="timer-bar-wrap">
                <div className="timer-info">
                  <Clock size={14} className="icon-cyan" />
                  <span>Valid for {countdown}s</span>
                </div>
                <div className="timer-progress-bg">
                  <div
                    className="timer-progress-fill"
                    style={{ width: `${(countdown / 90) * 100}%` }}
                  />
                </div>
              </div>
            </div>
            <div className="modal-footer">
              <button className="secondary-btn" onClick={closePairModal}>
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TOTP Setup Modal */}
      {showTotpModal && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Configure TOTP Authenticator</h3>
              <button className="close-btn" onClick={() => setShowTotpModal(false)}>
                ×
              </button>
            </div>
            <form onSubmit={handleEnableTOTP} className="modal-body">
              <p className="modal-desc">
                Scan this QR code in your authenticator app, then enter the generated 6-digit verification code below. This replaces the account's current TOTP credential, if any.
              </p>

              <div className="qr-container">
                <canvas ref={totpCanvasRef} />
              </div>

              <div className="secret-key-display">
                <span className="secret-label">Secret:</span>
                <code className="secret-code">{totpSecret}</code>
              </div>

              {totpError && <div className="alert-box error sm">{totpError}</div>}

              <div className="form-group mt-3">
                <label className="form-label">6-Digit Verification Code</label>
                <input
                  type="text"
                  className="form-input text-center text-mono text-large"
                  placeholder="000000"
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  autoFocus
                  required
                />
              </div>

              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={() => setShowTotpModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="primary-btn" disabled={totpCode.length < 6}>
                  Verify & Enable
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Recovery Codes Modal */}
      {showRecoveryModal && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Backup Recovery Codes</h3>
              <button className="close-btn" onClick={() => setShowRecoveryModal(false)}>
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="alert-box warn">
                <ShieldAlert size={16} />
                <span>Save these backup codes securely. Each code can be used exactly once.</span>
              </div>

              <div className="recovery-codes-grid">
                {recoveryCodes.map((c, i) => (
                  <div key={i} className="recovery-code-item">
                    <code>{c}</code>
                  </div>
                ))}
              </div>
            </div>
            <div className="modal-footer">
              <button className="secondary-btn" onClick={copyRecoveryCodes}>
                {copied ? <Check size={14} /> : <Copy size={14} />}
                <span>{copied ? 'Copied' : 'Copy All'}</span>
              </button>
              <button className="primary-btn" onClick={() => setShowRecoveryModal(false)}>
                I Have Saved Them
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
