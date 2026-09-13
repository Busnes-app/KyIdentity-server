import React from 'react';
import { AppGrant, BrowserSession, LogoutDelivery } from '../types';
import { Monitor, AppWindow, LogOut, RefreshCw } from 'lucide-react';

const when = (iso: string) => new Date(iso).toLocaleString();

const factorLabel: Record<string, string> = {
  totp: 'code', push: 'phone', webauthn: 'passkey', recovery: 'recovery code',
};

const logoutLabel: Record<LogoutDelivery['status'], string> = {
  queued: 'Pending', delivered: 'Acknowledged', failed: 'Failed',
};

interface SessionListProps {
  sessions: BrowserSession[];
  apps: AppGrant[];
  logouts: LogoutDelivery[];
  onRevokeSession: (session: BrowserSession) => void;
  /** Absent when the viewer may not revoke app access (own-account view). */
  onRevokeApp?: (app: AppGrant) => void;
  /** Absent when the viewer may not retry a stuck sign-out notification. */
  onRetryLogout?: (delivery: LogoutDelivery) => void;
}

/**
 * Browser sessions and app token grants for one account. App rows come from the token
 * registry only: they show which apps can still call KySignOn, not whether the app's own
 * login is alive, so the copy never promises a downstream sign-out.
 */
export const SessionList: React.FC<SessionListProps> = ({ sessions, apps, logouts, onRevokeSession, onRevokeApp, onRetryLogout }) => (
  <>
    <div className="device-list">
      {sessions.length === 0 ? (
        <div className="empty-box"><p>No active browser sessions.</p></div>
      ) : (
        sessions.map((s) => (
          <div key={s.id} className="device-card">
            <div className="device-icon-box"><Monitor size={20} className="icon-cyan" /></div>
            <div className="device-info">
              <span className="device-name">
                {s.userAgent || 'Unknown browser'}
                {s.current && <span className="status-badge active"> This session</span>}
              </span>
              <span className="device-id-mono">
                {s.ipAddress || 'unknown address'} · active {when(s.lastActiveAt)} · signed in {when(s.createdAt)}
                {s.factorMethod ? ` with ${factorLabel[s.factorMethod] ?? s.factorMethod}` : ''} · expires {when(s.expiresAt)}
              </span>
            </div>
            <button className="icon-danger-btn" onClick={() => onRevokeSession(s)} title="Sign out this session" aria-label={`Sign out session ${s.id}`}>
              <LogOut size={16} />
            </button>
          </div>
        ))
      )}
    </div>
    <div className="section-header">
      <div className="section-title-wrap"><h3>Apps holding access tokens</h3></div>
    </div>
    <div className="device-list">
      {apps.length === 0 ? (
        <div className="empty-box"><p>No app holds a live token.</p></div>
      ) : (
        apps.map((a) => (
          <div key={a.clientId} className="device-card">
            <div className="device-icon-box"><AppWindow size={20} className="icon-cyan" /></div>
            <div className="device-info">
              <span className="device-name">{a.clientName}</span>
              <span className="device-id-mono">
                {a.tokens} live token{a.tokens === 1 ? '' : 's'} · last expires {when(a.expiresAt)}. The app's own login may last longer.
              </span>
            </div>
            {onRevokeApp && (
              <button className="icon-danger-btn" onClick={() => onRevokeApp(a)} title="Revoke this app's tokens" aria-label={`Revoke tokens for ${a.clientName}`}>
                <LogOut size={16} />
              </button>
            )}
          </div>
        ))
      )}
    </div>
    <div className="section-header">
      <div className="section-title-wrap"><h3>Sign-out notifications</h3></div>
    </div>
    <LogoutDeliveries logouts={logouts} onRetryLogout={onRetryLogout} />
  </>
);

/** Back-channel logout deliveries owed to apps: what each app was told, or not. */
export const LogoutDeliveries: React.FC<{ logouts: LogoutDelivery[]; onRetryLogout?: (delivery: LogoutDelivery) => void }> = ({ logouts, onRetryLogout }) => (
  <>
    <div className="device-list">
      {logouts.length === 0 ? (
        <div className="empty-box"><p>No app has been told about a sign-out yet. Apps without a back-channel logout address are never told.</p></div>
      ) : (
        logouts.map((d) => (
          <div key={d.id} className="device-card">
            <div className="device-info">
              <span className="device-name">
                {d.clientName}
                <span className={`status-badge ${d.status === 'delivered' ? 'active' : d.status === 'failed' ? 'disabled' : 'warn'}`}> {logoutLabel[d.status]}</span>
              </span>
              <span className="device-id-mono">
                {d.attempts} attempt{d.attempts === 1 ? '' : 's'} · {when(d.updatedAt)}
                {d.status === 'queued' && d.nextAttemptAt ? ` · next ${when(d.nextAttemptAt)}` : ''}
                {d.lastError ? ` · ${d.lastError}` : ''}
                {d.status === 'delivered' ? ' · the app acknowledged the sign-out' : ''}
              </span>
            </div>
            {onRetryLogout && d.status !== 'delivered' && (
              <button className="icon-btn" onClick={() => onRetryLogout(d)} title="Retry now" aria-label={`Retry sign-out notification for ${d.clientName}`}>
                <RefreshCw size={16} />
              </button>
            )}
          </div>
        ))
      )}
    </div>
  </>
);
