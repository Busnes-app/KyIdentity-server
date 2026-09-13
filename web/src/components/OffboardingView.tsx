import React, { useEffect, useState } from 'react';
import { apiJson, apiRequest, errorMessage } from '../api';
import { parseOffboarding } from '../parsers';
import { LogoutDeliveries } from './SessionList';
import { RefreshCw } from 'lucide-react';
import type { Offboarding, OffboardingTarget } from '../types';

const observedLabel: Record<OffboardingTarget['observed'], string> = {
  '': 'Not listed yet', present_active: 'Still active at target', present_inactive: 'Inactive at target', absent: 'Absent at target', unsupported: 'Verification unsupported',
};
const when = (iso?: string) => (iso ? new Date(iso).toLocaleString() : '');

function targetBadge(t: OffboardingTarget): { cls: string; text: string } {
  if (!t.recorded) return { cls: 'warn', text: 'Still provisioned' };
  if (t.contradicted) return { cls: 'disabled', text: 'Still active at target' };
  if (t.verified) return { cls: 'active', text: 'Verified' };
  if (t.acknowledged) return { cls: 'active', text: 'Acknowledged' };
  if (t.lastEvent?.status === 'failed') return { cls: 'disabled', text: 'Failed' };
  return { cls: 'warn', text: t.blocked ? 'Blocked' : 'Pending' };
}

/**
 * Per-app completion of one account's removal. It is honest about three different
 * things: what was queued, what each app acknowledged, and what a later listing actually
 * saw. "Complete" is claimed only when every target is verified.
 */
export const OffboardingView: React.FC<{ userId: string; username: string; onClose: () => void }> = ({ userId, username, onClose }) => {
  const [off, setOff] = useState<Offboarding | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try {
      setOff(await apiJson(`/api/admin/users/${userId}/offboarding`, parseOffboarding));
      setError(null);
    } catch (err) {
      setError(errorMessage(err, 'Failed to load offboarding status'));
    }
  };
  useEffect(() => { load(); }, [userId]);

  const retry = async (path: string, failure: string) => {
    try {
      await apiRequest(path, { method: 'POST' });
      load();
    } catch (err) {
      alert(errorMessage(err, failure));
    }
  };

  const summary = !off ? '' : off.active ? 'The account is active; nothing has been removed.'
    : off.verified ? 'Complete: every target verified the removal.'
    : off.acknowledged ? 'Acknowledged by every target; not yet verified by a listing.'
    : 'Removal still pending on at least one target.';
  const badge = !off ? '' : off.active ? 'Not offboarded' : off.verified ? 'Complete' : off.acknowledged ? 'Acknowledged' : 'Pending';

  return (
    <div className="modal-backdrop">
      <div className="modal-card">
        <div className="modal-header">
          <h3>Offboarding {username}</h3>
          <button className="close-btn" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">
          {error && <div className="form-error">{error}</div>}
          {off && (
            <>
              <p>
                <span className={`status-badge ${off.active ? 'disabled' : off.acknowledged ? 'active' : 'warn'}`}>{badge}</span>{' '}
                {summary}{off.deleted ? ' The directory account is deleted; remote mappings are kept for retries.' : ''}
              </p>
              <div className="device-list">
                {off.targets.length === 0 ? (
                  <div className="empty-box"><p>No paired product holds this account.</p></div>
                ) : (
                  off.targets.map((t) => {
                    const b = targetBadge(t);
                    const ev = t.lastEvent;
                    return (
                      <div key={t.systemId} className="device-card">
                        <div className="device-info">
                          <span className="device-name">
                            {t.systemName}
                            <span className={`status-badge ${b.cls}`}> {b.text}</span>
                            {t.systemStatus === 'disabled' && <span className="status-badge disabled"> Connector disabled</span>}
                          </span>
                          <span className="device-id-mono">
                            {ev ? `${ev.type} ${ev.status} · ${ev.attempts} attempt${ev.attempts === 1 ? '' : 's'} · ${when(ev.updatedAt)}` : 'nothing sent yet'}
                            {ev?.status === 'pending' && ev.nextAttemptAt ? ` · next ${when(ev.nextAttemptAt)}` : ''}
                            {ev?.error ? ` · ${ev.error}` : ''}
                            {` · ${observedLabel[t.observed]}${t.observedAt ? ` ${when(t.observedAt)}` : ''}`}
                          </span>
                        </div>
                        {t.recorded && !t.acknowledged && !t.blocked && (
                          <button className="icon-btn" onClick={() => retry(`/api/admin/systems/${encodeURIComponent(t.systemId)}/provisioning/${userId}/retry`, 'Failed to retry delivery')} title="Retry now" aria-label={`Retry delivery to ${t.systemName}`}>
                            <RefreshCw size={16} />
                          </button>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
              <div className="section-header">
                <div className="section-title-wrap"><h3>Sign-out notifications</h3></div>
              </div>
              <LogoutDeliveries logouts={off.logouts} onRetryLogout={(d) => retry(`/api/admin/users/${userId}/logouts/${d.id}/retry`, 'Failed to retry sign-out notification')} />
            </>
          )}
        </div>
        <div className="modal-footer">
          <button type="button" className="secondary-btn" onClick={load}>Refresh</button>
          <button type="button" className="primary-btn" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
};
