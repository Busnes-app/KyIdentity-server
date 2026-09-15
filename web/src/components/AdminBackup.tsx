import React, { useEffect, useState } from 'react';
import { BackupDrillResult, BackupStatus } from '../types';
import { apiJson, apiRequest, errorMessage } from '../api';
import { isCancelled, useStepUp } from './StepUpPrompt';
import { parseBackupStatus, parseDrillResult, parseBackupRun } from '../parsers';
import {
  Play,
  Download,
  CheckCircle2,
  XCircle,
  Loader2,
  Link2,
  Unlink,
  KeyRound,
  Send,
  AlertCircle,
  RefreshCw,
  Clock,
  HardDrive,
  Server,
} from 'lucide-react';

const HOUR = 3600;
const SCHEDULE_CHOICES: { label: string; sec: number }[] = [
  { label: 'Off', sec: 0 },
  { label: 'Every hour', sec: HOUR },
  { label: 'Every 6 hours', sec: 6 * HOUR },
  { label: 'Every 12 hours', sec: 12 * HOUR },
  { label: 'Daily', sec: 24 * HOUR },
  { label: 'Weekly', sec: 7 * 24 * HOUR },
];

function when(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function every(sec?: number): string {
  if (!sec) return 'Off';
  const hit = SCHEDULE_CHOICES.find((c) => c.sec === sec);
  if (hit) return hit.label;
  return sec % HOUR === 0 ? `Every ${sec / HOUR} hours` : `Every ${Math.round(sec / 60)} minutes`;
}

function bytes(n: number): string {
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MiB`;
  if (n >= 1 << 10) return `${Math.round(n / (1 << 10))} KiB`;
  return `${n} B`;
}

export const AdminBackup: React.FC = () => {
  const [status, setStatus] = useState<BackupStatus | null>(null);
  const [loadingStatus, setLoadingStatus] = useState<boolean>(true);
  const [statusError, setStatusError] = useState<string>('');

  const [running, setRunning] = useState<boolean>(false);
  const [runMessage, setRunMessage] = useState<string>('');
  const [runError, setRunError] = useState<string>('');

  const [runningDrill, setRunningDrill] = useState<boolean>(false);
  const [drillResult, setDrillResult] = useState<BackupDrillResult | null>(null);

  const [scheduleSec, setScheduleSec] = useState<number>(24 * HOUR);
  const [scheduleSaving, setScheduleSaving] = useState<boolean>(false);
  const [scheduleMessage, setScheduleMessage] = useState<string>('');
  const [scheduleError, setScheduleError] = useState<string>('');

  const [remoteUrl, setRemoteUrl] = useState<string>('');
  const [pairCode, setPairCode] = useState<string>('');
  const [pairing, setPairing] = useState<boolean>(false);
  const [pairMessage, setPairMessage] = useState<string>('');
  const [pairError, setPairError] = useState<string>('');

  const [unpairing, setUnpairing] = useState<boolean>(false);

  const [pinKey, setPinKey] = useState<string>('');
  const [pinK, setPinK] = useState<string>('2');
  const [pinN, setPinN] = useState<string>('3');
  const [pinning, setPinning] = useState<boolean>(false);
  const [pinError, setPinError] = useState<string>('');

  // Every action here either produces a sealed copy of the whole directory, changes where
  // it goes, or turns the schedule off, so each runs under its own single-use step-up grant.
  const { requestGrant, stepUpPrompt } = useStepUp();

  const fetchStatus = async () => {
    setLoadingStatus(true);
    setStatusError('');
    try {
      const data = await apiJson('/api/admin/backup/status', parseBackupStatus);
      setStatus(data);
      if (data.recovery_url) setRemoteUrl(data.recovery_url);
      if (typeof data.intervalSec === 'number') setScheduleSec(data.intervalSec);
    } catch (err) {
      setStatusError(errorMessage(err, 'Could not load backup status'));
    } finally {
      setLoadingStatus(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const runBackup = async () => {
    setRunning(true);
    setRunMessage('');
    setRunError('');
    try {
      const grant = await requestGrant('Backing up seals the whole directory and its keys to the suite recovery key and sends the capsule to every configured destination.', 'POST /api/admin/backup/deposit');
      const res = await apiJson('/api/admin/backup/deposit', parseBackupRun, { method: 'POST', stepUpToken: grant });
      const went: string[] = [];
      if (res.localPath) went.push(`written to ${res.localPath}`);
      if (res.receipt) went.push(`deposited with KyRecovery at ${when(res.receipt.depositedAt)}`);
      setRunMessage(`Capsule ${res.capsuleId} (${bytes(res.sizeBytes)}) ${went.join(' and ')}.`);
      if (res.localError) setRunError(`The local copy failed: ${res.localError}`);
      await fetchStatus();
    } catch (err) {
      if (isCancelled(err)) return;
      setRunError(errorMessage(err, 'Backup failed'));
      await fetchStatus();
    } finally {
      setRunning(false);
    }
  };

  /**
   * Downloads the sealed capsule under a fresh step-up grant. A plain link cannot carry the
   * grant header, so the response is fetched and saved from a blob. The step-up header
   * doubles as the CSRF defence on this state-changing GET.
   */
  const downloadCapsule = async () => {
    setRunError('');
    setRunMessage('');
    try {
      const grant = await requestGrant('The capsule holds your entire directory and its keys, sealed to the suite recovery key.', 'GET /api/admin/backup/export-capsule');
      const res = await fetch('/api/admin/backup/export-capsule', {
        credentials: 'same-origin',
        headers: { 'X-KyIdentity-StepUp': grant },
      });
      if (!res.ok) {
        const body: unknown = await res.json().catch(() => ({}));
        const message =
          typeof body === 'object' && body !== null && 'error' in body
            ? String((body as { error: unknown }).error)
            : `Download failed (HTTP ${res.status})`;
        throw new Error(message);
      }
      const match = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') ?? '');
      const url = URL.createObjectURL(await res.blob());
      const a = document.createElement('a');
      a.href = url;
      a.download = match ? match[1] : 'kyidentity.kycap';
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      if (isCancelled(err)) return;
      setRunError(errorMessage(err, 'Could not download the capsule'));
    }
  };

  const runDrill = async () => {
    setRunningDrill(true);
    setDrillResult(null);
    try {
      setDrillResult(await apiJson('/api/admin/backup/drill', parseDrillResult, { method: 'POST' }));
    } catch (err) {
      const message = errorMessage(err, 'Restore drill failed to run');
      setDrillResult({ passed: false, duration_ms: 0, error_message: message, checks: [{ name: 'Execution', passed: false, message }] });
    } finally {
      setRunningDrill(false);
    }
  };

  const saveSchedule = async (e: React.FormEvent) => {
    e.preventDefault();
    setScheduleSaving(true);
    setScheduleMessage('');
    setScheduleError('');
    try {
      const grant = await requestGrant(scheduleSec === 0 ? 'Turning the schedule off stops automatic backups until it is turned back on.' : 'Changing the schedule changes how often this server backs itself up.', 'PUT /api/admin/backup/schedule');
      await apiRequest('/api/admin/backup/schedule', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interval_sec: scheduleSec }),
        stepUpToken: grant,
      });
      setScheduleMessage(scheduleSec === 0 ? 'Automatic backups are off.' : `Backing up ${every(scheduleSec).toLowerCase()}.`);
      await fetchStatus();
    } catch (err) {
      if (isCancelled(err)) return;
      setScheduleError(errorMessage(err, 'Could not save the schedule'));
    } finally {
      setScheduleSaving(false);
    }
  };

  const pair = async (e: React.FormEvent) => {
    e.preventDefault();
    setPairing(true);
    setPairMessage('');
    setPairError('');
    try {
      const grant = await requestGrant('Pairing pins the suite recovery key every future backup is sealed to, and stores a standing credential for the service that will hold them.', 'POST /api/admin/backup/pair-remote');
      await apiRequest('/api/admin/backup/pair-remote', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recovery_url: remoteUrl.trim(), pairing_code: pairCode.trim() }),
        stepUpToken: grant,
      });
      setPairMessage(`Paired with ${remoteUrl.trim()}.`);
      setPairCode('');
      await fetchStatus();
    } catch (err) {
      if (isCancelled(err)) return;
      setPairError(errorMessage(err, 'Pairing failed'));
    } finally {
      setPairing(false);
    }
  };

  const unpair = async () => {
    if (!window.confirm('Unpair from KyRecovery?\n\nScheduled deposits stop and the deposit credential is removed from this server. Capsules KyRecovery already holds stay there, the recovery key stays pinned, and the local backup directory keeps working. Ask the KyRecovery admin to revoke this product there as well.')) return;
    setUnpairing(true);
    setPairMessage('');
    setPairError('');
    try {
      const grant = await requestGrant('Unpairing stops off-site backups until this server is paired again.', 'DELETE /api/admin/backup/pairing');
      await apiRequest('/api/admin/backup/pairing', { method: 'DELETE', stepUpToken: grant });
      setPairMessage('Unpaired. Off-site backups have stopped.');
      await fetchStatus();
    } catch (err) {
      if (isCancelled(err)) return;
      setPairError(errorMessage(err, 'Could not unpair'));
    } finally {
      setUnpairing(false);
    }
  };

  const pin = async (e: React.FormEvent) => {
    e.preventDefault();
    setPinning(true);
    setPinError('');
    try {
      const grant = await requestGrant('Pinning the recovery key decides, once, whose custodian cards can open every backup this server makes.', 'POST /api/admin/backup/pin-key');
      await apiRequest('/api/admin/backup/pin-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ public_key: pinKey.trim(), threshold: Number(pinK), total_shares: Number(pinN) }),
        stepUpToken: grant,
      });
      setPinKey('');
      await fetchStatus();
    } catch (err) {
      if (isCancelled(err)) return;
      setPinError(errorMessage(err, 'Could not pin the key'));
    } finally {
      setPinning(false);
    }
  };

  const keyPinned = status?.keyPinned ?? false;
  const paired = status?.paired ?? false;
  const hasLocal = Boolean(status?.localDir);
  const canBackUp = keyPinned && (paired || hasLocal);
  const scheduleOn = (status?.intervalSec ?? 0) > 0;
  const newestLocal = status?.localCopies[0];

  return (
    <div className="admin-page">
      {stepUpPrompt}
      <div className="page-header">
        <div>
          <h1 className="page-title">Backup &amp; recovery</h1>
        </div>
        <button type="button" className="secondary-btn sm" onClick={fetchStatus} disabled={loadingStatus}>
          <RefreshCw size={14} className={loadingStatus ? 'spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {statusError && (
        <div className="alert-box error sm">
          <AlertCircle size={16} /> {statusError}
        </div>
      )}
      {status?.recovery_key_error && (
        <div className="alert-box error sm">
          <AlertCircle size={16} /> {status.recovery_key_error}
        </div>
      )}
      {status && !keyPinned && (
        <div className="alert-box warn sm">
          <AlertCircle size={16} /> No backups are being made. Pair with KyRecovery or pin the suite recovery key below.
        </div>
      )}
      {status && keyPinned && !paired && !hasLocal && (
        <div className="alert-box warn sm">
          <AlertCircle size={16} /> A key is pinned but capsules have nowhere to go. Pair with KyRecovery, or set KYIDENTITY_BACKUP_DIR to keep copies on this host.
        </div>
      )}
      {status && keyPinned && !scheduleOn && (
        <div className="alert-box warn sm">
          <Clock size={16} /> Automatic backups are off. Only the button below makes one.
        </div>
      )}

      <div className="dr-facts">
        <div className="dr-fact">
          <div className="dr-fact-label">
            <span>Recovery key</span>
            <span className={`status-badge ${keyPinned ? 'active' : 'warn'}`}>{keyPinned ? 'Pinned' : 'None'}</span>
          </div>
          <div className="dr-fact-value font-mono">{status?.recovery_key_id ?? '—'}</div>
          <div className="dr-fact-note">
            {keyPinned ? `${status?.threshold} of ${status?.total_shares} custodian cards open a capsule` : 'Nothing can be sealed until a key is pinned'}
          </div>
        </div>
        <div className="dr-fact">
          <div className="dr-fact-label">
            <span>KyRecovery</span>
            <span className={`status-badge ${paired ? 'active' : 'disabled'}`}>{paired ? 'Paired' : 'Not paired'}</span>
          </div>
          <div className="dr-fact-value">{paired ? status?.recovery_url : 'No off-site copy'}</div>
          <div className="dr-fact-note">
            {status?.last_deposit ? `Last deposit ${when(status.last_deposit.depositedAt)}` : paired ? 'Nothing deposited yet' : ''}
          </div>
        </div>
        <div className="dr-fact">
          <div className="dr-fact-label">
            <span>Local copies</span>
            <span className={`status-badge ${hasLocal ? 'active' : 'disabled'}`}>{hasLocal ? `${status?.localCopies.length ?? 0} of ${status?.localKeep}` : 'Off'}</span>
          </div>
          <div className="dr-fact-value font-mono">{status?.localDir ?? 'KYIDENTITY_BACKUP_DIR not set'}</div>
          <div className="dr-fact-note">{status?.localError ?? (newestLocal ? `Newest ${when(newestLocal.createdAt)}` : hasLocal ? 'Nothing written yet' : '')}</div>
        </div>
        <div className="dr-fact">
          <div className="dr-fact-label">
            <span>Schedule</span>
            <span className={`status-badge ${scheduleOn ? 'active' : 'warn'}`}>{every(status?.intervalSec)}</span>
          </div>
          <div className="dr-fact-value">{scheduleOn && status?.nextRunAt ? `Next ${when(status.nextRunAt)}` : 'Manual only'}</div>
          <div className="dr-fact-note">Counts from the last attempt, successful or not</div>
        </div>
      </div>

      <div className="settings-section">
        <div className="section-header">
          <div className="section-title-wrap">
            <h2>Back up now</h2>
          </div>
          <div className="dr-actions">
            <button type="button" className="primary-btn sm" onClick={runBackup} disabled={running || !canBackUp}>
              {running ? <Loader2 size={14} className="spin" /> : <Send size={14} />}
              <span>{running ? 'Sealing…' : 'Back up now'}</span>
            </button>
            <button type="button" className="secondary-btn sm" onClick={downloadCapsule} disabled={!keyPinned}>
              <Download size={14} />
              <span>Download capsule</span>
            </button>
            <button type="button" className="secondary-btn sm" onClick={runDrill} disabled={runningDrill}>
              {runningDrill ? <Loader2 size={14} className="spin" /> : <Play size={14} />}
              <span>{runningDrill ? 'Restoring…' : 'Run restore drill'}</span>
            </button>
          </div>
        </div>
        <div className="dr-body">
          <p className="form-hint">
            One sealed capsule goes to every destination above: the local directory, and KyRecovery when paired.
            Download saves the same capsule to this browser instead. Nothing on this server can open a capsule;
            that takes {status?.threshold ?? 'k'} custodian cards together.
          </p>
          <div className="text-sm text-muted">A capsule carries</div>
          <ul className="dr-members">
            {(status?.members ?? []).map((m) => (
              <li key={m}>{m}</li>
            ))}
          </ul>
          {runMessage && (
            <div className="alert-box success sm mt-3">
              <CheckCircle2 size={16} /> {runMessage}
            </div>
          )}
          {runError && (
            <div className="alert-box error sm mt-3">
              <XCircle size={16} /> {runError}
            </div>
          )}
          {hasLocal && (status?.localCopies.length ?? 0) > 0 && (
            <ul className="dr-copies">
              {status?.localCopies.map((c) => (
                <li key={c.name}>
                  <span>{c.name}</span>
                  <span>
                    {bytes(c.sizeBytes)} · {when(c.createdAt)}
                  </span>
                </li>
              ))}
            </ul>
          )}
          {drillResult && (
            <div className="mt-3">
              <div className="text-sm">
                Restore drill{' '}
                <span className={`status-badge ${drillResult.passed ? 'active' : 'disabled'}`}>{drillResult.passed ? 'passed' : 'failed'}</span>{' '}
                <span className="text-muted">{drillResult.duration_ms} ms</span>
              </div>
              {drillResult.error_message && <div className="text-sm text-danger mt-2">{drillResult.error_message}</div>}
              <div className="dr-checks">
                {drillResult.checks.map((check, idx) => (
                  <div key={idx} className="dr-check">
                    {check.passed ? <CheckCircle2 size={14} className="text-cyan" /> : <XCircle size={14} className="text-danger" />}
                    <span className="font-bold">{check.name}</span>
                    <span className="text-muted">{check.message}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="settings-section">
        <div className="section-header">
          <div className="section-title-wrap">
            <h2>Schedule</h2>
          </div>
        </div>
        <div className="dr-body">
          <form onSubmit={saveSchedule} className="form-row" style={{ alignItems: 'flex-end' }}>
            <div className="form-group flex-1" style={{ marginBottom: 0 }}>
              <label className="form-label" htmlFor="backup-interval">
                Back up automatically
              </label>
              <select id="backup-interval" className="form-select" value={scheduleSec} onChange={(e) => setScheduleSec(Number(e.target.value))}>
                {SCHEDULE_CHOICES.map((c) => (
                  <option key={c.sec} value={c.sec}>
                    {c.label}
                  </option>
                ))}
              </select>
            </div>
            <button type="submit" className="primary-btn sm" disabled={scheduleSaving || scheduleSec === (status?.intervalSec ?? -1)}>
              {scheduleSaving ? <Loader2 size={14} className="spin" /> : <Clock size={14} />}
              <span>Save</span>
            </button>
          </form>
          <p className="form-hint mt-3" style={{ marginBottom: 0 }}>
            Each run snapshots the whole database, so the floor is {Math.round((status?.minIntervalSec ?? 900) / 60)} minutes.
            The schedule does nothing until a key is pinned and there is somewhere to send the capsule.
          </p>
          {scheduleMessage && (
            <div className="alert-box success sm mt-3">
              <CheckCircle2 size={16} /> {scheduleMessage}
            </div>
          )}
          {scheduleError && (
            <div className="alert-box error sm mt-3">
              <XCircle size={16} /> {scheduleError}
            </div>
          )}
        </div>
      </div>

      <div className="dr-two">
        <div className="settings-section">
          <div className="section-header">
            <div className="section-title-wrap">
              <h2>
                <Server size={16} className="icon-cyan" /> KyRecovery
              </h2>
            </div>
            <span className={`status-badge ${paired ? 'active' : 'disabled'}`}>{paired ? 'Paired' : 'Not paired'}</span>
          </div>
          <div className="dr-body">
            <p className="form-hint">
              KyRecovery keeps capsules it cannot open, off this host. In its dashboard, generate a pairing code for
              this service and enter it here. Pairing hands this server the suite recovery key and a deposit credential;
              {paired ? ' re-pairing is only accepted with the same key.' : ' the key is pinned once and never replaced.'}
            </p>
            <form onSubmit={pair}>
              <div className="form-group">
                <label className="form-label" htmlFor="recovery-url">
                  Server URL
                </label>
                <input id="recovery-url" className="form-input" type="url" placeholder="https://recovery.example.com" value={remoteUrl} onChange={(e) => setRemoteUrl(e.target.value)} required />
              </div>
              <div className="form-row" style={{ alignItems: 'flex-end' }}>
                <div className="form-group flex-1" style={{ marginBottom: 0 }}>
                  <label className="form-label" htmlFor="pairing-code">
                    Pairing code
                  </label>
                  <input id="pairing-code" className="form-input font-mono" type="text" inputMode="numeric" placeholder="123456" value={pairCode} onChange={(e) => setPairCode(e.target.value)} required />
                </div>
                <button type="submit" className="primary-btn sm" disabled={pairing}>
                  {pairing ? <Loader2 size={14} className="spin" /> : <Link2 size={14} />}
                  <span>{paired ? 'Re-pair' : 'Pair'}</span>
                </button>
              </div>
            </form>
            {paired && (
              <button type="button" className="secondary-btn sm mt-3" onClick={unpair} disabled={unpairing}>
                {unpairing ? <Loader2 size={14} className="spin" /> : <Unlink size={14} />}
                <span>Unpair</span>
              </button>
            )}
            {pairMessage && (
              <div className="alert-box success sm mt-3">
                <CheckCircle2 size={16} /> {pairMessage}
              </div>
            )}
            {pairError && (
              <div className="alert-box error sm mt-3">
                <XCircle size={16} /> {pairError}
              </div>
            )}
          </div>
        </div>

        <div className="settings-section">
          <div className="section-header">
            <div className="section-title-wrap">
              <h2>
                <KeyRound size={16} className="icon-cyan" /> Recovery key by hand
              </h2>
            </div>
            <span className={`status-badge ${keyPinned ? 'active' : 'warn'}`}>{keyPinned ? 'Pinned' : 'None'}</span>
          </div>
          <div className="dr-body">
            {keyPinned ? (
              <p className="form-hint" style={{ marginBottom: 0 }}>
                The key is pinned{paired ? ' by pairing' : ''}. Rotating it means a new ceremony and a fresh data
                directory; there is no button for that on purpose.
              </p>
            ) : (
              <>
                <p className="form-hint">
                  For a server with no KyRecovery. Run the suite ceremony once, keep the custodian cards, and paste
                  the public key it shows, with the split it used. Capsules then go to the local directory.
                </p>
                <form onSubmit={pin}>
                  <div className="form-group">
                    <label className="form-label" htmlFor="pin-key">
                      Suite recovery public key
                    </label>
                    <textarea id="pin-key" className="form-textarea font-mono" rows={4} value={pinKey} onChange={(e) => setPinKey(e.target.value)} placeholder="base64 from the ceremony page" required />
                  </div>
                  <div className="form-row" style={{ alignItems: 'flex-end' }}>
                    <div className="form-group" style={{ marginBottom: 0, width: '6rem' }}>
                      <label className="form-label" htmlFor="pin-k">
                        Needed
                      </label>
                      <input id="pin-k" className="form-input" type="number" min={2} max={255} value={pinK} onChange={(e) => setPinK(e.target.value)} required />
                    </div>
                    <div className="form-group" style={{ marginBottom: 0, width: '6rem' }}>
                      <label className="form-label" htmlFor="pin-n">
                        Of
                      </label>
                      <input id="pin-n" className="form-input" type="number" min={2} max={255} value={pinN} onChange={(e) => setPinN(e.target.value)} required />
                    </div>
                    <div className="flex-1" />
                    <button type="submit" className="primary-btn sm" disabled={pinning}>
                      {pinning ? <Loader2 size={14} className="spin" /> : <KeyRound size={14} />}
                      <span>Pin key</span>
                    </button>
                  </div>
                </form>
                {pinError && (
                  <div className="alert-box error sm mt-3">
                    <XCircle size={16} /> {pinError}
                  </div>
                )}
              </>
            )}
            {hasLocal && (
              <p className="form-hint mt-3" style={{ marginBottom: 0 }}>
                <HardDrive size={12} className="icon-cyan" /> Local copies land in {status?.localDir}; the newest {status?.localKeep} are kept.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
