import React, { useEffect, useState } from 'react';
import { Trash2 } from 'lucide-react';
import { apiJson, apiRequest, errorMessage, isRecord, isStepUpRequired } from '../api';
import { parseLauncher } from '../parsers';
import { Application, User } from '../types';
import { Modal } from './Modal';
import { PageHead } from './PageHead';
import { isCancelled, useStepUp } from './StepUpPrompt';

export interface EraseScope { holder: boolean; otherMembers: number }

export function parseEraseScope(value: unknown): EraseScope {
  if (!isRecord(value) || typeof value.holder !== 'boolean' || typeof value.otherMembers !== 'number') throw new Error('Unexpected erase options');
  return { holder: value.holder, otherMembers: value.otherMembers };
}

/** What the clicker types, as the server checks it: the mailbox address, else the sign-in email. */
export function eraseAddress(user: Pick<User, 'email' | 'mailboxAddress'>): string {
  return user.mailboxAddress || user.email;
}

/** The typed address confirms only a non-empty address, ignoring case and outer spaces. */
export function confirmsAddress(typed: string, address: string): boolean {
  return address !== '' && typed.trim().toLowerCase() === address.toLowerCase();
}

/** What the button deletes, in the clicker's words. */
export function eraseSummary(scope: EraseScope): string {
  if (!scope.holder) return 'Deletes your account and everything you keep in every app. Everyone else in your organisation keeps their data.';
  if (scope.otherMembers === 0) return 'Deletes your account and everything in it, in every app, right away.';
  const others = scope.otherMembers === 1 ? 'The other member has' : `The other ${scope.otherMembers} members have`;
  return `Deletes your organisation. You lose access straight away. ${others} 7 days to export their own data before everything is deleted.`;
}

type AppList = Application[] | 'loading' | 'failed';

/** Loads the apps to export from; retry runs it again. */
function useExportApps(active: boolean): [AppList, () => void] {
  const [apps, setApps] = useState<AppList>('loading');
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!active) return;
    let live = true;
    setApps('loading');
    apiJson('/api/user/applications', parseLauncher)
      .then(l => { if (live) setApps(l.applications.filter(a => a.url)); })
      .catch(() => { if (live) setApps('failed'); });
    return () => { live = false; };
  }, [active, attempt]);
  return [apps, () => setAttempt(n => n + 1)];
}

/** The export links, or why there are none. A failed load never reads as "nothing to export". */
export const ExportLinks: React.FC<{ apps: AppList; retry: () => void }> = ({ apps, retry }) => {
  if (apps === 'loading') return <p role="status">Loading your apps…</p>;
  if (apps === 'failed') return (
    <div className="alert-box error" role="alert">
      <span>Your apps could not be loaded, so you cannot export from here yet.</span>
      <button type="button" className="secondary-btn sm" onClick={retry}>Try again</button>
    </div>
  );
  if (apps.length === 0) return <p className="text-muted text-sm">You have no apps to export from.</p>;
  return <ul className="erase-apps">{apps.map(a => <li key={a.key}><a href={a.url} target="_blank" rel="noopener noreferrer">Export from {a.name}</a></li>)}</ul>;
};

/**
 * Delete everything (multi-tenant only). The server answers 404 elsewhere, and then this
 * renders nothing. Exports come first, then the typed address and a step-up with a second factor.
 */
export const EraseAccount: React.FC<{ user: User }> = ({ user }) => {
  const [scope, setScope] = useState<EraseScope | null>(null);
  const [open, setOpen] = useState(false);
  const [apps, retryApps] = useExportApps(open);
  const [typed, setTyped] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const { requestGrant, stepUpPrompt } = useStepUp();

  useEffect(() => {
    let live = true;
    apiJson('/api/user/erase', parseEraseScope).then(s => { if (live) setScope(s); }).catch(() => {});
    return () => { live = false; };
  }, []);

  if (!scope) return null;
  const address = eraseAddress(user);
  const matches = confirmsAddress(typed, address);
  const scheduled = scope.holder && scope.otherMembers > 0;

  const close = () => { if (!busy) { setOpen(false); setTyped(''); setError(null); } };
  const erase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!matches || busy) return;
    setBusy(true);
    setError(null);
    try {
      const grant = await requestGrant('Enter your password and a second factor. This cannot be undone.', 'POST /api/user/erase');
      await apiRequest('/api/user/erase', { method: 'POST', stepUpToken: grant, body: JSON.stringify({ address: typed }) });
      setDone(true);
    } catch (err) {
      if (!isCancelled(err)) {
        setError(isStepUpRequired(err)
          ? 'This needs a second factor. Add an authenticator app, a passkey or KyAuth above, then try again.'
          : errorMessage(err, 'Could not delete'));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="settings-page security-page"><div className="settings-section">
      <div className="section-header">
        <div className="section-title-wrap">
          <h2>Delete everything</h2>
        </div>
        <button className="secondary-btn sm danger" onClick={() => setOpen(true)}>
          <Trash2 size={15} /><span>Delete everything…</span>
        </button>
      </div>
      <p className="text-muted text-sm">{eraseSummary(scope)} This cannot be undone.</p>
      {open && (
        <Modal title={done ? (scheduled ? 'Deletion scheduled' : 'Everything deleted') : 'Delete everything'}
          onClose={done ? () => window.location.assign('/') : close}>
          {done ? (
            <div className="modal-body">
              <p className="modal-desc" role="status">{scheduled
                ? 'You have been signed out. The other members have 7 days to export their own data.'
                : 'Everything has been deleted, and you have been signed out.'}</p>
            </div>
          ) : (
            <form onSubmit={erase}>
              <div className="modal-body">
                <p className="modal-desc">{eraseSummary(scope)} This cannot be undone.</p>
                <h4 className="erase-step">1. Export first</h4>
                <ExportLinks apps={apps} retry={retryApps} />
                <h4 className="erase-step">2. Confirm</h4>
                <div className="form-group">
                  <label className="form-label" htmlFor="erase-address">Type <strong>{address}</strong> to confirm</label>
                  <input id="erase-address" className="form-input" type="text" autoComplete="off" spellCheck={false}
                    value={typed} disabled={busy} onChange={e => setTyped(e.target.value)} />
                </div>
                {error && <div className="alert-box error" role="alert">{error}</div>}
                <div className="modal-footer">
                  <button type="submit" className="primary-btn danger" disabled={!matches || busy}>
                    <Trash2 size={16} /><span>{busy ? 'Deleting…' : 'Delete everything'}</span>
                  </button>
                </div>
              </div>
            </form>
          )}
        </Modal>
      )}
      {stepUpPrompt}
    </div></div>
  );
};

/**
 * The export-only session (an organisation being deleted): each app to export from, and
 * sign out. The server refuses everything else for this session.
 */
export const ExportOnly: React.FC<{ onLogout: () => void }> = ({ onLogout }) => {
  const [apps, retry] = useExportApps(true);
  return (
    <>
      <PageHead title="Your organisation is being deleted" lede="Export your own data from each app below before your organisation and its data are permanently deleted." />
      <div className="settings-page security-page"><div className="settings-section">
        <div className="section-header">
          <div className="section-title-wrap"><h2>Export your data</h2></div>
          <button className="secondary-btn sm" onClick={onLogout}><span>Sign out</span></button>
        </div>
        <ExportLinks apps={apps} retry={retry} />
      </div></div>
    </>
  );
};
