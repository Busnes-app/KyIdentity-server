import React, { useEffect, useState } from 'react';
import { Trash2 } from 'lucide-react';
import { ApiError, apiJson, apiRequest, errorMessage, isRecord, isStepUpRequired } from '../api';
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
        <HolderOrgExport />
        <ExportLinks apps={apps} retry={retry} />
      </div></div>
    </>
  );
};

export function parseOrgExportStatus(v: unknown): number {
  if (!isRecord(v) || typeof v.deleteAfter !== 'number' || !Number.isSafeInteger(v.deleteAfter) || v.deleteAfter <= 0) throw new Error('Export deadline is malformed');
  return v.deleteAfter;
}

export type OrgExportContinuation =
  | { readonly kind: 'complete' }
  | { readonly kind: 'partial'; readonly truncatedSections: string[]; readonly nextAuditOffset: number | null };

export function parseOrgExportContinuation(v: unknown): OrgExportContinuation {
  if (!isRecord(v)) throw new Error('Organisation export is malformed');
  if (v.partial !== true) return { kind: 'complete' };
  const truncatedSections: string[] = [];
  let nextAuditOffset: number | null = null;
  if (isRecord(v.truncated)) {
    for (const [section, info] of Object.entries(v.truncated)) {
      truncatedSections.push(section);
      if (section === 'audit' && isRecord(info) && typeof info.next_offset === 'number' && Number.isSafeInteger(info.next_offset) && info.next_offset > 0) {
        nextAuditOffset = info.next_offset;
      }
    }
  }
  return { kind: 'partial', truncatedSections, nextAuditOffset };
}

export function orgExportUrl(auditOffset = 0): string {
  return auditOffset > 0 ? `/api/user/org-export?audit_offset=${auditOffset}` : '/api/user/org-export';
}

export function orgExportFilename(auditOffset = 0): string {
  return auditOffset > 0 ? `organisation-audit-from-${auditOffset}.json` : 'organisation.json';
}

function triggerJsonDownload(data: unknown, filename: string): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

type ExportDownloadState =
  | { readonly kind: 'idle' }
  | { readonly kind: 'downloading'; readonly offset: number }
  | { readonly kind: 'complete'; readonly pagesDownloaded: number }
  | { readonly kind: 'partial'; readonly pagesDownloaded: number; readonly truncatedSections: string[]; readonly nextAuditOffset: number | null }
  | { readonly kind: 'error'; readonly message: string; readonly retryOffset: number; readonly priorPages: number };

export function HolderExportLink({ deadline, initialContinuation }: { deadline: number; initialContinuation?: OrgExportContinuation }) {
  const [download, setDownload] = useState<ExportDownloadState>(() => {
    if (!initialContinuation) return { kind: 'idle' };
    if (initialContinuation.kind === 'complete') return { kind: 'complete', pagesDownloaded: 1 };
    return { kind: 'partial', pagesDownloaded: 1, truncatedSections: initialContinuation.truncatedSections, nextAuditOffset: initialContinuation.nextAuditOffset };
  });

  const downloadPage = async (offset: number, priorPages: number) => {
    setDownload({ kind: 'downloading', offset });
    try {
      const data = await apiRequest(orgExportUrl(offset));
      const continuation = parseOrgExportContinuation(data);
      triggerJsonDownload(data, orgExportFilename(offset));
      const pagesDownloaded = priorPages + 1;
      if (continuation.kind === 'complete') {
        setDownload({ kind: 'complete', pagesDownloaded });
      } else {
        setDownload({ kind: 'partial', pagesDownloaded, truncatedSections: continuation.truncatedSections, nextAuditOffset: continuation.nextAuditOffset });
      }
    } catch (err) {
      setDownload({ kind: 'error', message: errorMessage(err, 'Could not download the organisation export.'), retryOffset: offset, priorPages });
    }
  };

  const nextAuditOffset = download.kind === 'partial' ? download.nextAuditOffset : null;

  return (
    <div className="alert-box" role="status">
      <div>
        <p>Your organisation is scheduled for permanent deletion on {new Date(deadline * 1000).toLocaleString()}. As account holder, you can download the organisation’s directory, memberships, assignments and audit log. App content is exported from each app separately.</p>
        <div className="action-row">
          <button
            type="button"
            className="secondary-btn"
            disabled={download.kind === 'downloading'}
            onClick={() => void downloadPage(0, 0)}
          >
            {download.kind === 'downloading' && download.offset === 0 ? 'Downloading…' : 'Download organisation directory (JSON)'}
          </button>
          {download.kind === 'partial' && nextAuditOffset !== null && (
            <button
              type="button"
              className="secondary-btn"
              onClick={() => void downloadPage(nextAuditOffset, download.pagesDownloaded)}
            >
              Download next audit page (from event {nextAuditOffset})
            </button>
          )}
        </div>
        {download.kind === 'partial' && (
          <p role="alert">
            Partial export saved ({download.pagesDownloaded} {download.pagesDownloaded === 1 ? 'file' : 'files'}).{' '}
            {download.truncatedSections.length > 0
              ? `These sections exceeded the per-download limit: ${download.truncatedSections.join(', ')}. `
              : 'This export exceeded the per-download limit. '}
            {download.nextAuditOffset !== null
              ? `Use “Download next audit page” to fetch remaining audit events starting at offset ${download.nextAuditOffset}.`
              : 'Contact support if you need additional pages for non-audit sections.'}
          </p>
        )}
        {download.kind === 'complete' && (
          <p>Organisation directory export downloaded ({download.pagesDownloaded} {download.pagesDownloaded === 1 ? 'file' : 'files'}).</p>
        )}
        {download.kind === 'error' && (
          <p role="alert">
            {download.message}{' '}
            <button type="button" className="secondary-btn" onClick={() => void downloadPage(download.retryOffset, download.priorPages)}>
              Try again
            </button>
          </p>
        )}
      </div>
    </div>
  );
}
function HolderOrgExport() {
  const [state, setState] = useState<number | 'loading' | 'hidden' | 'failed'>('loading');
  const load = () => { setState('loading'); apiJson('/api/user/org-export/status', parseOrgExportStatus).then(setState).catch(e => setState(e instanceof ApiError && e.status === 404 ? 'hidden' : 'failed')); };
  useEffect(load, []);
  if (state === 'hidden') return null;
  if (state === 'loading') return <p role="status">Checking organisation export…</p>;
  if (state === 'failed') return <div className="alert-box error" role="alert">Could not check the organisation export. <button className="secondary-btn" onClick={load}>Try again</button></div>;
  return <HolderExportLink deadline={state} />;
}
