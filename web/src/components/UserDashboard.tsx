import React, { useEffect, useState } from 'react';
import { User, Application } from '../types';
import { apiJson, apiRequest, errorMessage, isRecord } from '../api';
import { parseApplications } from '../parsers';
import { AccessRequests } from './AccessRequests';
import { faviconUrl } from '../favicon';
import { Image, Upload, ExternalLink, ArrowUpRight, Plus, Pencil } from 'lucide-react';
import { LAUNCHER_ICONS, launcherIcon } from '../launcherIcons';

interface UserDashboardProps {
  user: User;
  manage?: boolean;
  onNavigateToDevices: () => void;
}

/** The card being edited, or a blank one when adding. */
interface CardDraft {
  id: string;
  source?: Application['source'];
  name: string;
  url: string;
  description: string;
  iconName: string;
}

const blankDraft: CardDraft = { id: '', name: '', url: '', description: '', iconName: 'favicon' };

/** Uploaded icons are named "icon:<id>" and served by the API; built-ins are drawn inline. */
function uploadedIconUrl(iconName: string): string | undefined {
  const id = iconName.startsWith('icon:') ? iconName.slice(5) : '';
  return /^[0-9a-f-]{36}$/.test(id) ? `/api/icons/${id}` : undefined;
}

const METHOD_LABELS: Record<string, string> = {
  push: 'Phone approval',
  webauthn: 'Passkey',
  totp: 'Six-digit codes',
};

export const UserDashboard: React.FC<UserDashboardProps> = ({ user, onNavigateToDevices, manage = false }) => {
  const [notice, setNotice] = useState<string | null>(null);
  const [apps, setApps] = useState<Application[]>([]);
  const [failedFavicons, setFailedFavicons] = useState<string[]>([]);
  const [draft, setDraft] = useState<CardDraft | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const fetchApps = () =>
    apiJson(manage ? '/api/admin/applications' : '/api/user/applications', parseApplications)
      .then(setApps)
      .catch(() => setApps([]));

  useEffect(() => {
    fetchApps();
  }, [manage]);

  // The picker is a scrolling grid; open it on the card's current icon rather than the top.
  useEffect(() => {
    document.querySelector('.icon-pick[aria-pressed="true"]')?.scrollIntoView({ block: 'nearest' });
  }, [draft?.id]);

  const editCard = (app: Application) =>
    setDraft({
      id: app.id,
      source: app.source,
      name: app.name,
      url: app.url,
      description: app.description ?? '',
      iconName: app.iconName || 'favicon',
    });

  // A client-derived card is presentation over a registered OAuth client, so only its blurb
  // and icon are editable here; its name and URL belong to the client registration.
  const isClientCard = draft?.source === 'client';

  const saveCard = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!draft) return;
    try {
      if (isClientCard) {
        await apiRequest(`/api/admin/clients/${encodeURIComponent(draft.id)}/launcher`, {
          method: 'PUT',
          body: JSON.stringify({ description: draft.description.trim(), iconName: draft.iconName }),
        });
      } else {
        const body = JSON.stringify({
          name: draft.name.trim(),
          url: draft.url.trim(),
          description: draft.description.trim(),
          iconName: draft.iconName,
        });
        await (draft.id
          ? apiRequest(`/api/admin/applications/${encodeURIComponent(draft.id)}`, { method: 'PUT', body })
          : apiRequest('/api/admin/applications', { method: 'POST', body }));
      }
      if (!draft.id) setNotice('Application created. Assign access under Administration → App connections.');
      setDraft(null);
      setFailedFavicons([]);
      fetchApps();
    } catch (err) {
      alert(errorMessage(err, 'Failed to save application'));
    }
  };

  const uploadIcon = async (file: File | undefined) => {
    if (!file || !draft) return;
    setUploadError(null);
    if (file.size > 128 * 1024) {
      setUploadError('Icon must be 128 KiB or smaller.');
      return;
    }
    try {
      const body = await apiRequest('/api/admin/icons', {
        method: 'POST',
        body: file,
        headers: { 'Content-Type': file.type },
      });
      const iconName = isRecord(body) && typeof body.iconName === 'string' ? body.iconName : '';
      if (!iconName) throw new Error('Upload returned no icon');
      setDraft({ ...draft, iconName });
    } catch (err) {
      setUploadError(errorMessage(err, 'Upload failed'));
    }
  };

  const methods = (user.mfaMethods ?? []).filter((m) => m in METHOD_LABELS);
  const isAdmin = user.role === 'admin';
  const suite = apps.filter((app) => app.source === 'client');
  const links = apps.filter((app) => app.source !== 'client');

  const appList = (list: Application[]) => (
    <ul className="app-list">
      {list.map((app) => {
        const IconComp = launcherIcon(app.iconName) ?? ExternalLink;
        const favicon = app.iconName === 'favicon' ? faviconUrl(app.url) : uploadedIconUrl(app.iconName);
        return (
          <li key={app.id}>
            <a href={app.url} target="_blank" rel="noopener noreferrer" className="app-row">
              <span className="app-icon">
                {favicon && !failedFavicons.includes(app.id) ? (
                  <img
                    className="app-favicon"
                    src={favicon}
                    alt=""
                    referrerPolicy="no-referrer"
                    onError={() => setFailedFavicons((ids) => [...ids, app.id])}
                  />
                ) : (
                  <IconComp size={20} />
                )}
              </span>
              <span className="app-text">
                <b>{app.name}</b>
                {app.description && <span>{app.description}</span>}
              </span>
              <ArrowUpRight size={16} className="app-go" />
            </a>
            {isAdmin && (
              <button
                className="app-edit-btn"
                onClick={() => editCard(app)}
                aria-label={`Edit ${app.name}`}
                title="Edit this card"
              >
                <Pencil size={14} />
              </button>
            )}
          </li>
        );
      })}
    </ul>
  );

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">{manage ? 'Manage launcher cards' : 'Applications'}</h1>
        {isAdmin && (
          <button className="secondary-btn sm" onClick={() => setDraft({ ...blankDraft })}>
            <Plus size={14} /> Add application
          </button>
        )}
      </div>

      {notice && <p className="alert-box success" role="status">{notice}</p>}
      {!manage && <div className="identity">
        <div>
          <span className="text-muted">Signed in as</span>
          <div className="identity-name">{user.username}</div>
          <div className="identity-facts">
            <span>{user.displayName || user.username}</span>
            <span>{user.email}</span>
            <span>{isAdmin ? 'Administrator' : 'User'}</span>
          </div>
        </div>
        <button type="button" className="identity-mfa" onClick={onNavigateToDevices}>
          <span className="text-muted">Second factor</span>
          {methods.length > 0 ? (
            <ul>
              {methods.map((m) => (
                <li key={m}>{METHOD_LABELS[m]}</li>
              ))}
            </ul>
          ) : (
            <b>None. Set one up.</b>
          )}
        </button>
      </div>}

      {apps.length === 0 && (
        <p className="app-empty">
          {manage ? 'No launcher cards yet. Add an application link.' : isAdmin ? 'No applications are available to you. Manage assignments under App connections.' : 'No applications are available to you. Ask an administrator for access.'}
        </p>
      )}

      {suite.length > 0 && (
        <>
          <h2 className="section-title">Suite</h2>
          {appList(suite)}
        </>
      )}
      {links.length > 0 && (
        <>
          <h2 className="section-title">Other links</h2>
          {appList(links)}
        </>
      )}
      {!manage && <AccessRequests />}

      {draft && (
        <div className="modal-backdrop" onMouseDown={() => setDraft(null)}>
          <div className="modal-card" onMouseDown={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h3>{draft.id ? `Edit ${draft.name}` : 'Add external application'}</h3>
              <button className="close-btn" onClick={() => setDraft(null)} aria-label="Close">
                ×
              </button>
            </div>
            <form className="modal-body" onSubmit={saveCard}>
              {!isClientCard && (
                <>
                  <div className="form-group">
                    <label className="form-label" htmlFor="app-name">Application name</label>
                    <input
                      id="app-name"
                      className="form-input"
                      value={draft.name}
                      onChange={(event) => setDraft({ ...draft, name: event.target.value })}
                      required
                      autoFocus
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label" htmlFor="app-url">Application URL</label>
                    <input
                      id="app-url"
                      className="form-input font-mono"
                      type="url"
                      value={draft.url}
                      onChange={(event) => setDraft({ ...draft, url: event.target.value })}
                      placeholder="https://portainer.example.com"
                      required
                    />
                  </div>
                </>
              )}
              {isClientCard && (
                <p className="form-hint">
                  Name and sign-in URL come from this app&apos;s OAuth client registration. Change them
                  under OAuth clients.
                </p>
              )}
              <div className="form-group">
                <label className="form-label" htmlFor="app-description">Description (optional)</label>
                <input
                  id="app-description"
                  className="form-input"
                  value={draft.description}
                  onChange={(event) => setDraft({ ...draft, description: event.target.value })}
                  maxLength={200}
                  placeholder="What this app is for"
                  autoFocus={isClientCard}
                />
              </div>
              <fieldset className="form-group icon-picker">
                <legend className="form-label">Icon</legend>
                <label className="icon-pick" aria-pressed={draft.iconName.startsWith('icon:')} title="Upload an image">
                  {uploadedIconUrl(draft.iconName) ? (
                    <img className="app-favicon" src={uploadedIconUrl(draft.iconName)} alt="" />
                  ) : (
                    <Upload size={20} />
                  )}
                  <span>Upload</span>
                  <input
                    type="file"
                    accept="image/png,image/jpeg,image/webp,image/svg+xml"
                    onChange={(event) => uploadIcon(event.target.files?.[0])}
                  />
                </label>
                <button
                  type="button"
                  className="icon-pick"
                  aria-pressed={draft.iconName === 'favicon'}
                  title="Site favicon"
                  onClick={() => setDraft({ ...draft, iconName: 'favicon' })}
                >
                  <Image size={20} />
                  <span>Favicon</span>
                </button>
                {LAUNCHER_ICONS.map(([name, label, Icon]) => (
                  <button
                    key={name}
                    type="button"
                    className="icon-pick"
                    aria-pressed={draft.iconName === name}
                    title={label}
                    onClick={() => setDraft({ ...draft, iconName: name })}
                  >
                    <Icon size={20} />
                    <span>{label}</span>
                  </button>
                ))}
              </fieldset>
              {uploadError && <p className="form-hint text-danger">{uploadError}</p>}
              <div className="modal-footer">
                <button type="button" className="secondary-btn" onClick={() => setDraft(null)}>Cancel</button>
                <button type="submit" className="primary-btn">{draft.id ? 'Save changes' : 'Add application'}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
