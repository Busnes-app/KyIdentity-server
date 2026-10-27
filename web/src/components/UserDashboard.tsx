import React, { useEffect, useState } from 'react';
import { User, Application, Launcher, LauncherPrefs } from '../types';
import { apiJson, apiRequest, errorMessage, isRecord } from '../api';
import { parseApplications, parseLauncher } from '../parsers';
import { AccessRequests } from './AccessRequests';
import { Image, Upload, ArrowUpRight, Plus, Pencil } from 'lucide-react';
import { LAUNCHER_ICONS } from '../launcherIcons';
import { AppIcon, LauncherView, uploadedIconUrl } from './Launcher';
import { LauncherCustomize } from './LauncherCustomize';
import { arrange, normalize, searchLauncher, unhide } from '../launcherLayout';
import { Modal } from './Modal';

interface UserDashboardProps {
  user: User;
  manage?: boolean;
  onNavigateToDevices: () => void;
  onNavigateToConnections?: () => void;
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

const SECOND_FACTORS = ['push', 'webauthn', 'totp'];

export const UserDashboard: React.FC<UserDashboardProps> = (props) =>
  props.manage ? <ManageCards user={props.user} /> : <Applications {...props} />;

/** The everyday launcher, arranged the way this user chose. */
const Applications: React.FC<UserDashboardProps> = ({ user, onNavigateToDevices, onNavigateToConnections }) => {
  const [launcher, setLauncher] = useState<Launcher | null>(null);
  const [editing, setEditing] = useState(false);
  const [query, setQuery] = useState('');
  const [error, setError] = useState<string | null>(null);

  const load = () =>
    apiJson('/api/user/applications', parseLauncher)
      .then(setLauncher)
      .catch((err) => setError(errorMessage(err, 'Could not load your applications')));

  useEffect(() => {
    load();
  }, []);

  const save = async (prefs: LauncherPrefs) => {
    setError(null);
    try {
      await apiRequest('/api/user/launcher-preferences', { method: 'PUT', body: JSON.stringify(prefs) });
      setLauncher((l) => l && { ...l, preferences: prefs });
      setEditing(false);
    } catch (err) {
      setError(errorMessage(err, 'Could not save your launcher'));
    }
  };

  const reset = async () => {
    setError(null);
    try {
      await apiRequest('/api/user/launcher-preferences', { method: 'DELETE' });
      setEditing(false);
      await load();
    } catch (err) {
      setError(errorMessage(err, 'Could not reset your launcher'));
    }
  };

  const apps = launcher?.applications ?? [];
  const prefs = launcher?.preferences ?? null;
  const arranged = searchLauncher(arrange(apps, prefs), query);
  const resultCount = arranged.groups.reduce((count, group) => count + group.apps.length, 0) + arranged.hidden.length;
  const noSecondFactor = !(user.mfaMethods ?? []).some((m) => SECOND_FACTORS.includes(m));
  const errorBox = error && <p className="alert-box error" role="alert">{error}</p>;

  if (editing) {
    return (
      <div>
        {errorBox}
        <LauncherCustomize
          apps={apps}
          initial={normalize(apps, prefs)}
          onCancel={() => setEditing(false)}
          onSave={save}
          onReset={reset}
        />
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div><h1 className="page-title">Applications</h1><p className="launcher-intro">Your workspace, connected.</p></div>
        <div className="launcher-who">
          {apps.length > 0 && (
            <button type="button" className="secondary-btn sm" onClick={() => setEditing(true)}>
              Customize
            </button>
          )}
        </div>
      </div>
      {noSecondFactor && (
        <p className="alert-box warn">
          Your account has no second factor.{' '}
          <button type="button" className="text-btn" onClick={onNavigateToDevices}>
            Set one up
          </button>
        </p>
      )}
      {errorBox}
      {launcher && apps.length === 0 && (
        <p className="app-empty">
          {user.role === 'admin'
            ? 'No applications are available to you. Manage assignments under App connections.'
            : 'No applications are available to you. Ask an administrator for access.'}
        </p>
      )}
      {launcher && apps.length === 0 && onNavigateToConnections && <button type="button" className="secondary-btn" onClick={onNavigateToConnections}>Manage app connections</button>}
      {apps.length > 0 && <div className="launcher-search">
        <label htmlFor="application-search">Find an application</label>
        <div className="launcher-search-controls">
          <input id="application-search" type="search" placeholder="Search by name or description" value={query} onChange={(event) => setQuery(event.target.value)} />
          {query && <button type="button" className="secondary-btn sm" onClick={() => setQuery('')}>Clear search</button>}
        </div>
        {query.trim() && <p role="status">{resultCount} {resultCount === 1 ? 'match' : 'matches'}{resultCount === 0 ? '. Try another name or clear your search.' : ''}</p>}
      </div>}
      <LauncherView arranged={arranged} onUnhide={(key) => save(unhide(normalize(apps, prefs), key))} />
      <AccessRequests />
    </div>
  );
};

/** Every custom launcher card, independent of the admin's own access. */
const ManageCards: React.FC<{ user: User }> = ({ user }) => {
  const [notice, setNotice] = useState<string | null>(null);
  const [apps, setApps] = useState<Application[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [draft, setDraft] = useState<CardDraft | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const fetchApps = () =>
    apiJson('/api/admin/applications', parseApplications)
      .then((list) => { setApps(list); setLoadError(null); })
      .catch((err) => setLoadError(errorMessage(err, 'Could not load launcher cards')));

  useEffect(() => {
    fetchApps();
  }, []);

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

  const isAdmin = user.role === 'admin';

  const appList = (list: Application[]) => (
    <ul className="app-list">
      {list.map((app) => {
        return (
          <li key={app.key}>
            <a href={app.url} target="_blank" rel="noopener noreferrer" className="app-row">
              <AppIcon key={app.iconName} app={app} />
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
        <h1 className="page-title">Manage launcher cards</h1>
        {isAdmin && (
          <button className="secondary-btn sm" onClick={() => setDraft({ ...blankDraft })}>
            <Plus size={14} /> Add application
          </button>
        )}
      </div>

      {notice && <p className="alert-box success" role="status">{notice}</p>}
      {loadError && <div className="alert-box error" role="alert">{loadError}<button className="secondary-btn sm" onClick={fetchApps}>Retry</button></div>}
      {apps?.length === 0 && <p className="app-empty">No launcher cards yet. Add an application link.</p>}
      {apps && apps.length > 0 && appList(apps)}

      {draft && (
        <Modal title={draft.id ? `Edit ${draft.name}` : 'Add external application'} onClose={() => setDraft(null)} closeOnBackdrop>
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
        </Modal>
      )}
    </div>
  );
};
