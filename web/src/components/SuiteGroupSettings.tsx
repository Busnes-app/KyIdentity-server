import { useEffect, useState } from 'react';
import { apiRequest, errorMessage } from '../api';
import { parseSuiteGroupSettings } from '../parsers';
import type { DirectoryGroup, SuiteGroupSettings } from '../types';

type Mutate = (reason: string, method: 'PUT', path: string, body: object) => Promise<boolean>;

export const suiteGroupAppLabels: Record<string, string> = {
  kydrive: 'KyDrive workspace',
  kycalendar: 'KyCalendar group calendar',
  kymessage: 'KyMessages room',
  kypost: 'KyPost distribution list',
};

/** The form: one switch for the group, one per app while it is on. */
export function SuiteGroupForm({ settings, busy, onSave }: {
  settings: SuiteGroupSettings; busy: boolean; onSave: (next: SuiteGroupSettings) => void;
}) {
  const [draft, setDraft] = useState(settings);
  useEffect(() => setDraft(settings), [settings]);
  const changed = JSON.stringify(draft) !== JSON.stringify(settings);
  return <>
    <div className="form-group"><span className="form-label">Shared resources</span>
      <label><input type="checkbox" checked={draft.enabled} disabled={busy}
        onChange={e => setDraft({ ...draft, enabled: e.target.checked })} /> Create shared resources for this group</label>
      <p className="text-muted text-sm">Each app below gives the group one shared space. Members also need access to that app; administrator accounts are never added. Turning this off or deleting the group archives the spaces: nothing is deleted.{draft.slug ? ` Address name: ${draft.slug}.` : ''}</p></div>
    {draft.enabled && <div className="form-group" role="group" aria-labelledby="suite-group-apps"><span id="suite-group-apps" className="form-label">Apps</span>
      {draft.apps.map(app => <div key={app.id}><label><input type="checkbox" checked={app.enabled} disabled={busy}
        onChange={e => setDraft({ ...draft, apps: draft.apps.map(a => a.id === app.id ? { ...a, enabled: e.target.checked } : a) })} /> {suiteGroupAppLabels[app.id] ?? app.id}</label></div>)}
    </div>}
    <div className="form-group"><button type="button" className="secondary-btn sm" disabled={busy || !changed} onClick={() => onSave(draft)}>Save shared resources</button></div>
  </>;
}

export function GroupSharedResources({ group, busy, mutate }: { group: DirectoryGroup; busy: boolean; mutate: Mutate }) {
  const path = `/api/admin/groups/${group.id}/suite`;
  const [settings, setSettings] = useState<SuiteGroupSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = () => apiRequest(path).then(v => setSettings(parseSuiteGroupSettings(v)), err => setError(errorMessage(err, 'Could not load shared resources')));
  useEffect(() => { void load(); }, [path]);
  if (error) return <div className="alert-box error" role="alert">{error}</div>;
  if (!settings) return null;
  return <SuiteGroupForm settings={settings} busy={busy} onSave={async next => {
    const apps = Object.fromEntries(next.apps.filter(a => settings.apps.find(b => b.id === a.id)?.enabled !== a.enabled).map(a => [a.id, a.enabled]));
    if (await mutate(`${next.enabled ? 'Turn on' : 'Turn off'} shared resources for '${group.name}'.`, 'PUT', path, { enabled: next.enabled, apps })) void load();
  }} />;
}
