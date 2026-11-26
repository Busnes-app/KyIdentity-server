import React, { useEffect, useState } from 'react';
import { ApiError, apiJson, errorMessage, isRecord, setStaffOrg } from '../api';

/** One org in the staff finder (GET /api/admin/orgs). */
export interface StaffOrg {
  id: string;
  name: string;
  kind: string;
  status: string;
  billingRef: string;
  seatsUsed: number;
  maxSeats: number;
}

export function parseStaffOrgs(value: unknown): StaffOrg[] {
  if (!isRecord(value) || !Array.isArray(value.orgs)) throw new Error('Org list is malformed');
  return value.orgs.map(o => {
    if (!isRecord(o) || typeof o.id !== 'string' || typeof o.name !== 'string' || typeof o.kind !== 'string' || typeof o.status !== 'string' ||
      typeof o.billingRef !== 'string' || typeof o.seatsUsed !== 'number' || typeof o.maxSeats !== 'number') {
      throw new Error('Org list is malformed');
    }
    return { id: o.id, name: o.name, kind: o.kind, status: o.status, billingRef: o.billingRef, seatsUsed: o.seatsUsed, maxSeats: o.maxSeats };
  });
}

/**
 * The first selection: the first org the finder answers (the staff org). A single-tenant
 * install answers 404, and any other failure is shown, but both leave no selection to
 * make (org ''), so the admin pages still render and answer for themselves.
 */
export async function initialOrg(load: () => Promise<StaffOrg[]>): Promise<{ org: StaffOrg | null; error: string | null }> {
  try {
    const orgs = await load();
    return orgs[0] ? { org: orgs[0], error: null } : { org: null, error: 'No staff organisation found.' };
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return { org: null, error: null };
    return { org: null, error: errorMessage(err, 'Could not load organisations') };
  }
}

const label = (o: StaffOrg) => `${o.name}${o.kind === 'staff' ? ' (staff)' : ''}${o.status === 'active' ? '' : `, ${o.status}`}`;

/**
 * The staff org selector (multi-tenant). It starts in the staff org, and staff find another
 * by its ID, billing reference or a member's exact email. A single-tenant install answers
 * 404 and the picker shows nothing. onReady gets the selected org's ID ('' when there is no
 * selection to make, see initialOrg), and fires again on every change.
 */
export function OrgPicker({ onReady }: { onReady: (org: string) => void }) {
  const [current, setCurrent] = useState<StaffOrg | null>(null);
  const [query, setQuery] = useState('');
  const [found, setFound] = useState<StaffOrg[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const select = (o: StaffOrg) => {
    setStaffOrg(o.id);
    setCurrent(o);
    setFound(null);
    setQuery('');
    onReady(o.id);
  };

  useEffect(() => {
    void initialOrg(() => apiJson('/api/admin/orgs', parseStaffOrgs)).then(({ org, error }) => {
      if (org) {
        select(org);
        return;
      }
      setError(error);
      onReady('');
    });
    return () => setStaffOrg('');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const search = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setFound(await apiJson(`/api/admin/orgs?q=${encodeURIComponent(query.trim())}`, parseStaffOrgs));
    } catch (err) {
      setError(errorMessage(err, 'Could not search organisations'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <OrgPickerView current={current} found={found} error={error} busy={busy} query={query}
      onQuery={setQuery} onSearch={search} onSelect={select} />
  );
}

interface OrgPickerViewProps {
  current: StaffOrg | null;
  found: StaffOrg[] | null;
  error: string | null;
  busy: boolean;
  query: string;
  onQuery: (value: string) => void;
  onSearch: (event: React.FormEvent) => void;
  onSelect: (org: StaffOrg) => void;
}

export function OrgPickerView({ current, found, error, busy, query, onQuery, onSearch, onSelect }: OrgPickerViewProps) {
  if (!current && !error && !busy && found === null) return null;

  return (
    <section className="settings-card" aria-label="Organisation">
      {current && <p role="status">Working in <strong>{label(current)}</strong> <code>{current.id}</code></p>}
      {error && <div className="alert-box error" role="alert">{error}</div>}
      <form onSubmit={onSearch} className="form-row">
        <label htmlFor="org-search">Find an organisation</label>
        <input id="org-search" className="form-input" value={query} disabled={busy} autoCapitalize="none" spellCheck={false}
          placeholder="Org ID, billing reference or a member's exact email" onChange={e => onQuery(e.target.value)} />
        <button type="submit" className="secondary-btn" disabled={busy}>Find</button>
      </form>
      {found && (found.length === 0 ? <p>No organisation matches.</p> : (
        <ul>
          {found.map(o => (
            <li key={o.id}>
              {label(o)} · {o.seatsUsed}{o.maxSeats ? ` of ${o.maxSeats}` : ''} seats{o.billingRef && ` · ${o.billingRef}`}{' '}
              <button type="button" className="secondary-btn" disabled={o.id === current?.id} onClick={() => onSelect(o)}>Work in this org</button>
            </li>
          ))}
        </ul>
      ))}
    </section>
  );
}
