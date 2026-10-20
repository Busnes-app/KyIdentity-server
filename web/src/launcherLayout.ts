import type { Application, LauncherPrefs } from './types';

/** Server limits, mirrored so the editor cannot build something the server rejects. */
export const MAX_GROUPS = 20;
export const MAX_GROUP_NAME = 40;

export interface ArrangedGroup {
  name: string;
  apps: Application[];
}

export interface Arranged {
  layout: LauncherPrefs['layout'];
  groups: ArrangedGroup[];
  hidden: Application[];
}

/** Today's grouping, used until a user customises: OAuth clients, then other links. */
export function defaultPrefs(apps: Application[]): LauncherPrefs {
  const groups = [
    { name: 'Suite', apps: apps.filter((a) => a.source === 'client').map((a) => a.key) },
    { name: 'Other links', apps: apps.filter((a) => a.source !== 'client').map((a) => a.key) },
  ];
  return { layout: 'tiles', groups: groups.filter((g) => g.apps.length), hidden: [] };
}

/**
 * The prefs the editor starts from: saved (or default) prefs, plus a trailing "New" group
 * for apps granted since the last save. Keys for apps the user can no longer reach are
 * kept, so a revoked-then-restored app returns to its place.
 */
export function normalize(apps: Application[], prefs: LauncherPrefs | null): LauncherPrefs {
  const p = prefs ?? defaultPrefs(apps);
  const placed = new Set([...p.groups.flatMap((g) => g.apps), ...p.hidden]);
  const fresh = apps.filter((a) => !placed.has(a.key)).map((a) => a.key);
  return {
    layout: p.layout,
    groups: fresh.length ? [...p.groups, { name: 'New', apps: fresh }] : p.groups,
    hidden: p.hidden,
  };
}

/** What the launcher draws: only reachable apps, and no empty groups. */
export function arrange(apps: Application[], prefs: LauncherPrefs | null): Arranged {
  const byKey = new Map(apps.map((a) => [a.key, a]));
  const resolve = (keys: string[]) => keys.flatMap((k) => byKey.get(k) ?? []);
  const p = normalize(apps, prefs);
  return {
    layout: p.layout,
    groups: p.groups.map((g) => ({ name: g.name, apps: resolve(g.apps) })).filter((g) => g.apps.length),
    hidden: resolve(p.hidden),
  };
}

/** Search is a view only: never feed its result back into saved preferences. */
export function searchLauncher(arranged: Arranged, query: string): Arranged {
  const text = query.trim().toLocaleLowerCase();
  if (!text) return arranged;
  const matches = (app: Application) => `${app.name} ${app.description ?? ''}`.toLocaleLowerCase().includes(text);
  return {
    ...arranged,
    groups: arranged.groups.map((group) => ({ ...group, apps: group.apps.filter(matches) })).filter((group) => group.apps.length > 0),
    hidden: arranged.hidden.filter(matches),
  };
}

/** A group index, or 'hidden'. */
export type Slot = number | 'hidden';

const slotKeys = (p: LauncherPrefs, s: Slot) => (s === 'hidden' ? p.hidden : p.groups[s]?.apps ?? []);

function without(p: LauncherPrefs, key: string): LauncherPrefs {
  return {
    ...p,
    groups: p.groups.map((g) => ({ ...g, apps: g.apps.filter((k) => k !== key) })),
    hidden: p.hidden.filter((k) => k !== key),
  };
}

function withSlot(p: LauncherPrefs, s: Slot, keys: string[]): LauncherPrefs {
  if (s === 'hidden') return { ...p, hidden: keys };
  return { ...p, groups: p.groups.map((g, i) => (i === s ? { ...g, apps: keys } : g)) };
}

/** Moves key into slot, before `before` when given, else to the end. */
export function moveApp(p: LauncherPrefs, key: string, to: Slot, before?: string): LauncherPrefs {
  const rest = without(p, key);
  const keys = [...slotKeys(rest, to)];
  const i = before ? keys.indexOf(before) : -1;
  keys.splice(i < 0 ? keys.length : i, 0, key);
  return withSlot(rest, to, keys);
}

/** Swaps key with its nearest visible neighbour; keys of unreachable apps are skipped. */
export function shiftApp(p: LauncherPrefs, key: string, dir: -1 | 1, visible: Set<string>): LauncherPrefs {
  const slot: Slot = p.hidden.includes(key) ? 'hidden' : p.groups.findIndex((g) => g.apps.includes(key));
  const keys = [...slotKeys(p, slot)];
  const i = keys.indexOf(key);
  let j = i + dir;
  while (j >= 0 && j < keys.length && !visible.has(keys[j])) j += dir;
  if (i < 0 || j < 0 || j >= keys.length) return p;
  [keys[i], keys[j]] = [keys[j], keys[i]];
  return withSlot(p, slot, keys);
}

export function addGroup(p: LauncherPrefs): LauncherPrefs {
  if (p.groups.length >= MAX_GROUPS) return p;
  return { ...p, groups: [...p.groups, { name: 'New group', apps: [] }] };
}

export function renameGroup(p: LauncherPrefs, index: number, name: string): LauncherPrefs {
  return { ...p, groups: p.groups.map((g, i) => (i === index ? { ...g, name: name.slice(0, MAX_GROUP_NAME) } : g)) };
}

/** Deleting a group never loses an app: its apps move to Hidden. */
export function deleteGroup(p: LauncherPrefs, index: number): LauncherPrefs {
  const gone = p.groups[index];
  if (!gone) return p;
  return { ...p, groups: p.groups.filter((_, i) => i !== index), hidden: [...p.hidden, ...gone.apps] };
}

/** Unhiding from the launcher puts the app at the end of the first group. */
export function unhide(p: LauncherPrefs, key: string): LauncherPrefs {
  const base = p.groups.length ? p : { ...p, groups: [{ name: 'Apps', apps: [] }] };
  return moveApp(base, key, 0);
}

/** Blank names become "Untitled" rather than a server rejection. */
export function forSave(p: LauncherPrefs): LauncherPrefs {
  return { ...p, groups: p.groups.map((g) => ({ ...g, name: g.name.trim() || 'Untitled' })) };
}
