import { describe, expect, it } from 'vitest';
import type { Application, LauncherPrefs } from './types';
import {
  MAX_GROUPS,
  addGroup,
  arrange,
  defaultPrefs,
  deleteGroup,
  forSave,
  moveApp,
  normalize,
  renameGroup,
  shiftApp,
  searchLauncher,
  unhide,
} from './launcherLayout';

const app = (source: 'client' | 'custom', id: string): Application => ({
  id,
  key: `${source}:${id}`,
  source,
  name: id,
  url: `https://${id}.test`,
  iconName: 'favicon',
  enabled: true,
});

const post = app('client', 'kypost');
const dns = app('client', 'kydns');
const wiki = app('custom', 'wiki');
const apps = [post, dns, wiki];
const names = (a: Application[]) => a.map((x) => x.id);

const prefs = (over: Partial<LauncherPrefs> = {}): LauncherPrefs => ({
  layout: 'tiles',
  groups: [{ name: 'Daily', apps: ['client:kypost', 'client:kydns'] }],
  hidden: ['custom:wiki'],
  ...over,
});

describe('arrange', () => {
  it('falls back to Suite and Other links until the user customises', () => {
    const a = arrange(apps, null);
    expect(a.layout).toBe('tiles');
    expect(a.groups.map((g) => [g.name, names(g.apps)])).toEqual([
      ['Suite', ['kypost', 'kydns']],
      ['Other links', ['wiki']],
    ]);
    expect(a.hidden).toEqual([]);
  });

  it('follows saved groups, order and hidden apps', () => {
    const a = arrange(apps, prefs({ groups: [{ name: 'Daily', apps: ['client:kydns', 'client:kypost'] }] }));
    expect(a.groups.map((g) => names(g.apps))).toEqual([['kydns', 'kypost']]);
    expect(names(a.hidden)).toEqual(['wiki']);
  });

  it('never shows an app the user cannot reach, whatever the prefs name', () => {
    const a = arrange([post], prefs({ hidden: ['client:gone'] }));
    expect(a.groups.flatMap((g) => names(g.apps))).toEqual(['kypost']);
    expect(a.hidden).toEqual([]);
  });

  it('puts newly granted apps in a trailing New group', () => {
    const a = arrange(apps, prefs({ hidden: [] }));
    expect(a.groups.map((g) => [g.name, names(g.apps)])).toEqual([
      ['Daily', ['kypost', 'kydns']],
      ['New', ['wiki']],
    ]);
  });

  it('drops groups with nothing reachable, so the dock is the first group with apps', () => {
    const a = arrange(apps, prefs({ layout: 'dock', groups: [{ name: 'Empty', apps: ['client:gone'] }, ...prefs().groups] }));
    expect(a.groups[0].name).toBe('Daily');
  });
});

describe('normalize', () => {
  it('keeps keys of unreachable apps so a restored app returns to its place', () => {
    const p = normalize([post], prefs({ groups: [{ name: 'Daily', apps: ['client:gone', 'client:kypost'] }] }));
    expect(p.groups[0].apps).toEqual(['client:gone', 'client:kypost']);
  });

  it('defaults skip empty groups', () => {
    expect(defaultPrefs([post]).groups.map((g) => g.name)).toEqual(['Suite']);
  });
});

describe('edits', () => {
  it('moves an app between slots, before a given app or to the end', () => {
    const p = moveApp(prefs(), 'custom:wiki', 0, 'client:kydns');
    expect(p.groups[0].apps).toEqual(['client:kypost', 'custom:wiki', 'client:kydns']);
    expect(p.hidden).toEqual([]);
    expect(moveApp(p, 'client:kypost', 'hidden').hidden).toEqual(['client:kypost']);
  });

  it('shifts past unreachable keys and stops at the ends', () => {
    const p = prefs({ groups: [{ name: 'g', apps: ['client:kypost', 'client:gone', 'client:kydns'] }] });
    const visible = new Set(apps.map((a) => a.key));
    expect(shiftApp(p, 'client:kydns', -1, visible).groups[0].apps).toEqual(['client:kydns', 'client:gone', 'client:kypost']);
    expect(shiftApp(p, 'client:kypost', -1, visible)).toBe(p);
  });

  it('deleting a group hides its apps instead of losing them', () => {
    const p = deleteGroup(prefs(), 0);
    expect(p.groups).toEqual([]);
    expect(p.hidden).toEqual(['custom:wiki', 'client:kypost', 'client:kydns']);
  });

  it('unhides to the end of the first group, creating one if needed', () => {
    expect(unhide(prefs(), 'custom:wiki').groups[0].apps).toEqual(['client:kypost', 'client:kydns', 'custom:wiki']);
    const solo = unhide(prefs({ groups: [] }), 'custom:wiki');
    expect(solo.groups).toEqual([{ name: 'Apps', apps: ['custom:wiki'] }]);
  });

  it('respects the server limits on groups and names', () => {
    let p = prefs({ groups: [] });
    for (let i = 0; i < MAX_GROUPS + 3; i++) p = addGroup(p);
    expect(p.groups).toHaveLength(MAX_GROUPS);
    expect(renameGroup(p, 0, 'x'.repeat(60)).groups[0].name).toHaveLength(40);
  });

  it('saves blank names as Untitled rather than failing', () => {
    expect(forSave(prefs({ groups: [{ name: '   ', apps: [] }] })).groups[0].name).toBe('Untitled');
  });
});


describe('searchLauncher', () => {
  it('searches visible and hidden apps without changing saved groups or order', () => {
    const saved = prefs({ layout: 'dock' });
    const before = structuredClone(saved);
    const arranged = arrange([post, { ...dns, description: 'Domain management' }, wiki], saved);
    expect(searchLauncher(arranged, ' DOMAIN ').groups[0].apps).toEqual([{ ...dns, description: 'Domain management' }]);
    expect(searchLauncher(arranged, 'WIKI').hidden).toEqual([wiki]);
    expect(searchLauncher(arranged, 'missing').groups).toEqual([]);
    expect(searchLauncher(arranged, '  ')).toBe(arranged);
    expect(saved).toEqual(before);
    expect(arranged.groups[0].apps.map((a) => a.key)).toEqual(['client:kypost', 'client:kydns']);
  });
});
