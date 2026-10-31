import { ADMIN } from './components/Sidebar';

export const SETTINGS_SECTIONS = [
  ['account', 'Account'],
  ['devices', 'Phones & apps'],
  ['appearance', 'Appearance'],
] as const;
export type SettingsSection = (typeof SETTINGS_SECTIONS)[number][0];

const TABS = new Set([
  'dashboard',
  'admin-launchers',
  ...SETTINGS_SECTIONS.map(([id]) => `settings/${id}`),
  ...ADMIN.flatMap(([, items]) => items.map(([tab]) => tab)),
]);

// Security and devices and Appearance were pages of their own before Settings held them.
const MOVED = new Map([['settings', 'settings/account'], ['devices', 'settings/account'], ['appearance', 'settings/appearance']]);

/** The view named by the URL hash (`#/admin-users`); anything unknown is Applications. */
export function tabFromHash(hash: string): string {
  const tab = hash.replace(/^#\/?/, '');
  const moved = MOVED.get(tab) ?? tab;
  return TABS.has(moved) ? moved : 'dashboard';
}

export const hashFor = (tab: string) => (tab === 'dashboard' ? '#/' : `#/${tab}`);
