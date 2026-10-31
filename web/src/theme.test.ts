import { renderToStaticMarkup } from 'react-dom/server';
import { createElement } from 'react';
import { describe, expect, it } from 'vitest';
import { findPair, findTheme } from './ky-ui/themes';
import { THEME_CHOICES, storedTheme } from './theme';
import { Appearance } from './components/Appearance';
import { Settings } from './components/Settings';
import type { User } from './types';

// Names earlier versions saved under kyidentity-theme whose palette survives, and the half they keep.
const KEPT: Record<string, string> = {
  'Busnes Light': 'busnes-light', 'Busnes Dark': 'busnes-dark', 'Dark Matter': 'dark-matter', 'Light Matter': 'light-matter',
  Ocean: 'ocean', 'White Cliffs': 'white-cliffs', Forest: 'forest', 'Patina Ky': 'patina-ky', 'Polished Ky': 'polished-ky',
  'Paper Clean': 'paper', 'Nord Slate': 'nord',
};

describe('theme', () => {
  it('offers six pairs, each as Match system, Light and Dark', () => {
    expect(THEME_CHOICES.map(c => c.pair.name)).toEqual(['Busnes', 'Matter', 'Ocean', 'Forest', 'Ky', 'Nord']);
    for (const { choices } of THEME_CHOICES) expect(choices.map(c => c.label)).toEqual(['Match system', 'Light', 'Dark']);
    expect(THEME_CHOICES[0].choices[0].value).toBe('system');
  });

  it('maps every surviving saved name to its fixed half', () => {
    for (const [name, id] of Object.entries(KEPT)) expect(findTheme(name)?.id).toBe(id);
  });

  it('resets removed palettes to Match system rather than guessing', () => {
    for (const name of ['Tropics', 'Coffee', 'Cyber Punk', 'Sun']) expect(findPair(name) ?? findTheme(name)).toBeUndefined();
  });

  it('follows the system without browser storage', () => {
    expect(storedTheme()).toBe('system');
  });

  it('renders one native radio group with a check on the selected segment and no inline styles', () => {
    const html = renderToStaticMarkup(createElement(Appearance));
    expect(html.match(/type="radio"/g)).toHaveLength(18);
    expect(html.match(/name="kyidentity-theme"/g)).toHaveLength(18);
    expect(html.match(/data-ky-preview="[a-z]+-pair"/g)).toHaveLength(6);
    expect(html).toContain('checked="" value="system"');
    expect(html.match(/lucide-check/g)).toHaveLength(1);
    expect(html).not.toContain('style=');
  });

  it('opens Settings on the Appearance tab with its description', () => {
    const user = { id: 'u', username: 'walter', role: 'user' } as User;
    const html = renderToStaticMarkup(createElement(Settings, { section: 'appearance', user, onUserUpdate: () => {} }));
    expect(html).toContain('<h1 class="ky-page-title">Settings</h1>');
    expect([...html.matchAll(/<a class="ky-nav-item" href="([^"]+)"( aria-current="page")?>([^<]+)</g)].map(m => [m[1], m[3], Boolean(m[2])])).toEqual([
      ['#/settings/account', 'Account', false], ['#/settings/devices', 'Phones &amp; apps', false], ['#/settings/appearance', 'Appearance', true],
    ]);
    expect(html).toContain('Pick a palette and how it handles light and dark. Match system switches with your device’s setting; Light or Dark keeps one. Your choice applies straight away and is saved in this browser only.');
    expect(html.match(/type="radio"/g)).toHaveLength(18);
  });
});
