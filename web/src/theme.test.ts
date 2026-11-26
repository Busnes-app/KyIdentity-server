import { renderToStaticMarkup } from 'react-dom/server';
import { createElement } from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { findPair, findTheme } from './ky-ui/themes';
import { SUITE_DEFAULT_KEY, THEME_CHOICES, THEME_KEY, setSuiteDefaultTheme, storedTheme } from './theme';
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
      ['#/settings/keyring', 'Suite keyring', false],
    ]);
    expect(html).toContain('Pick a palette and how it handles light and dark. Match system switches with your device’s setting; Light or Dark keeps one. Your choice applies straight away and is saved in this browser only.');
    expect(html.match(/type="radio"/g)).toHaveLength(18);
  });

  describe('suite default', () => {
    const store = new Map<string, string>();
    const fake = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v) };
    afterEach(() => { setSuiteDefaultTheme(null); store.clear(); delete (globalThis as { localStorage?: unknown }).localStorage; });
    const withStorage = () => { (globalThis as { localStorage?: unknown }).localStorage = fake; };

    it('a saved choice beats the suite default, which beats Match system', () => {
      withStorage();
      setSuiteDefaultTheme('ocean-pair');
      expect(storedTheme()).toBe('ocean-pair');
      store.set(THEME_KEY, 'nord');
      expect(storedTheme()).toBe('nord');
      store.set(THEME_KEY, 'system');
      expect(storedTheme()).toBe('system');
      store.set(THEME_KEY, 'Tropics');
      expect(storedTheme()).toBe('ocean-pair');
      setSuiteDefaultTheme(null);
      store.delete(THEME_KEY);
      expect(storedTheme()).toBe('system');
    });

    it('keeps only catalog IDs and caches the default for the next load', () => {
      withStorage();
      setSuiteDefaultTheme('forest');
      expect(store.get(SUITE_DEFAULT_KEY)).toBe('forest');
      setSuiteDefaultTheme('javascript:alert(1)');
      expect(storedTheme()).toBe('system');
      expect(store.get(SUITE_DEFAULT_KEY)).toBe('');
    });

    it('checks the default on the Appearance page when nothing is saved', () => {
      withStorage();
      setSuiteDefaultTheme('nord-pair');
      expect(renderToStaticMarkup(createElement(Appearance))).toContain('checked="" value="nord-pair"');
    });
  });
});
