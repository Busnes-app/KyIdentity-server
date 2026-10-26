import { renderToStaticMarkup } from 'react-dom/server';
import { createElement } from 'react';
import { describe, expect, it } from 'vitest';
import { THEME_CATALOG, findTheme } from './ky-ui/themes';
import { THEMES, storedTheme } from './theme';
import { Appearance } from './components/Appearance';

// Every name earlier versions saved under kyidentity-theme.
const SAVED = ['Busnes Light', 'Busnes Dark', 'Dark Matter', 'Light Matter', 'Tropics', 'Tropic Night', 'Ocean', 'Coffee', 'White Cliffs', 'Cyber Punk', 'Neon Purple', 'Space', 'Sky', 'Forest', 'Sun', 'Patina Ky', 'Polished Ky'];

describe('theme', () => {
  it('offers Match system first, then the suite catalog', () => {
    expect(THEMES).toHaveLength(THEME_CATALOG.length + 1);
    expect(THEMES[0].id).toBe('system');
  });

  it('still recognises every saved name and keeps it as the saved value', () => {
    for (const name of SAVED) expect(findTheme(name)?.name).toBe(name);
  });

  it('follows the system without browser storage', () => {
    expect(storedTheme().id).toBe('system');
  });

  it('renders native radio cards with shared previews and no inline styles', () => {
    const html = renderToStaticMarkup(createElement(Appearance));
    expect(html.match(/type="radio"/g)).toHaveLength(THEMES.length);
    expect(html.match(/data-ky-preview="/g)).toHaveLength(THEMES.length);
    expect(html).toContain('checked="" value="system"');
    expect(html).toContain('remembered by this browser only');
    expect(html).not.toContain('style=');
  });
});
