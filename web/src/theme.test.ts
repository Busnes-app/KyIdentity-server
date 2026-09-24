import { describe, expect, it } from 'vitest';
import { THEMES, THEME_NAMES, isLight, isThemeName, themeVars } from './theme';

describe('theme', () => {
  it('ships Busnes defaults alongside the existing suite palettes', () => {
    expect(THEME_NAMES).toHaveLength(17);
    expect(isThemeName('Patina Ky')).toBe(true);
  });

  it('rejects stored values that are not palette names, including prototype keys', () => {
    for (const bad of ['constructor', '__proto__', 'toString', '', null, undefined, 42]) {
      expect(isThemeName(bad)).toBe(false);
    }
  });

  it('classifies backgrounds by luminance', () => {
    expect(isLight(THEMES['Patina Ky'].bg)).toBe(false);
    expect(isLight(THEMES['Polished Ky'].bg)).toBe(true);
    expect(isLight('#ffffff')).toBe(true);
  });

  it('maps camelCase tokens onto kebab-case custom properties', () => {
    const vars = themeVars('Patina Ky');
    expect(vars['--ink-strong']).toBe('#e2e8f0');
    expect(vars['--sidebar-end']).toBe('#1b212c');
    expect(vars['--button-text']).toBe('#04120d');
    expect(Object.keys(vars)).toHaveLength(11);
  });
});
