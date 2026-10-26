import { readChoice, saveChoice, watchChoice } from './ky-ui/theme';
import { SYSTEM_THEME, THEME_CATALOG, applyThemeVariables, findTheme } from './ky-ui/themes';
import type { CatalogTheme, SystemTheme } from './ky-ui/themes';

// The suite catalog: Match system, Busnes Light/Dark and every named palette.
export type Theme = CatalogTheme | SystemTheme;
export const THEMES: readonly Theme[] = [SYSTEM_THEME, ...THEME_CATALOG];
export const THEME_KEY = 'kyidentity-theme';
const prefersDark = () => window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false;

export function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  const scheme = applyThemeVariables(theme.id, root);
  if (scheme) {
    delete root.dataset.theme;
    root.dataset.scheme = scheme;
    return;
  }
  const busnes = theme.id === 'system' ? (prefersDark() ? 'busnes-dark' : 'busnes-light') : theme.id;
  root.dataset.theme = busnes;
  delete root.dataset.scheme;
  root.style.colorScheme = busnes === 'busnes-dark' ? 'dark' : 'light';
}

/** The saved choice (names saved by earlier versions included), else Match system. */
export function storedTheme(): Theme {
  try {
    return findTheme(readChoice(THEME_KEY)) ?? SYSTEM_THEME;
  } catch {
    return SYSTEM_THEME;
  }
}

export function saveTheme(theme: Theme): void {
  try {
    // Names are what earlier versions saved; keep writing them.
    saveChoice(THEME_KEY, theme.id === 'system' ? 'system' : theme.name);
  } catch {
    // Storage off: the theme still applies for this page.
  }
}

if (typeof window !== 'undefined') watchChoice(THEME_KEY, () => applyTheme(storedTheme()), () => storedTheme().id !== 'system');
