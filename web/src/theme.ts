import { readChoice, saveChoice, watchChoice } from './ky-ui/theme';
import { SYSTEM_THEME, THEME_PAIRS, applyThemeVariables, findPair, findTheme } from './ky-ui/themes';

// Busnes.app defaults; explicit choices are local to this browser. The saved value is `system`
// (Busnes following the OS), a pair ID (that pair following the OS) or a half ID (a fixed mode).
// Names saved by earlier versions resolve through the catalog; removed palettes fall back to `system`.
export const THEME_KEY = 'kyidentity-theme';
export const THEME_CHOICES = THEME_PAIRS.map(pair => ({
  pair,
  choices: [
    { mode: 'system', label: 'Match system', value: pair.id === 'busnes-pair' ? SYSTEM_THEME.id : pair.id },
    { mode: 'light', label: 'Light', value: pair.light },
    { mode: 'dark', label: 'Dark', value: pair.dark },
  ],
}));

export function storedTheme(): string {
  try {
    const saved = readChoice(THEME_KEY);
    return findPair(saved)?.id ?? findTheme(saved)?.id ?? SYSTEM_THEME.id;
  } catch {
    return SYSTEM_THEME.id;
  }
}

const media = typeof window !== 'undefined' ? window.matchMedia?.('(prefers-color-scheme: dark)') : undefined;

export function applyTheme(theme: string, persist = false): void {
  const option = findTheme(theme);
  if (!option) return;
  const root = document.documentElement;
  const resolved = option.id === 'system' ? (media?.matches ? 'busnes-dark' : 'busnes-light') : option.id;
  const scheme = applyThemeVariables(resolved) ?? (resolved === 'busnes-light' ? 'light' : 'dark');
  root.dataset.theme = resolved;
  root.dataset.scheme = scheme;
  root.style.colorScheme = scheme;
  if (persist) {
    try {
      saveChoice(THEME_KEY, findPair(theme)?.id ?? option.id);
    } catch {
      // Storage off: the theme still applies for this page.
    }
  }
  window.dispatchEvent(new Event('ky:theme'));
}

if (typeof window !== 'undefined') watchChoice(THEME_KEY, () => applyTheme(storedTheme()));
