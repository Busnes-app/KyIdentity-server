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

// The suite default theme (Administration › Suite settings, public `GET /api/appearance`)
// applies until this browser saves a choice; a saved choice, Match system included, wins.
// The last default seen is kept under its own key so the next load paints it at once.
// ponytail: this mirrors ky-ui 0.12.0 `setServerDefaultTheme`/`chooseTheme`; switch to them
// at the next ky-ui sync.
export const SUITE_DEFAULT_KEY = 'kyidentity-theme-default';
const known = (value: string | null | undefined): string | null =>
  findPair(value)?.id ?? findTheme(value)?.id ?? null;

function readKnown(key: string): string | null {
  try {
    return known(readChoice(key));
  } catch {
    return null;
  }
}

let suiteDefault = readKnown(SUITE_DEFAULT_KEY);

/** The choice saved in this browser, or null when none is. */
export const savedTheme = (): string | null => readKnown(THEME_KEY);

/** The choice to apply: the saved one, else the suite default, else Match system. */
export function storedTheme(): string {
  return savedTheme() ?? suiteDefault ?? SYSTEM_THEME.id;
}

/** Records the suite default (unknown values clear it) and re-applies when nothing is saved. */
export function setSuiteDefaultTheme(value: unknown): void {
  const id = typeof value === 'string' ? known(value) : null;
  if (id === suiteDefault) return;
  suiteDefault = id;
  try {
    saveChoice(SUITE_DEFAULT_KEY, id ?? '');
  } catch {
    // Storage off: the default still applies for this page.
  }
  if (typeof document !== 'undefined') applyTheme(storedTheme());
}

/** Reads the suite default from the server; on any failure the cached one stays. */
export function loadSuiteDefaultTheme(): Promise<void> {
  return fetch('/api/appearance')
    .then(res => (res.ok ? res.json() : Promise.reject(new Error(String(res.status)))))
    .then((body: unknown) => {
      const theme = typeof body === 'object' && body !== null ? (body as { defaultTheme?: unknown }).defaultTheme : undefined;
      if (typeof theme === 'string') setSuiteDefaultTheme(theme);
    })
    .catch(() => undefined);
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
