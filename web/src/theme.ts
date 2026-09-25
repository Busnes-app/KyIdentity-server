import { readChoice, saveChoice, watchChoice } from './ky-ui/theme';
import { busnesPalettes } from './ky-ui/palettes';
// The suite palettes, byte for byte from kypost-server frontend/src/theme.ts (the eleven
// tokens the web apps share; the mail-only ones are dropped, as KyNotes and KyDNS do).
export const THEMES = {
  "Busnes Light": busnesPalettes["Busnes Light"],
  "Busnes Dark": busnesPalettes["Busnes Dark"],
  'Dark Matter': { bg: '#1a1a1e', panel: '#252530', ink: '#d4c5e2', inkStrong: '#e8ddf5', accent: '#c29a72', accentSoft: '#5a3f31', line: '#404050', glow: 'rgba(107, 74, 66, 0.25)', sidebarStart: '#1f1f24', sidebarEnd: '#2a2530', buttonText: '#24170f' },
  'Light Matter': { bg: '#f5efe5', panel: '#fff8ee', ink: '#4c3d32', inkStrong: '#2d1f15', accent: '#c29a72', accentSoft: '#e6d2be', line: '#c5b29d', glow: 'rgba(175, 126, 92, 0.2)', sidebarStart: '#ede2d2', sidebarEnd: '#e4d6c3', buttonText: '#24170f' },
  'Tropics': { bg: '#f4f1eb', panel: '#fffaf0', ink: '#43362d', inkStrong: '#241a14', accent: '#9bc400', accentSoft: '#d4e3a0', line: '#c4b7a3', glow: 'rgba(123, 165, 31, 0.2)', sidebarStart: '#ece5d8', sidebarEnd: '#e3dacb', buttonText: '#243100' },
  'Tropic Night': { bg: '#15131a', panel: '#221f2b', ink: '#cdbde0', inkStrong: '#e8ddf5', accent: '#9bc400', accentSoft: '#6b4a42', line: '#3c3650', glow: 'rgba(107, 74, 66, 0.28)', sidebarStart: '#1d1a24', sidebarEnd: '#292233', buttonText: '#1a2400' },
  'Ocean': { bg: '#0f1b24', panel: '#152a36', ink: '#b8d8e8', inkStrong: '#e0f2fb', accent: '#5ea9be', accentSoft: '#214657', line: '#2f5567', glow: 'rgba(58, 130, 155, 0.24)', sidebarStart: '#112430', sidebarEnd: '#173342', buttonText: '#0a1b22' },
  'Coffee': { bg: '#1d1714', panel: '#2a211d', ink: '#d6c0b3', inkStrong: '#f0ded2', accent: '#b47f5c', accentSoft: '#5f3f2f', line: '#4a3830', glow: 'rgba(132, 86, 61, 0.24)', sidebarStart: '#231a16', sidebarEnd: '#32251f', buttonText: '#220f08' },
  'White Cliffs': { bg: '#f7f9fb', panel: '#ffffff', ink: '#2e4c63', inkStrong: '#163246', accent: '#5ea8d8', accentSoft: '#dff1fb', line: '#8fc3df', glow: 'rgba(94, 168, 216, 0.2)', sidebarStart: '#f1f8fd', sidebarEnd: '#e7f3fb', buttonText: '#103246' },
  'Cyber Punk': { bg: '#120918', panel: '#1e1028', ink: '#f5d0ff', inkStrong: '#ffe9ff', accent: '#00f5d4', accentSoft: '#3b1760', line: '#5c2d84', glow: 'rgba(255, 0, 153, 0.2)', sidebarStart: '#1b0d24', sidebarEnd: '#281236', buttonText: '#051d1a' },
  'Neon Purple': { bg: '#130b1d', panel: '#231233', ink: '#e4ccff', inkStrong: '#f2e6ff', accent: '#c86cff', accentSoft: '#47206c', line: '#63358a', glow: 'rgba(200, 108, 255, 0.2)', sidebarStart: '#1b1029', sidebarEnd: '#2a1740', buttonText: '#210a35' },
  'Space': { bg: '#0b0f1a', panel: '#151c2d', ink: '#c8d5f0', inkStrong: '#e7efff', accent: '#86a8ff', accentSoft: '#263e74', line: '#34496f', glow: 'rgba(92, 126, 220, 0.18)', sidebarStart: '#0f1625', sidebarEnd: '#18233a', buttonText: '#101930' },
  'Sky': { bg: '#dff1ff', panel: '#f4fbff', ink: '#2f4f64', inkStrong: '#183142', accent: '#6db3d6', accentSoft: '#b6dced', line: '#93bdd2', glow: 'rgba(109, 179, 214, 0.28)', sidebarStart: '#d3ecfa', sidebarEnd: '#c2e2f4', buttonText: '#0f2e3f' },
  'Forest': { bg: '#142018', panel: '#1f2f24', ink: '#c7dbc7', inkStrong: '#e3f0df', accent: '#8faa74', accentSoft: '#3a5837', line: '#4f694f', glow: 'rgba(118, 148, 95, 0.24)', sidebarStart: '#18261c', sidebarEnd: '#223629', buttonText: '#12200f' },
  'Sun': { bg: '#fff3dc', panel: '#fff9ec', ink: '#5a4024', inkStrong: '#392611', accent: '#e0ab4f', accentSoft: '#f1d9a2', line: '#d4b27a', glow: 'rgba(224, 171, 79, 0.28)', sidebarStart: '#f8e7c5', sidebarEnd: '#f2dab1', buttonText: '#2a1808' },
  'Patina Ky': { bg: '#0d0f14', panel: '#161a22', ink: '#94a3b8', inkStrong: '#e2e8f0', accent: '#4deeea', accentSoft: '#0e4a48', line: '#1e293b', glow: 'rgba(77, 238, 234, 0.22)', sidebarStart: '#0d0f14', sidebarEnd: '#1b212c', buttonText: '#04120d' },
  'Polished Ky': { bg: '#eef2f6', panel: '#ffffff', ink: '#475569', inkStrong: '#0f172a', accent: '#0891b2', accentSoft: '#cffafe', line: '#cbd5e1', glow: 'rgba(8, 145, 178, 0.18)', sidebarStart: '#f1f5f9', sidebarEnd: '#e2e8f0', buttonText: '#042f2e' },
} as const;

export type ThemeName = keyof typeof THEMES;
export const THEME_NAMES = Object.keys(THEMES) as ThemeName[];
export const DEFAULT_THEME: ThemeName = 'Busnes Light';
function defaultTheme(): ThemeName { return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'Busnes Dark' : DEFAULT_THEME; }
export const THEME_KEY = 'kyidentity-theme';

export function isThemeName(value: unknown): value is ThemeName {
  return typeof value === 'string' && Object.prototype.hasOwnProperty.call(THEMES, value);
}

// Same rule as the desktop clients: a background above 0.55 luminance is a light theme,
// and native controls and scrollbars should follow it.
export function isLight(hex: string): boolean {
  const n = parseInt(hex.slice(1), 16);
  const r = (n >> 16) / 255;
  const g = ((n >> 8) & 255) / 255;
  const b = (n & 255) / 255;
  return 0.299 * r + 0.587 * g + 0.114 * b > 0.55;
}

/** The custom properties a theme sets on the root element. */
export function themeVars(name: ThemeName): Record<string, string> {
  const vars: Record<string, string> = {};
  for (const [key, value] of Object.entries(THEMES[name])) {
    vars['--' + key.replace(/[A-Z]/g, (m) => '-' + m.toLowerCase())] = value;
  }
  return vars;
}

export function applyTheme(name: ThemeName): void {
  const root = document.documentElement;
  const sharedName = name === 'Busnes Light' ? 'busnes-light' : name === 'Busnes Dark' ? 'busnes-dark' : undefined;
  for (const key of Object.keys(themeVars('Busnes Light'))) root.style.removeProperty(key);
  if (sharedName) {
    root.dataset.theme = sharedName;
    delete root.dataset.scheme;
    root.style.colorScheme = sharedName === 'busnes-dark' ? 'dark' : 'light';
    return;
  }
  delete root.dataset.theme;
  for (const [key, value] of Object.entries(themeVars(name))) {
    root.style.setProperty(key, value);
  }
  const scheme = isLight(THEMES[name].bg) ? 'light' : 'dark';
  root.style.colorScheme = scheme;
  root.dataset.scheme = scheme;
}

export function storedTheme(): ThemeName {
  try {
    const value = readChoice(THEME_KEY);
    return isThemeName(value) ? value : defaultTheme();
  } catch {
    return defaultTheme();
  }
}

export function saveTheme(name: ThemeName): void {
  try {
    saveChoice(THEME_KEY, name);
  } catch {
    // Storage off: the theme still applies for this page.
  }
}

if (typeof window !== 'undefined') watchChoice(THEME_KEY, () => applyTheme(storedTheme()), () => isThemeName(readChoice(THEME_KEY)));
