import { useEffect, useState } from 'react';
import { THEME_CHOICES, applyTheme, storedTheme } from '../theme';

/** The sign-in screen's compact picker; Appearance offers the same choices as cards. */
export function ThemeSwitcher() {
  const [theme, setTheme] = useState(storedTheme);
  useEffect(() => {
    const sync = () => setTheme(storedTheme());
    window.addEventListener('ky:theme', sync);
    return () => window.removeEventListener('ky:theme', sync);
  }, []);
  return <select aria-label="Color theme" value={theme} onChange={event => {
    setTheme(event.target.value);
    applyTheme(event.target.value, true);
  }}>{THEME_CHOICES.map(({ pair, choices }) => (
    <optgroup key={pair.id} label={pair.name}>
      {choices.map(({ mode, label, value }) => <option key={mode} value={value}>{pair.name} · {label}</option>)}
    </optgroup>
  ))}</select>;
}
