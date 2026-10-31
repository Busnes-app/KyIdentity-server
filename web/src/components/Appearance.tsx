import { useEffect, useState } from 'react';
import { Check } from 'lucide-react';
import { findTheme } from '../ky-ui/themes';
import { THEME_CHOICES, applyTheme, storedTheme } from '../theme';
import { PageHead } from './PageHead';

// One native radio group across the pairs: arrow keys move through every choice.
export function Appearance() {
  const [theme, setTheme] = useState(storedTheme);
  useEffect(() => {
    const sync = () => setTheme(storedTheme());
    window.addEventListener('ky:theme', sync);
    return () => window.removeEventListener('ky:theme', sync);
  }, []);
  return (
    <div className="appearance-page">
      <PageHead title="Appearance"
        lede="Pick a palette and how it handles light and dark. Match system switches with your device’s setting; Light or Dark keeps one. Your choice applies straight away and is saved in this browser only." />
      <fieldset className="ky-appearance">
        <legend className="ky-appearance-legend">Theme</legend>
        <div className="ky-appearance-grid appearance-pairs">
          {THEME_CHOICES.map(({ pair, choices }) => (
            <div key={pair.id} role="group" aria-labelledby={`${pair.id}-name`} className="appearance-pair">
              <div className="appearance-pair-head">
                <h2 id={`${pair.id}-name`} className="appearance-pair-name">{pair.name}</h2>
                <span className="appearance-pair-halves">{findTheme(pair.light)?.name} · {findTheme(pair.dark)?.name}</span>
              </div>
              <span className="ky-appearance-preview" data-ky-preview={pair.id} aria-hidden="true" />
              <div className="appearance-modes">
                {choices.map(({ mode, label, value }) => (
                  <label key={mode} className="appearance-mode">
                    <input type="radio" name="kyidentity-theme" value={value} checked={theme === value}
                      onChange={() => { setTheme(value); applyTheme(value, true); }} />
                    {theme === value && <Check size={14} strokeWidth={2.5} aria-hidden="true" />}
                    <span>{label}</span>
                  </label>
                ))}
              </div>
            </div>
          ))}
        </div>
      </fieldset>
    </div>
  );
}
