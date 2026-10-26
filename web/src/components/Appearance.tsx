import React, { useState } from 'react';
import { THEMES, Theme, applyTheme, saveTheme, storedTheme } from '../theme';

const mode = (scheme: string) => scheme === 'system' ? 'Light or dark' : scheme === 'light' ? 'Light' : 'Dark';

export const Appearance: React.FC = () => {
  const [current, setCurrent] = useState<Theme>(storedTheme);

  const choose = (theme: Theme) => {
    applyTheme(theme);
    saveTheme(theme);
    setCurrent(theme);
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Appearance</h1>
      </div>
      <p className="ky-appearance-description">Pick a theme. It applies straight away and is saved in this browser only. Match system follows your device’s light or dark setting.</p>
      <fieldset className="ky-appearance">
        <legend className="ky-appearance-legend">Theme</legend>
        <div className="ky-appearance-grid">
          {THEMES.map((theme) => (
            <label key={theme.id} className="ky-appearance-option">
              <input className="ky-appearance-radio" type="radio" name="kyidentity-theme" value={theme.id} checked={theme.id === current.id} onChange={() => choose(theme)} />
              <span className="ky-appearance-preview" aria-hidden="true" data-ky-preview={theme.id} />
              <span className="ky-appearance-name">{theme.name}</span>
              <small className="ky-appearance-mode">{mode(theme.scheme)}</small>
            </label>
          ))}
        </div>
      </fieldset>
    </div>
  );
};
