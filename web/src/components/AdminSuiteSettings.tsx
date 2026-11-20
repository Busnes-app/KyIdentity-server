import React, { useEffect, useState } from 'react';
import { apiJson, errorMessage, isRecord } from '../api';
import { findTheme } from '../ky-ui/themes';
import { THEME_CHOICES, setSuiteDefaultTheme } from '../theme';
import { PageHead } from './PageHead';
import { isCancelled, useStepUp } from './StepUpPrompt';

/** Platform-wide values every suite app reads (docs/SUITE-DIRECTORY.md). */
export interface SuiteSettings {
  emailDomains: string[];
  defaultTheme: string;
}

export function parseSuiteSettings(value: unknown): SuiteSettings {
  if (!isRecord(value) || !Array.isArray(value.emailDomains) || !value.emailDomains.every(d => typeof d === 'string') || typeof value.defaultTheme !== 'string') {
    throw new Error('Suite settings response is malformed');
  }
  return { emailDomains: value.emailDomains, defaultTheme: value.defaultTheme };
}

/** One domain per line (commas and spaces also separate); blanks dropped. */
export const splitDomains = (text: string) => text.split(/[\s,]+/).filter(Boolean);

const themeLabel = (id: string) => findTheme(id)?.name ?? id;

export function AdminSuiteSettings() {
  const [saved, setSaved] = useState<SuiteSettings | null>(null);
  const [theme, setTheme] = useState('system');
  const [domains, setDomains] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const { requestGrant, stepUpPrompt } = useStepUp();

  const show = (s: SuiteSettings) => {
    setSaved(s); setTheme(s.defaultTheme); setDomains(s.emailDomains.join('\n'));
    setSuiteDefaultTheme(s.defaultTheme);
  };
  useEffect(() => {
    apiJson('/api/admin/suite-settings', parseSuiteSettings).then(show).catch(err => setError(errorMessage(err, 'Could not load suite settings')));
  }, []);

  const run = async (what: string, call: () => Promise<SuiteSettings>) => {
    setBusy(true); setError(null); setNotice(null);
    try { show(await call()); setNotice('Saved.'); } catch (err) { if (!isCancelled(err)) setError(errorMessage(err, what)); } finally { setBusy(false); }
  };
  const saveTheme = (e: React.FormEvent) => {
    e.preventDefault();
    void run('Could not save the default theme', () => apiJson('/api/admin/suite-settings/default-theme', parseSuiteSettings, { method: 'PUT', body: JSON.stringify({ theme }) }));
  };
  const path = '/api/admin/suite-settings/email-domains';
  const saveDomains = (e: React.FormEvent) => {
    e.preventDefault();
    void run('Could not save the mail domains', async () => {
      const stepUpToken = await requestGrant('Change the mail domains every suite app reads.', `PUT ${path}`);
      return apiJson(path, parseSuiteSettings, { method: 'PUT', stepUpToken, body: JSON.stringify({ domains: splitDomains(domains) }) });
    });
  };

  return (
    <div className="admin-page">
      <PageHead title="Suite settings" lede="Values every suite app reads from KyIdentity, the same for the whole install." />
      {error && <div className="alert-box error" role="alert">{error}</div>}
      {notice && <div className="alert-box" role="status">{notice}</div>}
      {saved && <>
        <form className="settings-section inline-form" onSubmit={saveTheme}>
          <div className="form-row">
            <div className="form-group flex-1">
              <label className="form-label" htmlFor="suite-theme">Default theme</label>
              <select id="suite-theme" className="form-select" value={theme} disabled={busy} onChange={e => setTheme(e.target.value)}>
                {THEME_CHOICES.map(({ pair, choices }) => (
                  <optgroup key={pair.id} label={pair.name}>
                    {choices.map(({ mode, value }) => (
                      <option key={value} value={value}>{mode === 'system' ? `${pair.name}, follows device` : themeLabel(value)}</option>
                    ))}
                  </optgroup>
                ))}
              </select>
            </div>
            <button type="submit" className="primary-btn" disabled={busy || theme === saved.defaultTheme}>Save</button>
          </div>
          <p className="form-hint">Every suite app, and this sign-in page, uses it until a person picks a theme of their own. Their choice always wins.</p>
        </form>
        <form className="settings-section inline-form" onSubmit={saveDomains}>
          <div className="form-group">
            <label className="form-label" htmlFor="suite-domains">Mail domains</label>
            <textarea id="suite-domains" className="form-input" rows={4} spellCheck={false} autoCapitalize="none" placeholder="example.com" value={domains} disabled={busy} onChange={e => setDomains(e.target.value)} />
          </div>
          <p className="form-hint">The domains people's addresses use, one per line, at most 50. KyPost and the other apps read this list instead of keeping their own. It does not restrict which addresses accounts may have.</p>
          <div className="form-row">
            <button type="submit" className="primary-btn" disabled={busy || splitDomains(domains).join('\n') === saved.emailDomains.join('\n')}>Save domains</button>
          </div>
        </form>
      </>}
      {stepUpPrompt}
    </div>
  );
}
