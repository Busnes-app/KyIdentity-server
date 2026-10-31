import { readFileSync } from 'node:fs';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import mitLicenseText from '../mit.txt?raw';
import { parseMe } from '../parsers';
import { LicenseFooter } from './LicenseFooter';
import { Sidebar } from './Sidebar';

const year = new Date().getFullYear();

describe('licence footer', () => {
  it('ships the repository licence unchanged', () => {
    expect(mitLicenseText).toBe(readFileSync(new URL('../../../LICENSE.txt', import.meta.url), 'utf8'));
  });

  it('shows the copyright line as the button that opens the licence', () => {
    const html = renderToStaticMarkup(<LicenseFooter version="1.2.3" />);
    expect(html).toContain('class="ky-license-link"');
    expect(html).toContain(`© ${year} · MIT License`);
  });

  it('badges the version only when the server sent one', () => {
    expect(renderToStaticMarkup(<LicenseFooter version="0.5.0" />)).toContain('<span class="ky-about-version">v0.5.0</span>');
    expect(renderToStaticMarkup(<LicenseFooter />)).not.toContain('ky-about-version');
  });

  it('is the shared About dialog: developer, licence, full text and an outlined Close', () => {
    const html = renderToStaticMarkup(<LicenseFooter />);
    expect(html).toContain('<dialog class="ky-about" aria-label="About KyIdentity"');
    expect(html).toContain('Developed by Busnes.app');
    expect(html).toContain(`© ${year} · Licensed under the MIT License`);
    expect(html).toContain('Copyright (c) 2026 Busnes.app');
    expect(html).toContain('<button type="button" class="ky-about-close">Close</button>');
    expect(html).not.toContain('×');
  });

  it('sits in the signed-in sidebar, fed the version from /api/auth/me', () => {
    const user = parseMe({ id: 'u1', username: 'alice', role: 'user', status: 'active', version: '0.5.0' });
    expect(user.version).toBe('0.5.0');
    const html = renderToStaticMarkup(<Sidebar user={user} activeTab="dashboard" setActiveTab={() => {}} onLogout={() => {}} />);
    expect(html).toContain('class="ky-license"');
  });
});
