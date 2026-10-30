import { readFileSync } from 'node:fs';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import mitLicenseText from '../mit.txt?raw';
import { parseMe } from '../parsers';
import { LicenseDetails, LicenseFooter, LicenseTitle } from './LicenseFooter';
import { Sidebar } from './Sidebar';

const year = new Date().getFullYear();

describe('licence footer', () => {
  it('ships the repository licence unchanged', () => {
    expect(mitLicenseText).toBe(readFileSync(new URL('../../../LICENSE.txt', import.meta.url), 'utf8'));
  });

  it('shows the copyright line as the button that opens the licence', () => {
    const html = renderToStaticMarkup(<LicenseFooter version="1.2.3" />);
    expect(html).toContain('class="license-link"');
    expect(html).toContain(`© ${year} · MIT License`);
  });

  it('badges the version only when the server sent one', () => {
    expect(renderToStaticMarkup(<LicenseTitle version="0.5.0" />)).toContain('<span class="license-version-badge">v0.5.0</span>');
    expect(renderToStaticMarkup(<LicenseTitle />)).not.toContain('license-version-badge');
  });

  it('dialog body names the developer, the licence and its full text', () => {
    const html = renderToStaticMarkup(<LicenseDetails />);
    expect(html).toContain('Developed by Busnes.app');
    expect(html).toContain(`© ${year} · Licensed under the MIT License`);
    expect(html).toContain('Copyright (c) 2026 Busnes.app');
  });

  it('sits in the signed-in sidebar, fed the version from /api/auth/me', () => {
    const user = parseMe({ id: 'u1', username: 'alice', role: 'user', status: 'active', version: '0.5.0' });
    expect(user.version).toBe('0.5.0');
    const html = renderToStaticMarkup(<Sidebar user={user} activeTab="dashboard" setActiveTab={() => {}} onLogout={() => {}} />);
    expect(html).toContain('class="sidebar-footer"');
  });
});
