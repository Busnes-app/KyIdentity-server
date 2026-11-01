import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { Sidebar } from './Sidebar';
import type { Access, User } from '../types';

const none: Access = { admin: false, helpdesk: false, auditor: false, appOwner: [] };
const render = (user: User, activeTab: string) =>
  renderToStaticMarkup(<Sidebar user={user} activeTab={activeTab} setActiveTab={() => {}} onLogout={() => {}} />);
const admin: User = { id: 'a1', username: 'admin', displayName: 'Administrator', email: 'a@x.test', role: 'admin', access: { ...none, admin: true } };
// Section labels, plain or the fold buttons inside them.
const sections = (html: string) => [...html.matchAll(/<p class="ky-nav-section">(?:<button[^>]*>(?:<svg[\s\S]*?<\/svg>)?)?([^<]+)/g)].map(m => m[1]);
const item = (label: string) => new RegExp(`aria-current="page"[^>]*>(?:<svg[\\s\\S]*?<\\/svg>)<span>${label}</span>`);

describe('sidebar', () => {
  it('groups administration into Directory, Integrations, Security and System, under Your account', () => {
    expect(sections(render(admin, 'admin-users'))).toEqual(['Your account', 'Directory', 'Integrations', 'Security', 'System']);
  });

  it('marks exactly one current item and opens only its section', () => {
    const html = render(admin, 'admin-clients');
    expect(html.match(/aria-current="page"/g)).toHaveLength(1);
    expect(html).toMatch(item('OAuth clients'));
    // Your account is a plain label; only the current administration section is expanded.
    expect(html.match(/aria-expanded="true"/g)).toHaveLength(1);
    expect(html).toMatch(/aria-expanded="true" data-current="true">(?:<svg[\s\S]*?<\/svg>)Integrations/);
    // Folded rows stay in the markup (phones show them all); CSS hides them on desktop.
    expect(html.match(/data-folded="true"/g)).toHaveLength(9);
    expect(html).not.toContain('<details');
  });

  it('keeps App connections current while managing launcher cards', () => {
    expect(render(admin, 'admin-launchers')).toMatch(item('App connections'));
  });

  it('shows a delegate only the sections it may use', () => {
    const helpdesk: User = { ...admin, role: 'user', access: { ...none, helpdesk: true } };
    const html = render(helpdesk, 'dashboard');
    expect(sections(html)).toEqual(['Your account', 'Directory']);
    expect(html).toContain('Delegated administrator');
  });

  it('holds Account, Phones & apps and Appearance in one Settings item', () => {
    const html = render(admin, 'settings/devices');
    expect(html.match(/aria-current="page"/g)).toHaveLength(1);
    expect(html).toMatch(item('Settings'));
    expect(html).not.toMatch(/<span>(Appearance|Security and devices|Account|Phones &amp; apps)<\/span>/);
  });

  it('names the user over their role with an icon-only Sign out', () => {
    const html = render({ ...admin, role: 'user', access: none }, 'dashboard');
    expect(sections(html)).toEqual(['Your account']);
    expect(html).toContain('<p class="ky-user-name">admin</p><p class="ky-user-role">Everyday account</p>');
    const signOut = /<button type="button" class="ky-icon-button" aria-label="Sign out" title="Sign out"><svg[^>]*lucide-log-out[^>]*>[\s\S]*?<\/svg><\/button>/;
    expect(html).toMatch(new RegExp(`class="ky-user-actions">${signOut.source}</div>`));
    expect(html).not.toContain('<span>Sign out</span>');
    // Phones: the same button in the header, and no Settings gear (KyIdentity keeps the nav item).
    expect(html).toMatch(new RegExp(`class="ky-mobile-actions">${signOut.source}</div>`));
    expect(html).not.toContain('aria-label="Settings"');
    expect(html).toMatch(/<div class="ky-brand"><img[^>]*width="28"[^>]*\/><span>KyIdentity<\/span><\/div>/);
    expect(html).not.toContain('ID Authority');
  });
});
