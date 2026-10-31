import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { Sidebar } from './Sidebar';
import type { Access, User } from '../types';

const none: Access = { admin: false, helpdesk: false, auditor: false, appOwner: [] };
const render = (user: User, activeTab: string) =>
  renderToStaticMarkup(<Sidebar user={user} activeTab={activeTab} setActiveTab={() => {}} onLogout={() => {}} />);
const admin: User = { id: 'a1', username: 'admin', displayName: 'Administrator', email: 'a@x.test', role: 'admin', access: { ...none, admin: true } };
const sections = (html: string) => [...html.matchAll(/<summary[^>]*>(?:<svg[\s\S]*?<\/svg>)?([^<]+)/g)].map(m => m[1]);

describe('sidebar', () => {
  it('groups administration into Directory, Applications, Security and System', () => {
    expect(sections(render(admin, 'admin-users'))).toEqual(['Directory', 'Applications', 'Security', 'System']);
  });

  it('marks exactly one current item and opens only its section', () => {
    const html = render(admin, 'admin-clients');
    expect(html.match(/aria-current="page"/g)).toHaveLength(1);
    expect(html).toMatch(/aria-current="page"[^>]*>(?:<svg[\s\S]*?<\/svg>)OAuth clients/);
    expect(html.match(/<details[^>]* open=""/g)).toHaveLength(1);
    expect(html).toMatch(/<details[^>]* open=""><summary[^>]*data-current="true"[^>]*>(?:<svg[\s\S]*?<\/svg>)Applications/);
  });

  it('keeps App connections current while managing launcher cards', () => {
    expect(render(admin, 'admin-launchers')).toMatch(/aria-current="page"[^>]*>(?:<svg[\s\S]*?<\/svg>)App connections/);
  });

  it('shows a delegate only the sections it may use', () => {
    const helpdesk: User = { ...admin, role: 'user', access: { ...none, helpdesk: true } };
    const html = render(helpdesk, 'dashboard');
    expect(sections(html)).toEqual(['Directory']);
    expect(html).toContain('Delegated administrator');
  });

  it('names the user over their role with a labelled Sign out row', () => {
    const html = render({ ...admin, role: 'user', access: none }, 'dashboard');
    expect(html).not.toContain('<summary');
    expect(html).toContain('<p class="ky-user-name">admin</p><p class="ky-user-role">Everyday account</p>');
    expect(html).toMatch(/class="ky-user-signout"><svg[^>]*lucide-log-out[\s\S]*?<span>Sign out<\/span>/);
  });
});
