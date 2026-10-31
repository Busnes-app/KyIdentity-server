import React, { useEffect, useState } from 'react';
import { Access, User } from '../types';
import { LicenseFooter } from './LicenseFooter';
import { Shield, LayoutGrid, Smartphone, Palette, Users, UsersRound, RefreshCw, Key, FileText, Archive, LogOut, Mail, Database, Inbox, Bell, ChevronRight, AppWindow } from 'lucide-react';

interface SidebarProps {
  user: User;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onLogout: () => void;
}

type Icon = React.FC<{ size?: number; 'aria-hidden'?: boolean }>;
type Item = [tab: string, label: string, icon: Icon];
type Section = [title: string, items: Item[]];

const ACCOUNT: Item[] = [
  ['dashboard', 'Applications', LayoutGrid],
  ['devices', 'Security and devices', Smartphone],
  ['appearance', 'Appearance', Palette],
];

const ADMIN: Section[] = [
  ['Directory', [
    ['admin-users', 'Users', Users],
    ['admin-groups', 'Groups', UsersRound],
    ['admin-systems', 'Suite sync', RefreshCw],
    ['admin-scim', 'Inbound SCIM', Database],
  ]],
  ['Integrations', [
    ['admin-app-registry', 'App connections', AppWindow],
    ['admin-clients', 'OAuth clients', Key],
    ['admin-requests', 'Access requests', Inbox],
  ]],
  ['Security', [
    ['admin-enrollment', 'Sign-in policies', Shield],
    ['admin-audit', 'Audit log', FileText],
    ['admin-alerts', 'Alerts', Bell],
  ]],
  ['System', [
    ['admin-backup', 'Disaster recovery', Archive],
    ['admin-mail', 'Mail delivery', Mail],
  ]],
];

export const Brand: React.FC = () => (
  <div className="brand">
    <img className="ky-mark-stamp" src="/app-icon.png" width={40} height={40} alt="" />
    <div>
      <b>KyIdentity</b>
      <small>ID Authority</small>
    </div>
  </div>
);

/** Navigation is a convenience; the server enforces every route. */
function adminSections(a: Access | undefined): Section[] {
  if (!a) return [];
  if (a.admin || a.auditor) return ADMIN;
  const allowed = (tab: string) => (tab === 'admin-users' && a.helpdesk) || ((tab === 'admin-app-registry' || tab === 'admin-requests') && a.appOwner.length > 0);
  return ADMIN.map(([title, items]): Section => [title, items.filter(([tab]) => allowed(tab))]).filter(([, items]) => items.length > 0);
}

function roleLabel(user: User): string {
  if (user.role === 'admin') return 'Administrator';
  return adminSections(user.access).length > 0 ? 'Delegated administrator' : 'Everyday account';
}

// Launcher management is reached from App connections, so that item stays current there.
const navTab = (tab: string) => (tab === 'admin-launchers' ? 'admin-app-registry' : tab);
const sectionOf = (sections: Section[], tab: string) => sections.find(([, items]) => items.some(([t]) => t === navTab(tab)))?.[0];

export const Sidebar: React.FC<SidebarProps> = ({ user, activeTab, setActiveTab, onLogout }) => {
  const admin = adminSections(user.access);
  // Administration sections fold, one open at a time, so the whole nav fits a laptop screen.
  const current = sectionOf(admin, activeTab);
  const [open, setOpen] = useState(() => current ?? admin[0]?.[0] ?? '');
  useEffect(() => { if (current) setOpen(current); }, [current]);
  // Your account folds on its own and starts open.
  const [accountOpen, setAccountOpen] = useState(true);

  const items = (list: Item[]) => list.map(([tab, label, Icon]) => (
    <button
      key={tab}
      type="button"
      onClick={() => setActiveTab(tab)}
      className="ky-nav-item"
      aria-current={navTab(activeTab) === tab ? 'page' : undefined}
    >
      <Icon size={16} aria-hidden />
      {label}
    </button>
  ));

  return (
    <aside className="side">
      <Brand />
      <div className="side-navigation">
        <nav className="side-nav" aria-label="Your account">
          <details className="side-section" open={accountOpen} onToggle={e => setAccountOpen(e.currentTarget.open)}>
            <summary className="side-heading" data-current={ACCOUNT.some(([tab]) => tab === activeTab) || undefined}>
              <ChevronRight size={14} aria-hidden="true" />
              Your account
            </summary>
            {items(ACCOUNT)}
          </details>
        </nav>
        {admin.length > 0 && (
          <nav className="side-nav" aria-label="Administration">
            {admin.map(([title, list]) => (
              <details
                key={title}
                className="side-section"
                open={open === title}
                onToggle={e => {
                  const isOpen = e.currentTarget.open;
                  setOpen(o => (isOpen ? title : o === title ? '' : o));
                }}
              >
                <summary className="side-heading" data-current={current === title || undefined}>
                  <ChevronRight size={14} aria-hidden="true" />
                  {title}
                </summary>
                {items(list)}
              </details>
            ))}
          </nav>
        )}
      </div>
      <div className="ky-user">
        <div className="ky-user-copy">
          <p className="ky-user-name">{user.username}</p>
          <p className="ky-user-role">{roleLabel(user)}</p>
        </div>
        <button type="button" className="ky-user-signout" onClick={onLogout}>
          <LogOut size={16} aria-hidden="true" />
          <span>Sign out</span>
        </button>
      </div>
      <LicenseFooter version={user.version} />
    </aside>
  );
};
