import React, { Fragment, useEffect, useState } from 'react';
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
  <div className="ky-brand">
    <img className="ky-mark-stamp" src="/app-icon.png" width={28} height={28} alt="" />
    <span>KyIdentity</span>
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
  // Fifteen rows do not fit 1440x900 with labels, so administration sections fold on desktop,
  // one open at a time (the current item's). Phones show every item in the tab row.
  const current = sectionOf(admin, activeTab);
  const [open, setOpen] = useState(() => current ?? admin[0]?.[0] ?? '');
  useEffect(() => { if (current) setOpen(current); }, [current]);

  const items = (list: Item[], folded = false) => list.map(([tab, label, Icon]) => (
    <button
      key={tab}
      type="button"
      onClick={() => setActiveTab(tab)}
      className="ky-nav-item"
      data-folded={folded || undefined}
      aria-current={navTab(activeTab) === tab ? 'page' : undefined}
    >
      <Icon aria-hidden />
      <span>{label}</span>
    </button>
  ));

  return (
    <header className="ky-sidebar">
      <div className="ky-mobile-head">
        <Brand />
        <button type="button" className="ky-mobile-signout" aria-label="Sign out" onClick={onLogout}>
          <LogOut aria-hidden="true" />
        </button>
      </div>
      <nav className="ky-nav" aria-label="Primary">
        <p className="ky-nav-section">Your account</p>
        {items(ACCOUNT)}
        {admin.map(([title, list]) => (
          <Fragment key={title}>
            <p className="ky-nav-section">
              <button type="button" className="ky-nav-fold" aria-expanded={open === title} data-current={current === title || undefined}
                onClick={() => setOpen(o => (o === title ? '' : title))}>
                <ChevronRight aria-hidden="true" />
                {title}
              </button>
            </p>
            {items(list, open !== title)}
          </Fragment>
        ))}
      </nav>
      <div className="ky-sidebar-foot">
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
      </div>
    </header>
  );
};
