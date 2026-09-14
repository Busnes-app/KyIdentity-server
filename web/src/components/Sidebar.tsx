import React from 'react';
import { Access, User } from '../types';
import { Shield, LayoutGrid, Smartphone, Palette, Users, RefreshCw, Key, FileText, Archive, LogOut, Mail, Database } from 'lucide-react';

interface SidebarProps {
  user: User;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onLogout: () => void;
}

type Icon = React.FC<{ size?: number }>;
type Item = [tab: string, label: string, icon: Icon];

const ACCOUNT: Item[] = [
  ['dashboard', 'Applications', LayoutGrid],
  ['devices', 'Security and devices', Smartphone],
  ['appearance', 'Appearance', Palette],
];

const ADMIN: Item[] = [
  ['admin-users', 'Users', Users],
  ['admin-enrollment', 'MFA policies', Shield],
  ['admin-groups', 'Groups', Users],
  ['admin-app-registry', 'App connections', LayoutGrid],
  ['admin-systems', 'Suite sync', RefreshCw],
  ['admin-scim', 'Inbound SCIM', Database],
  ['admin-clients', 'OAuth clients', Key],
  ['admin-audit', 'Audit log', FileText],
  ['admin-backup', 'Disaster recovery', Archive],
  ['admin-mail', 'Mail delivery', Mail],
];

export const Brand: React.FC = () => (
  <div className="brand">
    <span className="brand-tile">
      <Shield size={24} />
    </span>
    <div>
      <b>KySignOn</b>
      <small>ID Authority</small>
    </div>
  </div>
);

/** Navigation is a convenience; the server enforces every route. */
function adminItems(a: Access | undefined): Item[] {
  if (!a) return [];
  if (a.admin || a.auditor) return ADMIN;
  return ADMIN.filter(([tab]) => (tab === 'admin-users' && a.helpdesk) || (tab === 'admin-app-registry' && a.appOwner.length > 0));
}

function roleLabel(user: User): string {
  if (user.role === 'admin') return 'Administrator';
  return adminItems(user.access).length > 0 ? 'Delegated administrator' : 'User';
}

export const Sidebar: React.FC<SidebarProps> = ({ user, activeTab, setActiveTab, onLogout }) => {
  const admin = adminItems(user.access);
  const group = (title: string, items: Item[]) => (
    <nav className="side-nav" aria-label={title}>
      <h4>{title}</h4>
      {items.map(([tab, label, Icon]) => (
        <button
          key={tab}
          onClick={() => setActiveTab(tab)}
          aria-current={activeTab === tab ? 'page' : undefined}
        >
          <Icon size={17} />
          {label}
        </button>
      ))}
    </nav>
  );

  return (
    <aside className="side">
      <Brand />
      {group('Your account', ACCOUNT)}
      {admin.length > 0 && group('Administration', admin)}
      <div className="side-me">
        <div className="side-who">
          <b>{user.username}</b>
          <span>{roleLabel(user)}</span>
        </div>
        <button className="icon-btn" onClick={onLogout} title="Sign out" aria-label="Sign out">
          <LogOut size={16} />
        </button>
      </div>
    </aside>
  );
};
