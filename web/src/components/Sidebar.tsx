import React from 'react';
import { User } from '../types';
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

export const Sidebar: React.FC<SidebarProps> = ({ user, activeTab, setActiveTab, onLogout }) => {
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
      {user.role === 'admin' && group('Administration', ADMIN)}
      <div className="side-me">
        <div className="side-who">
          <b>{user.username}</b>
          <span>{user.role === 'admin' ? 'Administrator' : 'User'}</span>
        </div>
        <button className="icon-btn" onClick={onLogout} title="Sign out" aria-label="Sign out">
          <LogOut size={16} />
        </button>
      </div>
    </aside>
  );
};
