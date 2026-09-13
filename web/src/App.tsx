import React, { useEffect, useState } from 'react';
import { User } from './types';
import { apiJson, apiRequest } from './api';
import { parseMe } from './parsers';
import { Sidebar } from './components/Sidebar';
import { LoginView } from './components/LoginView';
import { UserDashboard } from './components/UserDashboard';
import { DeviceSettings } from './components/DeviceSettings';
import { Appearance } from './components/Appearance';
import { AdminAppRegistry } from './components/AdminAppRegistry';
import { AdminEnrollmentPolicies } from './components/AdminEnrollmentPolicies';
import { AdminGroups } from './components/AdminGroups';
import { AdminUsers } from './components/AdminUsers';
import { AdminSystems } from './components/AdminSystems';
import { AdminClients } from './components/AdminClients';
import { AdminAudit } from './components/AdminAudit';
import { AdminBackup } from './components/AdminBackup';
import { AdminMail } from './components/AdminMail';
import { AccountLinkView } from './components/AccountLinkView';
import { RefreshCw } from 'lucide-react';

export const App: React.FC = () => {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [groupUser, setGroupUser] = useState<User | null>(null);

  // Link pages need no session and must not wait for one.
  const linkKind = window.location.pathname === '/activate' ? 'activation' : window.location.pathname === '/reset' ? 'reset' : null;

  const checkSession = async () => {
    try {
      setCurrentUser(await apiJson('/api/auth/me', parseMe));
    } catch {
      setCurrentUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkSession();

    const handleUnauthorized = () => {
      setCurrentUser(null);
    };

    window.addEventListener('kysignon:unauthorized', handleUnauthorized);
    window.addEventListener('kysignon:enrollment-required',checkSession);
    return () => {window.removeEventListener('kysignon:unauthorized', handleUnauthorized);window.removeEventListener('kysignon:enrollment-required',checkSession);};
  }, []);

  const handleLogout = async () => {
    try {
      await apiRequest('/api/auth/logout', { method: 'POST' });
    } catch {
      // The local session is cleared regardless; a failed logout call must not strand the
      // user on an authenticated-looking screen.
    }
    setCurrentUser(null);
    setActiveTab('dashboard');
  };

  if (loading) {
    return (
      <div className="loading-screen">
        <RefreshCw className="spin icon-cyan" size={32} />
        <p className="loading-text">Checking your session</p>
      </div>
    );
  }

  if (linkKind) return <AccountLinkView kind={linkKind} />;

  if (!currentUser || (window.location.pathname === '/login' && new URLSearchParams(window.location.search).has('interaction'))) {
    return <LoginView onLoginSuccess={(u) => { setCurrentUser(u); checkSession(); }} />;
  }

  if (currentUser.enrollment?.restricted) return <div className="shell"><main className="main-content" style={{ gridColumn: '1 / -1' }}>
    <div role="status" className="alert-box"><div><h1>Complete MFA enrollment</h1><p>This session can only set up account security. Permitted methods: {currentUser.enrollment.allowedMethods.map(m=>m==='webauthn'?'passkey':m.toUpperCase()).join(', ')}.</p><p>After enrolling, sign out and sign in with a permitted factor to continue.</p><button className="secondary-btn" onClick={handleLogout}>Sign out and sign in again</button></div></div>
    <DeviceSettings user={currentUser} onUserUpdate={checkSession}/>
  </main></div>;

  return (
    <div className="shell">
      <Sidebar
        user={currentUser}
        activeTab={activeTab}
        setActiveTab={tab => { setGroupUser(null); setActiveTab(tab); }}
        onLogout={handleLogout}
      />

      <main className="main-content">
        {currentUser.enrollment?.required && !currentUser.enrollment.enrolled && <div role="status" className="alert-box"><p>Enroll a permitted MFA factor by {new Date(currentUser.enrollment.deadline*1000).toLocaleString()}. <button className="secondary-btn" onClick={()=>setActiveTab('devices')}>Set up MFA</button></p></div>}
        {activeTab === 'dashboard' && (
          <UserDashboard
            user={currentUser}
            onNavigateToDevices={() => setActiveTab('devices')}
          />
        )}

        {activeTab === 'devices' && (
          <DeviceSettings user={currentUser} onUserUpdate={checkSession} />
        )}

        {activeTab === 'appearance' && <Appearance />}

        {currentUser.role === 'admin' && (
          <>
            {activeTab === 'admin-enrollment' && <AdminEnrollmentPolicies />}
            {activeTab === 'admin-users' && <AdminUsers onManageGroups={user => { setGroupUser(user); setActiveTab('admin-groups'); }} />}
            {activeTab === 'admin-groups' && <AdminGroups key={groupUser?.id ?? 'all'} user={groupUser} onClearUser={() => setGroupUser(null)} />}
            {activeTab === 'admin-app-registry' && <AdminAppRegistry onManageLaunchers={() => setActiveTab('admin-launchers')} />}
            {activeTab === 'admin-launchers' && <UserDashboard key="manage-launchers" manage user={currentUser} onNavigateToDevices={() => setActiveTab('devices')} />}
            {activeTab === 'admin-systems' && <AdminSystems />}
            {activeTab === 'admin-clients' && <AdminClients />}
            {activeTab === 'admin-audit' && <AdminAudit />}
            {activeTab === 'admin-backup' && <AdminBackup />}
            {activeTab === 'admin-mail' && <AdminMail />}
          </>
        )}
      </main>
    </div>
  );
};
