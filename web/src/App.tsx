import React, { useEffect, useReducer, useState } from 'react';
import { User, canAdminister } from './types';
import { apiJson, isSignedOut, logout } from './api';
import { parseMe } from './parsers';
import { nextSession } from './session';
import { Sidebar } from './components/Sidebar';
import { LoginView } from './components/LoginView';
import { UserDashboard } from './components/UserDashboard';
import { DeviceSettings } from './components/DeviceSettings';
import { Settings } from './components/Settings';
import { SettingsSection, hashFor, tabFromHash } from './route';
import { AdminAppRegistry } from './components/AdminAppRegistry';
import { AdminEnrollmentPolicies } from './components/AdminEnrollmentPolicies';
import { AdminGroups } from './components/AdminGroups';
import { AdminUsers } from './components/AdminUsers';
import { AdminSystems } from './components/AdminSystems';
import { AdminClients } from './components/AdminClients';
import { AdminAudit } from './components/AdminAudit';
import { AdminBackup } from './components/AdminBackup';
import { AdminMail } from './components/AdminMail';
import { AdminBranding } from './components/AdminBranding';
import { AdminSCIM } from './components/AdminSCIM';
import { AdminAccessRequests } from './components/AdminAccessRequests';
import { AdminAlerts } from './components/AdminAlerts';
import { AccountLinkView } from './components/AccountLinkView';
import { PasswordChangeRequired } from './components/PasswordChangeRequired';
import { LicenseFooter } from './components/LicenseFooter';
import { SessionUnavailable } from './components/SessionUnavailable';
import { DeviceApproval } from './components/DeviceApproval';
import { RefreshCw } from 'lucide-react';

export const App: React.FC = () => {
  const [session, updateSession] = useReducer(nextSession, { kind: 'signedOut' });
  const currentUser = session.kind === 'signedIn' ? session.user : null;
  const [loading, setLoading] = useState(true);
  const [activeTab, setTab] = useState(() => tabFromHash(window.location.hash));
  const [groupUser, setGroupUser] = useState<User | null>(null);
  const [logoutFailed, setLogoutFailed] = useState(false);

  // The view lives in the URL hash, so links and the back button work.
  const setActiveTab = (tab: string) => {
    if (window.location.hash === hashFor(tab)) setTab(tab);
    else window.location.hash = hashFor(tab);
  };
  useEffect(() => {
    const sync = () => {
      const tab = tabFromHash(window.location.hash);
      // A moved or unknown hash is rewritten in place, not added to history.
      if (window.location.hash && window.location.hash !== hashFor(tab)) history.replaceState(null, '', hashFor(tab));
      if (tab !== 'admin-groups') setGroupUser(null);
      setTab(tab);
    };
    sync();
    window.addEventListener('hashchange', sync);
    return () => window.removeEventListener('hashchange', sync);
  }, []);

  // Link pages need no session and must not wait for one.
  const linkKind = window.location.pathname === '/activate' ? 'activation' : window.location.pathname === '/reset' ? 'reset' : null;

  // Only a 401 signs this browser out. Any other failure keeps whoever is signed in, and with
  // nobody yet shows a retry screen rather than sign-in over a session that may be live.
  const checkSession = async () => {
    try {
      updateSession({ kind: 'signedIn', user: await apiJson('/api/auth/me', parseMe) });
    } catch (err) {
      if (isSignedOut(err)) {
        updateSession({ kind: 'signedOut' });
      } else {
        updateSession({ kind: 'unavailable' });
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkSession();

    const handleUnauthorized = () => {
      setLogoutFailed(false);
      updateSession({ kind: 'signedOut' });
    };

    window.addEventListener('kyidentity:unauthorized', handleUnauthorized);
    window.addEventListener('kyidentity:enrollment-required',checkSession);
    window.addEventListener('kyidentity:password-change-required',checkSession);
    return () => {window.removeEventListener('kyidentity:unauthorized', handleUnauthorized);window.removeEventListener('kyidentity:enrollment-required',checkSession);window.removeEventListener('kyidentity:password-change-required',checkSession);};
  }, []);

  // The sign-in screen appears only once the server has ended the session: on a shared
  // computer, a signed-out look over a live cookie hands the account to the next person.
  const handleLogout = async () => {
    if (!(await logout())) {
      setLogoutFailed(true);
      return;
    }
    setLogoutFailed(false);
    updateSession({ kind: 'signedOut' });
    setActiveTab('dashboard');
  };
  const logoutAlert = logoutFailed && <div className="alert-box error" role="alert"><p>Sign-out did not reach the server, so this browser is still signed in. Check the connection and sign out again.</p></div>;

  if (loading) {
    return (
      <div className="loading-screen">
        <RefreshCw className="spin icon-cyan" size={32} />
        <p className="loading-text">Checking your session</p>
      </div>
    );
  }

  if (linkKind) return <AccountLinkView kind={linkKind} />;

  if (session.kind === 'unavailable') {
    return <SessionUnavailable onRetry={() => { setLoading(true); void checkSession(); }} />;
  }

  if (!currentUser || (window.location.pathname === '/login' && new URLSearchParams(window.location.search).has('interaction'))) {
    return <LoginView onLoginSuccess={(u) => { setLogoutFailed(false); updateSession({ kind: 'signedIn', user: u }); checkSession(); }} />;
  }

  if (currentUser.enrollment?.restricted) return <main className="ky-content">
    {logoutAlert}
    <div role="status" className="alert-box"><div><h1>Complete MFA enrollment</h1><p>This session can only set up account security. Permitted methods: {currentUser.enrollment.allowedMethods.map(m=>m==='webauthn'?'passkey':m.toUpperCase()).join(', ')}.</p><p>After enrolling, sign out and sign in with a permitted factor to continue.</p><button className="secondary-btn" onClick={handleLogout}>Sign out and sign in again</button></div></div>
    <DeviceSettings user={currentUser} onUserUpdate={checkSession}/>
  </main>;

  if (currentUser.passwordChangeRequired) {
    return <>{logoutAlert}<PasswordChangeRequired user={currentUser} onLogout={handleLogout} onChanged={() => { setActiveTab('dashboard'); checkSession(); }} /></>;
  }

  // Workstation sign-in (RFC 8628): approve a code a computer shows.
  if (window.location.pathname === '/device') return <DeviceApproval user={currentUser} />;

  return (
    <div className="ky-app">
      <Sidebar
        user={currentUser}
        activeTab={activeTab}
        setActiveTab={tab => { setGroupUser(null); setActiveTab(tab); }}
        onLogout={handleLogout}
      />

      <main className="ky-content">
        {logoutAlert}
        {currentUser.enrollment?.required && !currentUser.enrollment.enrolled && <div role="status" className="alert-box"><p>Enroll a permitted MFA factor by {new Date(currentUser.enrollment.deadline*1000).toLocaleString()}. <button className="secondary-btn" onClick={()=>setActiveTab('settings/account')}>Set up MFA</button></p></div>}
        {activeTab === 'dashboard' && (
          <UserDashboard
            user={currentUser}
            onNavigateToDevices={() => setActiveTab('settings/account')}
            onNavigateToConnections={currentUser.access?.admin || currentUser.access?.appOwner.length ? () => setActiveTab('admin-app-registry') : undefined}
          />
        )}

        {activeTab.startsWith('settings/') && (
          <Settings section={activeTab.slice(9) as SettingsSection} user={currentUser} onUserUpdate={checkSession} />
        )}

        {canAdminister(currentUser.access) && (
          <>
            {activeTab === 'admin-enrollment' && <AdminEnrollmentPolicies />}
            {activeTab === 'admin-users' && <AdminUsers access={currentUser.access} onManageGroups={user => { setGroupUser(user); setActiveTab('admin-groups'); }} />}
            {activeTab === 'admin-groups' && <AdminGroups key={groupUser?.id ?? 'all'} user={groupUser} onClearUser={() => setGroupUser(null)} />}
            {activeTab === 'admin-app-registry' && <AdminAppRegistry onManageLaunchers={() => setActiveTab('admin-launchers')} />}
            {activeTab === 'admin-launchers' && <UserDashboard key="manage-launchers" manage user={currentUser} onNavigateToDevices={() => setActiveTab('settings/account')} />}
            {activeTab === 'admin-systems' && <AdminSystems />}
            {activeTab === 'admin-clients' && <AdminClients />}
            {activeTab === 'admin-audit' && <AdminAudit />}
            {activeTab === 'admin-backup' && <AdminBackup />}
            {activeTab === 'admin-mail' && <AdminMail />}
            {activeTab === 'admin-branding' && <AdminBranding />}
            {activeTab === 'admin-scim' && <AdminSCIM />}
            {activeTab === 'admin-requests' && <AdminAccessRequests />}
            {activeTab === 'admin-alerts' && <AdminAlerts access={currentUser.access} />}
          </>
        )}
        <LicenseFooter version={currentUser.version} className="ky-content-foot" />
      </main>
    </div>
  );
};
