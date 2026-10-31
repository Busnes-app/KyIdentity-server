import React from 'react';
import { ThemeSwitcher } from './ThemeSwitcher';

/** The suite sign-in frame (ky-ui shell): every screen before the dashboard renders inside it. */
export const AuthFrame: React.FC<{ children: React.ReactNode; after?: React.ReactNode }> = ({ children, after }) => (
  <main className="ky-auth">
    <div className="ky-auth-theme"><ThemeSwitcher /></div>
    <div className="ky-auth-body">
      <div className="ky-auth-brand">
        <img className="ky-mark-stamp" src="/app-icon.png" width={56} height={56} alt="" />
        <h1>KyIdentity</h1>
        <p>Sign in once, then open everything.</p>
      </div>
      <div className="ky-auth-card">{children}</div>
    </div>
    {after}
  </main>
);
