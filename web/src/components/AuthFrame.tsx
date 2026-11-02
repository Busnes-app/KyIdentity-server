import React from 'react';
import { ThemeSwitcher } from './ThemeSwitcher';
import { useBranding, type Branding } from '../branding';

/** The sign-in heading: the organisation's logo and name when set (issue #145), else KyIdentity's. */
export const AuthBrand: React.FC<{ branding: Branding }> = ({ branding }) => (
  <div className="ky-auth-brand">
    {branding.logoUrl
      ? <img className="brand-logo" src={branding.logoUrl} width={56} height={56} alt="" />
      : <img className="ky-mark-stamp" src="/app-icon.png" width={56} height={56} alt="" />}
    <h1>{branding.name || 'KyIdentity'}</h1>
    <p>{branding.name ? 'Sign in with KyIdentity, then open everything.' : 'Sign in once, then open everything.'}</p>
  </div>
);

/** The suite sign-in frame (ky-ui shell): every screen before the dashboard renders inside it. */
export const AuthFrame: React.FC<{ children: React.ReactNode; after?: React.ReactNode }> = ({ children, after }) => (
  <main className="ky-auth">
    <div className="ky-auth-theme"><ThemeSwitcher /></div>
    <div className="ky-auth-body">
      <AuthBrand branding={useBranding()} />
      <div className="ky-auth-card">{children}</div>
    </div>
    {after}
  </main>
);
