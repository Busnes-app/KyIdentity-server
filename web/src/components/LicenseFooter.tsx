import React, { useState } from 'react';
import mitLicenseText from '../mit.txt?raw';
import { Modal } from './Modal';

export const LicenseTitle: React.FC<{ version?: string }> = ({ version }) => (
  <span className="license-title-main">
    <span className="license-app-name">KyIdentity</span>
    {version ? <span className="license-version-badge">v{version}</span> : null}
  </span>
);

export const LicenseDetails: React.FC = () => (
  <div className="license-window">
    <p className="license-title-sub">Developed by Busnes.app</p>
    <p className="license-title-sub">&copy; {new Date().getFullYear()} &middot; Licensed under the MIT License</p>
    <textarea className="license-text" readOnly value={mitLicenseText} aria-label="MIT License" />
  </div>
);

/** The suite's sidebar licence line; opens the version and MIT text. */
export const LicenseFooter: React.FC<{ version?: string }> = ({ version }) => {
  const [open, setOpen] = useState(false);
  return (
    <div className="sidebar-footer">
      <p>
        <button type="button" className="license-link" onClick={() => setOpen(true)}>
          &copy; {new Date().getFullYear()} &middot; MIT License
        </button>
      </p>
      {open && (
        <Modal
          className="license-modal"
          closeOnBackdrop
          onClose={() => setOpen(false)}
          title={<LicenseTitle version={version} />}
        >
          <LicenseDetails />
        </Modal>
      )}
    </div>
  );
};
