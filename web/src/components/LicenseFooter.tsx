import React, { useRef } from 'react';
import mitLicenseText from '../mit.txt?raw';

/** The suite's licence line and About dialog (ky-ui shell markup). */
/** `className` places it: the sidebar foot by default, `ky-content-foot` at a phone page's end. */
export const LicenseFooter: React.FC<{ version?: string; className?: string }> = ({ version, className = 'ky-license' }) => {
  const dialog = useRef<HTMLDialogElement>(null);
  const year = new Date().getFullYear();
  const close = () => dialog.current?.close();

  return (
    <footer className={className}>
      <button type="button" className="ky-license-link" onClick={() => dialog.current?.showModal()}>
        &copy; {year} &middot; MIT License
      </button>
      <dialog ref={dialog} className="ky-about" aria-label="About KyIdentity"
        onClick={event => { if (event.target === dialog.current) close(); }}>
        <div className="ky-about-head">
          <div>
            <h2 className="ky-about-name">KyIdentity{version ? <span className="ky-about-version">v{version}</span> : null}</h2>
            <p className="ky-about-meta">Developed by Busnes.app</p>
            <p className="ky-about-meta">&copy; {year} &middot; Licensed under the MIT License</p>
          </div>
          <button type="button" className="ky-about-close" onClick={close}>Close</button>
        </div>
        <textarea className="ky-about-license" readOnly value={mitLicenseText} aria-label="MIT License" />
      </dialog>
    </footer>
  );
};
