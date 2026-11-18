import React from 'react';
import { AlertCircle } from 'lucide-react';

/** Shown when the session could not be checked: the server did not answer, so the browser
 * may well still be signed in, and the sign-in screen would be wrong. */
export const SessionUnavailable: React.FC<{ onRetry: () => void }> = ({ onRetry }) => (
  <div className="loading-screen" role="alert">
    <AlertCircle className="icon-cyan" size={32} />
    <p className="loading-text">KyIdentity could not check your session. Try again to find out whether you are signed in.</p>
    <button type="button" className="secondary-btn" onClick={onRetry}>Try again</button>
  </div>
);
