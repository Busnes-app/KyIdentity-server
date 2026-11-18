import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { AdminBackup, BackupFacts } from './AdminBackup';
import { SessionUnavailable } from './SessionUnavailable';
import type { BackupStatus } from '../types';

const unpaired: BackupStatus = {
  paired: false, keyPinned: false, intervalSec: 0, localCopies: [], members: [], app_name: 'KySignOn', app_version: '',
};

// What an unpaired, unpinned install looks like; none of it may appear while unknown.
const offStates = ['Not paired', '>None<', 'No off-site copy', 'Nothing can be sealed', 'KYIDENTITY_BACKUP_DIR not set', 'Manual only'];

describe('backup status that has not been read', () => {
  it('shows every fact as unknown, never as unpaired or unpinned', () => {
    for (const loading of [true, false]) {
      const html = renderToStaticMarkup(<BackupFacts status={null} loading={loading} />);
      for (const off of offStates) expect(html).not.toContain(off);
      expect(html.match(/>Unknown</g)?.length).toBe(4);
      expect(html).toContain(loading ? 'Loading the backup status' : 'The backup status could not be read');
    }
  });
  it('still shows a status that was read as unpaired', () => {
    const html = renderToStaticMarkup(<BackupFacts status={unpaired} loading={false} />);
    for (const off of ['Not paired', '>None<', 'No off-site copy', 'Nothing can be sealed', 'KYIDENTITY_BACKUP_DIR not set']) expect(html).toContain(off);
    expect(html).not.toContain('>Unknown<');
  });
  it('offers no pairing, pinning or schedule change before the status is known', () => {
    // A static render is the page before its first status read has answered.
    const html = renderToStaticMarkup(<AdminBackup />);
    for (const off of offStates) expect(html).not.toContain(off);
    for (const control of ['id="recovery-url"', 'id="pairing-code"', 'id="pin-key"', '>Pin key<', '>Pair<', '>Unpair<']) expect(html).not.toContain(control);
    expect(html).toMatch(/<button type="submit" class="primary-btn sm" disabled="">.*?<span>Save<\/span>/);
    expect(html).toMatch(/<button type="button" class="primary-btn sm" disabled="">.*?Back up now/);
  });
});

describe('a session that could not be checked', () => {
  it('offers a retry and says the browser is still signed in, with no sign-in form', () => {
    const html = renderToStaticMarkup(<SessionUnavailable onRetry={() => {}} />);
    expect(html).toContain('Try again');
    expect(html).toContain('You have not been signed out');
    expect(html).not.toMatch(/password|Sign in/i);
  });
});
