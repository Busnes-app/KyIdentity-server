import { describe, expect, it } from 'vitest';
import { scheduleFact } from './AdminBackup';
import type { BackupStatus } from '../types';

const ready: BackupStatus = {
  paired: true, keyPinned: true, intervalSec: 86400, nextRunAt: '2026-10-31T12:00:00Z',
  localCopies: [], members: [], app_name: 'KySignOn', app_version: '',
};

describe('backup schedule fact', () => {
  it('waits for a recovery key instead of promising a next run', () => {
    expect(scheduleFact({ ...ready, keyPinned: false, paired: false })).toEqual({ badge: 'disabled', text: 'Waiting for recovery key' });
  });
  it('waits for a destination when a key is pinned but nothing is paired or local', () => {
    expect(scheduleFact({ ...ready, paired: false })).toEqual({ badge: 'disabled', text: 'Waiting for a destination' });
  });
  it('shows the next run only when a backup can actually run', () => {
    expect(scheduleFact(ready).badge).toBe('active');
    expect(scheduleFact(ready).text).toMatch(/^Next /);
    expect(scheduleFact({ ...ready, paired: false, localDir: '/backups' }).badge).toBe('active');
  });
  it('says manual only with no schedule', () => {
    expect(scheduleFact({ ...ready, intervalSec: 0 })).toEqual({ badge: 'warn', text: 'Manual only' });
    expect(scheduleFact(null).text).toBe('Manual only');
  });
});
