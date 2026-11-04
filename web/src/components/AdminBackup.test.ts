import { afterEach, describe, expect, it, vi } from 'vitest';
import { copyText, scheduleFact } from './AdminBackup';
import type { BackupStatus } from '../types';

const ready: BackupStatus = {
  paired: true, keyPinned: true, intervalSec: 86400, nextRunAt: '2026-10-31T12:00:00Z',
  localCopies: [], members: [], app_name: 'KySignOn', app_version: '',
};

describe('backup schedule fact', () => {
  it('waits for a recovery key instead of promising a next run', () => {
    expect(scheduleFact({ ...ready, keyPinned: false, paired: false })).toEqual({ badge: 'danger', text: 'Waiting for recovery key' });
  });
  it('waits for a destination when a key is pinned but nothing is paired or local', () => {
    expect(scheduleFact({ ...ready, paired: false })).toEqual({ badge: 'danger', text: 'Waiting for a destination' });
  });
  it('shows the next run only when a backup can actually run', () => {
    expect(scheduleFact(ready).badge).toBe('success');
    expect(scheduleFact(ready).text).toMatch(/^Next /);
    expect(scheduleFact({ ...ready, paired: false, localDir: '/backups' }).badge).toBe('success');
  });
  it('says manual only with no schedule', () => {
    expect(scheduleFact({ ...ready, intervalSec: 0 })).toEqual({ badge: 'warning', text: 'Manual only' });
    expect(scheduleFact(null).text).toBe('Manual only');
  });
});

describe('copying the capsule digest', () => {
  afterEach(() => { vi.unstubAllGlobals(); });
  it('reports a copy only when the clipboard took it', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    expect(await copyText('abc')).toBe(true);
    expect(writeText).toHaveBeenCalledWith('abc');
  });
  it('reports failure where the clipboard refuses or does not exist (plain http)', async () => {
    vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn().mockRejectedValue(new Error('denied')) } });
    expect(await copyText('abc')).toBe(false);
    vi.stubGlobal('navigator', {});
    expect(await copyText('abc')).toBe(false);
  });
});
