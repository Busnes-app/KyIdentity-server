import { describe, expect, it } from 'vitest';
import { hashFor, tabFromHash } from './route';

describe('hash routes', () => {
  it('opens each view at its own hash', () => {
    expect(tabFromHash('#/admin-users')).toBe('admin-users');
    expect(tabFromHash('#/settings/devices')).toBe('settings/devices');
    expect(tabFromHash('#/settings/appearance')).toBe('settings/appearance');
    expect(tabFromHash(hashFor('settings/account'))).toBe('settings/account');
  });

  it('sends the pages Settings replaced to their tab', () => {
    expect(tabFromHash('#/devices')).toBe('settings/account');
    expect(tabFromHash('#/appearance')).toBe('settings/appearance');
    expect(tabFromHash('#/settings')).toBe('settings/account');
  });

  it('falls back to Applications for an empty or unknown hash', () => {
    expect(tabFromHash('')).toBe('dashboard');
    expect(tabFromHash('#/')).toBe('dashboard');
    expect(tabFromHash('#/settings/nope')).toBe('dashboard');
    expect(tabFromHash('#/constructor')).toBe('dashboard');
    expect(hashFor('dashboard')).toBe('#/');
  });
});
