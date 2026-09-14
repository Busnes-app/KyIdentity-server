import { describe, expect, it } from 'vitest';
import { describeInstant, instantFromLocal, localInputValue } from './instant';

describe('instants', () => {
  it('turns a local wall-clock entry into one UTC instant and back', () => {
    const local = '2026-06-01T09:30';
    const iso = instantFromLocal(local);
    expect(iso).toMatch(/Z$/);
    expect(localInputValue(iso)).toBe(local);
  });

  it('treats an empty or unparseable entry as no instant rather than inventing one', () => {
    expect(instantFromLocal('')).toBeUndefined();
    expect(instantFromLocal('not a time')).toBeUndefined();
    expect(localInputValue(undefined)).toBe('');
  });

  it('always shows the exact instant next to the local reading', () => {
    const iso = '2026-06-01T07:30:00.000Z';
    expect(describeInstant(iso)).toContain(iso);
  });
});
