import { describe, expect, it } from 'vitest';
import { keepStorage } from './persist';

const storage = (persisted: boolean, granted: boolean) => {
  const asked: string[] = [];
  return {
    asked,
    persisted: async () => { asked.push('persisted'); return persisted; },
    persist: async () => { asked.push('persist'); return granted; },
  };
};

describe('keepStorage', () => {
  it('does not ask again once storage is kept', async () => {
    const kept = storage(true, false);
    expect(await keepStorage(kept)).toBe(true);
    expect(kept.asked).toEqual(['persisted']);
  });
  it("asks once, and reports the browser's answer", async () => {
    const granted = storage(false, true);
    expect(await keepStorage(granted)).toBe(true);
    expect(granted.asked).toEqual(['persisted', 'persist']);
    expect(await keepStorage(storage(false, false))).toBe(false);
  });
  it('is false without the API, or when the browser throws', async () => {
    expect(await keepStorage(undefined)).toBe(false);
    expect(await keepStorage({})).toBe(false);
    expect(await keepStorage({ persisted: async () => { throw new Error('no'); }, persist: async () => true })).toBe(false);
  });
});
