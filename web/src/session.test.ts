import { describe, expect, it } from 'vitest';
import { nextSession, type SessionState } from './session';

const signedIn: SessionState = {
  kind: 'signedIn',
  user: { id: 'u1', username: 'sam', displayName: 'Sam', email: 'sam@example.test', role: 'user' },
};

describe('session checks and confirmed sign-out', () => {
  it('keeps a known user through an unreadable check, then honours a logout or 401', () => {
    const failedCheck = nextSession(signedIn, { kind: 'unavailable' });
    expect(failedCheck).toEqual(signedIn);
    const signedOut = nextSession(failedCheck, { kind: 'signedOut' });
    expect(signedOut).toEqual({ kind: 'signedOut' });
    // A delayed failed check must not revive the old user's identity.
    expect(nextSession(signedOut, { kind: 'unavailable' })).toEqual({ kind: 'unavailable' });
  });

  it('retries an unreadable initial check, then accepts a real session or signed-out answer', () => {
    const unavailable = nextSession({ kind: 'signedOut' }, { kind: 'unavailable' });
    expect(unavailable).toEqual({ kind: 'unavailable' });
    expect(nextSession(unavailable, signedIn)).toEqual(signedIn);
    expect(nextSession(unavailable, { kind: 'signedOut' })).toEqual({ kind: 'signedOut' });
  });
});
