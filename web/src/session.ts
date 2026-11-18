import type { User } from './types';

export type SessionState =
  | { kind: 'signedIn'; user: User }
  | { kind: 'signedOut' }
  | { kind: 'unavailable' };

// An unreadable session keeps a known user. A confirmed sign-out always replaces it.
export function nextSession(current: SessionState, result: SessionState): SessionState {
  return result.kind === 'unavailable' && current.kind === 'signedIn' ? current : result;
}
