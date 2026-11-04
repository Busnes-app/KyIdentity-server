import { describe, expect, it } from 'vitest';
import { unsentPushNotice } from './LoginView';

describe('a sign-in that sent no push', () => {
  // A phone-only user retrying while a push waits must learn why no request arrived.
  it('explains a push method with no challenge, and nothing else', () => {
    expect(unsentPushNotice({ mfaMethods: ['push'] })).toContain('Wait a few minutes');
    expect(unsentPushNotice({ mfaMethods: ['push'], challengeId: 'c1' })).toBeNull();
    expect(unsentPushNotice({ mfaMethods: ['totp'] })).toBeNull();
  });
});
