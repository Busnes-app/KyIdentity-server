import { afterEach, describe, expect, it, vi } from 'vitest';
import { createPasskey, fromBase64Url, toBase64Url } from './webauthn';

describe('base64url codecs', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    expect(Array.from(fromBase64Url(toBase64Url(bytes.buffer)))).toEqual(Array.from(bytes));
  });

  it('encodes to the exact base64url form (no padding, URL-safe alphabet)', () => {
    // Concrete output: [251, 255, 190, 254] → '-_--_g'
    // Standard base64 would be '+/++/g=='; base64url unpadded is '-_--_g'
    const bytes = new Uint8Array([251, 255, 190, 254]);
    const encoded = toBase64Url(bytes.buffer);
    expect(encoded).toBe('-_--_g');
    expect(encoded).not.toContain('=');
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
  });

  it('decodes base64url strings with URL-safe alphabet back to bytes', () => {
    // Exercise the alphabet-restore branch: '-_--_g' → [251, 255, 190, 254]
    const decoded = fromBase64Url('-_--_g');
    expect(Array.from(decoded)).toEqual([251, 255, 190, 254]);
  });

  it('decodes a string the server would have produced', () => {
    expect(new TextDecoder().decode(fromBase64Url('Q0hBTExFTkdF'))).toBe('CHALLENGE');
  });
});

describe('createPasskey', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('sends the attestation object the server verifies', async () => {
    const create = vi.fn().mockResolvedValue({
      rawId: new Uint8Array([1, 2]).buffer,
      response: { attestationObject: new Uint8Array([3, 4]).buffer, clientDataJSON: new Uint8Array([5]).buffer },
    });
    vi.stubGlobal('navigator', { credentials: { create } });

    const finished = await createPasskey({
      challenge: 'Q0hBTExFTkdF', rpId: 'auth.example.com', rpName: 'KyIdentity',
      userHandle: 'dXNlcg', username: 'user', excludeCredentials: [],
    });

    expect(finished).toEqual({ credentialId: 'AQI', attestationObject: 'AwQ', clientDataJSON: 'BQ' });
    expect(create.mock.calls[0][0].publicKey.attestation).toBe('none');
  });
});
