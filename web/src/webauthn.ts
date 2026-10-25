/**
 * Browser half of the WebAuthn ceremonies. The server speaks base64url everywhere, so
 * every ArrayBuffer crossing the wire goes through these two codecs and nothing else.
 */

export function toBase64Url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function isPasskeySupported(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential;
}

export interface BeginRegistration {
  challenge: string;
  rpId: string;
  rpName: string;
  userHandle: string;
  username: string;
  excludeCredentials: string[];
}

export interface FinishRegistration {
  credentialId: string;
  attestationObject: string;
  clientDataJSON: string;
}

/** ES256. The server verifies nothing else, so nothing else is offered. */
const ES256 = -7;

export async function createPasskey(opts: BeginRegistration): Promise<FinishRegistration> {
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: fromBase64Url(opts.challenge),
      rp: { id: opts.rpId, name: opts.rpName },
      user: {
        id: fromBase64Url(opts.userHandle),
        name: opts.username,
        displayName: opts.username,
      },
      pubKeyCredParams: [{ type: 'public-key', alg: ES256 }],
      // Attestation is not trusted server-side, so requesting it would only add a
      // consent prompt for data nobody acts on.
      attestation: 'none',
      authenticatorSelection: { userVerification: 'preferred', residentKey: 'preferred' },
      excludeCredentials: opts.excludeCredentials.map((id) => ({
        type: 'public-key' as const,
        id: fromBase64Url(id),
      })),
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('Passkey creation was cancelled');

  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    credentialId: toBase64Url(credential.rawId),
    attestationObject: toBase64Url(response.attestationObject),
    clientDataJSON: toBase64Url(response.clientDataJSON),
  };
}

export interface BeginLogin {
  challenge: string;
  rpId: string;
  allowCredentials: string[];
}

export interface FinishAssertion {
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
}

export async function getPasskeyAssertion(opts: BeginLogin, signal?: AbortSignal): Promise<FinishAssertion> {
  const credential = await navigator.credentials.get({
    signal,
    publicKey: {
      challenge: fromBase64Url(opts.challenge),
      rpId: opts.rpId,
      allowCredentials: opts.allowCredentials.map((id) => ({
        type: 'public-key' as const,
        id: fromBase64Url(id),
      })),
      userVerification: 'preferred',
      timeout: 120_000,
    },
  });

  if (!(credential instanceof PublicKeyCredential)) throw new Error('Passkey sign-in was cancelled');

  const response = credential.response;
  if (!(response instanceof AuthenticatorAssertionResponse)) throw new Error('Invalid passkey assertion');
  return {
    credentialId: toBase64Url(credential.rawId),
    authenticatorData: toBase64Url(response.authenticatorData),
    clientDataJSON: toBase64Url(response.clientDataJSON),
    signature: toBase64Url(response.signature),
  };
}
