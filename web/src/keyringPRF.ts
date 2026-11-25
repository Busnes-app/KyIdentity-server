import { encodeKeyringBytes, importKeyringSecret, newKeyringSecret } from './keyringCrypto';

async function prfInput() {
  const input = new TextEncoder().encode('ky-keyring/1:webauthn-prf');
  return { first: await crypto.subtle.digest('SHA-256', input) };
}

function prfSecret(credential: PublicKeyCredential) {
  const result = credential.getClientExtensionResults().prf?.results?.first;
  if (result instanceof ArrayBuffer && result.byteLength === 32) return new Uint8Array(result);
  if (ArrayBuffer.isView(result) && result.byteLength === 32) {
    return Uint8Array.from(new Uint8Array(result.buffer, result.byteOffset, result.byteLength));
  }
}

async function prfMaterial(credential: PublicKeyCredential) {
  const secret = prfSecret(credential);
  if (!secret) throw new Error('This browser or passkey did not return a PRF result.');
  return importKeyringSecret(secret).finally(() => secret.fill(0));
}

export async function keyringPRFAvailable() {
  if (typeof PublicKeyCredential === 'undefined') return false;
  if (typeof PublicKeyCredential.getClientCapabilities !== 'function') return true;
  const capabilities = await PublicKeyCredential.getClientCapabilities();
  return capabilities['extension:prf'] !== false;
}

export async function newKeyringPasskey(userID: string, username: string) {
  const credential = await navigator.credentials.create({ publicKey: {
    challenge: newKeyringSecret(),
    rp: { name: 'KyIdentity Suite keyring' },
    user: { id: new TextEncoder().encode(userID), name: username, displayName: username + ' (Suite keyring)' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { residentKey: 'discouraged', userVerification: 'required' },
    extensions: { prf: { eval: await prfInput() } },
    attestation: 'none',
    timeout: 60_000,
  } });
  if (!(credential instanceof PublicKeyCredential) || credential.rawId.byteLength < 1 || credential.rawId.byteLength > 768) {
    throw new Error('The keyring passkey was not created.');
  }
  const extension = credential.getClientExtensionResults().prf;
  if (extension?.results?.first) return { credential_id: encodeKeyringBytes(new Uint8Array(credential.rawId)), secret: await prfMaterial(credential) };
  if (!extension?.enabled) throw new Error('This passkey does not support PRF. Use a trusted browser or your Emergency Kit.');
  return {
    credential_id: encodeKeyringBytes(new Uint8Array(credential.rawId)),
    secret: await getKeyringPasskey(new Uint8Array(credential.rawId)),
  };
}

export async function getKeyringPasskey(id: Uint8Array<ArrayBuffer>) {
  const credential = await navigator.credentials.get({ publicKey: {
    challenge: newKeyringSecret(), allowCredentials: [{ id, type: 'public-key' }], userVerification: 'required',
    extensions: { prf: { eval: await prfInput() } }, timeout: 60_000,
  } });
  if (!(credential instanceof PublicKeyCredential) || encodeKeyringBytes(new Uint8Array(credential.rawId)) !== encodeKeyringBytes(id)) {
    throw new Error('Select the passkey registered for this keyring.');
  }
  return prfMaterial(credential);
}
