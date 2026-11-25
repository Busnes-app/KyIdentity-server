import { apiJson, apiRequest, isRecord } from './api';
import { decodeKeyringBytes, isKeyringID } from './keyringCrypto';
import type { RingContext } from './keyringCrypto';

const base = '/api/user/keyring';

export const ringPaths = {
  status: base,
  wrappers: base + '/wrappers',
  wrapper: (id: string) => base + '/wrappers/' + id,
  recovery: base + '/recovery',
  transfers: base + '/transfers',
  transfer: (id: string) => base + '/transfers/' + id,
};

function field(value: unknown, name: string) {
  if (!isRecord(value) || typeof value[name] !== 'string') throw new Error('Invalid keyring response.');
  return value[name];
}

function encoded(value: unknown, name: string, length: number) {
  const result = field(value, name);
  decodeKeyringBytes(result, length);
  return result;
}

export function credentialBytes(credential: string) {
  const length = Math.floor(credential.length * 6 / 8);
  if (length < 1 || length > 768) throw new Error('Invalid passkey credential ID.');
  return decodeKeyringBytes(credential, length);
}

function wrapperInfo(value: unknown) {
  const id = field(value, 'id');
  if (!isKeyringID(id)) throw new Error('Invalid wrapper ID.');
  const kind = field(value, 'kind');
  switch (kind) {
    case 'device': return { kind, id } as const;
    case 'recovery': return { kind, id } as const;
    case 'prf': {
      const credential_id = field(value, 'credential_id');
      credentialBytes(credential_id);
      return { kind, id, credential_id } as const;
    }
    default: throw new Error('Unknown wrapper type.');
  }
}

export type WrapperInfo = ReturnType<typeof wrapperInfo>;
export type RingStatus = RingContext & { wrappers: WrapperInfo[] };

export function loadRing() {
  return apiJson(ringPaths.status, (value): RingStatus => {
    const issuer = field(value, 'issuer');
    const org_id = field(value, 'org_id');
    const user_id = field(value, 'user_id');
    const keyring_version = field(value, 'keyring_version');
    if (!issuer || !org_id || !user_id || (keyring_version !== '' && !isKeyringID(keyring_version)) ||
        !isRecord(value) || !Array.isArray(value.wrappers) || value.wrappers.length > 17) throw new Error('Invalid keyring status.');
    return { issuer, org_id, user_id, keyring_version, wrappers: value.wrappers.map(wrapperInfo) };
  });
}

export function fetchWrapper(info: WrapperInfo, capability?: string) {
  return apiJson(ringPaths.wrapper(info.id), value => {
    const wrapper = wrapperInfo(value);
    if (wrapper.id !== info.id || wrapper.kind !== info.kind) throw new Error('This wrapper has changed.');
    return encoded(value, 'sealed', 60);
  }, { headers: capability ? { 'X-Ky-Keyring-Device': capability } : undefined });
}

export function readTransfer(id: string) {
  return apiJson(ringPaths.transfer(id), value => ({
    recipient_key: encoded(value, 'recipient_key', 65),
    request_mac: encoded(value, 'request_mac', 32),
    user_agent: field(value, 'user_agent'),
    ip_address: field(value, 'ip_address'),
    signed_in_at: isRecord(value) && Number.isSafeInteger(value.signed_in_at) ? Number(value.signed_in_at) : 0,
  }));
}

export function claimTransfer(id: string) {
  return apiJson(ringPaths.transfer(id) + '/claim', value => ({
    sender_key: encoded(value, 'sender_key', 65),
    sealed: encoded(value, 'sealed', 60),
  }), { method: 'POST' });
}

export function writeRing(path: string, method: 'POST' | 'PUT' | 'DELETE', body?: object, stepUpToken?: string, capability?: string) {
  return apiRequest(path, {
    method, stepUpToken, body: body === undefined ? undefined : JSON.stringify(body),
    headers: capability ? { 'X-Ky-Keyring-Device': capability } : undefined,
  });
}
