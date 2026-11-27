import { xwingMarker, xwingPacketBytes, xwingPublicKeyBytes } from './pqCrypto';
import { apiJson, apiRequest, isRecord } from './api';
import { buildHandoffErrorURL, decodeKeyringBytes, handoffKeyLength, isKeyringID } from './keyringCrypto';
import type { RingContext } from './keyringCrypto';

const base = '/api/user/keyring';

export type KeyringAppKey = {
  key_version: number;
  sealed: string;
};

export type KeyringHandoffDetails = RingContext & {
  client_id: string;
  app_name: string;
  redirect_uri: string;
  state: string;
  keyring_pk: string;
  nonce: string;
  wrappers: WrapperInfo[];
  app_key: KeyringAppKey | null;
};

export type KeyringHandoffCompletion = {
  redirect_uri: string;
  code: string;
  state: string;
};

export type KeyringHandoffCancellation = {
  redirect_uri: string;
  state: string;
};

export const ringPaths = {
  status: base,
  wrappers: base + '/wrappers',
  wrapper: (id: string) => base + '/wrappers/' + id,
  recovery: base + '/recovery',
  app: (client: string) => base + '/apps/' + encodeURIComponent(client),
  transfers: base + '/transfers',
  transfer: (id: string) => base + '/transfers/' + id,
  handoff: (id: string) => base + '/handoff/' + encodeURIComponent(id),
  handoffComplete: (id: string) => base + '/handoff/' + encodeURIComponent(id) + '/complete',
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

export function loadHandoff(id: string) {
  return apiJson(ringPaths.handoff(id), (value): KeyringHandoffDetails => {
    const issuer = field(value, 'issuer');
    const org_id = field(value, 'org_id');
    const user_id = field(value, 'user_id');
    const keyring_version = field(value, 'keyring_version');
    const client_id = field(value, 'client_id');
    const app_name = field(value, 'app_name');
    const redirect_uri = field(value, 'redirect_uri');
    const state = field(value, 'state');
    const keyring_pk = field(value, 'keyring_pk');
    handoffKeyLength(keyring_pk);
    const nonce = field(value, 'nonce');
    if (!issuer || !org_id || !user_id || !client_id || !redirect_uri ||
        (keyring_version !== '' && !isKeyringID(keyring_version)) ||
        !isRecord(value) || !Array.isArray(value.wrappers) || value.wrappers.length > 17) {
      throw new Error('Invalid handoff response.');
    }

    let app_key: KeyringAppKey | null = null;
    if (value.app_key !== null && value.app_key !== undefined) {
      if (!isRecord(value.app_key) || !Number.isSafeInteger(value.app_key.key_version) ||
          Number(value.app_key.key_version) < 1 || Number(value.app_key.key_version) > 2147483647 ||
          typeof value.app_key.sealed !== 'string') {
        throw new Error('Invalid app key response.');
      }
      if (value.app_key.sealed !== '') decodeKeyringBytes(value.app_key.sealed, 60);
      app_key = { key_version: Number(value.app_key.key_version), sealed: value.app_key.sealed };
    }

    return {
      issuer,
      org_id,
      user_id,
      keyring_version,
      client_id,
      app_name: app_name || client_id,
      redirect_uri,
      state,
      keyring_pk,
      nonce,
      wrappers: value.wrappers.map(wrapperInfo),
      app_key,
    };
  });
}

export function completeHandoff(id: string) {
  return apiJson(ringPaths.handoffComplete(id), (value): KeyringHandoffCompletion => ({
    redirect_uri: field(value, 'redirect_uri'),
    code: field(value, 'code'),
    state: field(value, 'state'),
  }), { method: 'POST' });
}

export function cancelHandoff(id: string) {
  return apiJson(ringPaths.handoff(id), (value): KeyringHandoffCancellation => ({
    redirect_uri: field(value, 'redirect_uri'),
    state: field(value, 'state'),
  }), { method: 'DELETE' });
}

// Outcome of completing a handoff. `retry`: the interaction was not consumed, so the
// page may load it again. `restart`: it was consumed; only a fresh sign-in from the app
// helps. `restart` is the app's error redirect (no code) or null if even that is invalid.
export type HandoffOutcome =
  | { kind: 'redirect'; target: string }
  | { kind: 'retry'; error: unknown }
  | { kind: 'restart'; error: unknown; restart: string | null };

export async function finishHandoff(
  complete: () => Promise<KeyringHandoffCompletion>,
  build: (done: KeyringHandoffCompletion) => Promise<string> | string,
): Promise<HandoffOutcome> {
  let done: KeyringHandoffCompletion;
  try {
    done = await complete();
  } catch (error) {
    return { kind: 'retry', error };
  }
  try {
    return { kind: 'redirect', target: await build(done) };
  } catch (error) {
    return { kind: 'restart', error, restart: restartURL(done) };
  }
}

// OAuth error redirect (no code) telling the app to start a fresh sign-in; null if unusable.
export function restartURL(target: { redirect_uri: string; state: string }): string | null {
  try {
    return buildHandoffErrorURL(target.redirect_uri, target.state, 'server_error', 'Keyring handoff failed. Sign in again.');
  } catch {
    return null;
  }
}

export function saveAppKey(client: string, payload: KeyringAppKey & Pick<RingContext, 'keyring_version'>, stepUpToken?: string) {
  return apiRequest(ringPaths.app(client), {
    method: 'PUT',
    stepUpToken,
    body: JSON.stringify(payload),
  });
}

export function readTransfer(id: string) {
  return apiJson(ringPaths.transfer(id), value => ({
    recipient_key: encoded(value, 'recipient_key', xwingPublicKeyBytes),
    request_mac: encoded(value, 'request_mac', 32),
    user_agent: field(value, 'user_agent'),
    ip_address: field(value, 'ip_address'),
    signed_in_at: isRecord(value) && Number.isSafeInteger(value.signed_in_at) ? Number(value.signed_in_at) : 0,
  }));
}

export function claimTransfer(id: string) {
  return apiJson(ringPaths.transfer(id) + '/claim', value => ({
    sender_key: (() => {
      const marker = field(value, 'sender_key');
      if (marker !== xwingMarker) throw new Error('Unsupported transfer format. Reload both browsers.');
      return marker;
    })(),
    sealed: encoded(value, 'sealed', xwingPacketBytes),
  }), { method: 'POST' });
}

export function writeRing(path: string, method: 'POST' | 'PUT' | 'DELETE', body?: object, stepUpToken?: string, capability?: string) {
  return apiRequest(path, {
    method, stepUpToken, body: body === undefined ? undefined : JSON.stringify(body),
    headers: capability ? { 'X-Ky-Keyring-Device': capability } : undefined,
  });
}
