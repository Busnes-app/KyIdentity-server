import { newDeviceCapability, newKeyringSecret, importKeyringSecret, keyringScope, wrapRoot } from './keyringCrypto';
import type { RingContext } from './keyringCrypto';

type Device = { id: string; scope: string; secret: CryptoKey; capability: string };

function openDevices(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('kyidentity-keyring', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('devices', { keyPath: 'id' });
    request.onsuccess = () => resolve(request.result);
    request.onblocked = () => reject(new Error('Close other KyIdentity tabs and try again.'));
    request.onerror = () => reject(new Error('This browser could not open its keyring storage.'));
  });
}

async function deviceRequest<T>(mode: IDBTransactionMode, operation: (store: IDBObjectStore) => IDBRequest<T>) {
  const db = await openDevices();
  try {
    return await new Promise<unknown>((resolve, reject) => {
      const tx = db.transaction('devices', mode);
      const request = operation(tx.objectStore('devices'));
      tx.oncomplete = () => resolve(request.result);
      tx.onabort = () => reject(new Error('This browser could not access its saved device key.'));
    });
  } finally {
    db.close();
  }
}

export async function findKeyringDevice(context: RingContext, deviceIDs: string[]): Promise<Device | undefined> {
  const scope = JSON.stringify(keyringScope(context));
  for (const id of deviceIDs) {
    const value = await deviceRequest('readonly', store => store.get(id));
    if (value && typeof value === 'object' && 'id' in value && value.id === id && 'scope' in value && value.scope === scope &&
        'secret' in value && value.secret instanceof CryptoKey && 'capability' in value && typeof value.capability === 'string') {
      return { id, scope, secret: value.secret, capability: value.capability };
    }
  }
}

export async function createKeyringDevice(context: RingContext, root: Uint8Array<ArrayBuffer>) {
  const id = crypto.randomUUID();
  const bytes = newKeyringSecret();
  const secret = await importKeyringSecret(bytes).finally(() => bytes.fill(0));
  const { capability, device_hash } = await newDeviceCapability();
  const sealed = await wrapRoot({ context, id, kind: 'device' }, secret, root);
  // Persist before the server can commit. An ambiguous network response leaves the
  // device usable if its ID appears in the next status response.
  const device = { id, scope: JSON.stringify(keyringScope(context)), secret, capability } satisfies Device;
  await deviceRequest('readwrite', store => store.add(device));
  return { device, wrapper: { id, kind: 'device', sealed, device_hash } };
}

export async function forgetKeyringDevice(id: string) {
  await deviceRequest('readwrite', store => store.delete(id));
}
