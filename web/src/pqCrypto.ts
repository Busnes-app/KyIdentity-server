import wasmURL from '../.pq/pq.wasm?url';
import runtimeURL from '../.pq/wasm_exec.js?url';

// pqwasm returns error objects at its JS boundary. Keep unvalidated results unknown.
type PQ = {
  xwingGenerate: () => unknown;
  xwingSeal: (key: Uint8Array, info: Uint8Array, aad: Uint8Array, msg: Uint8Array) => unknown;
  xwingOpen: (seed: Uint8Array, info: Uint8Array, aad: Uint8Array, packet: Uint8Array) => unknown;
};
declare global {
  var pqwasm: PQ | undefined;
  var Go: new () => { importObject: WebAssembly.Imports; run: (instance: WebAssembly.Instance) => Promise<void> };
}

let loading: Promise<PQ> | undefined;
export function loadPQ(): Promise<PQ> {
  // Tests start the real Go runtime before importing the crypto consumers.
  if (globalThis.pqwasm) return Promise.resolve(globalThis.pqwasm);
  return loading ??= (async () => {
    await new Promise<void>((resolve, reject) => {
      const script = document.createElement('script');
      script.src = runtimeURL;
      script.onload = () => resolve();
      script.onerror = () => reject(new Error('Could not load keyring cryptography. Reload and try again.'));
      document.head.append(script);
    });
    const go = new Go();
    const response = await fetch(wasmURL);
    if (!response.ok) throw new Error('Could not load keyring cryptography.');
    const { instance } = await WebAssembly.instantiate(await response.arrayBuffer(), go.importObject);
    // Go registers pqwasm synchronously before blocking; the run promise lasts for the page.
    void go.run(instance);
    if (!globalThis.pqwasm) throw new Error('Keyring cryptography did not start.');
    return globalThis.pqwasm;
  })();
}

function bytes(value: unknown, length: number): Uint8Array<ArrayBuffer> {
  if (!(value instanceof Uint8Array) || value.length !== length) throw new Error('Invalid X-Wing key or ciphertext.');
  return new Uint8Array(value);
}

export const xwingMarker = 'xwing:1';
export const xwingPublicKeyBytes = 1216;
export const xwingPacketBytes = 1 + 1120 + 32 + 16;

export async function newXwingPair() {
  const value = (await loadPQ()).xwingGenerate();
  if (!value || typeof value !== 'object' || !('seed' in value) || !('publicKey' in value)) {
    throw new Error('Could not generate an X-Wing key.');
  }
  return { privateKey: bytes(value.seed, 32), publicKey: bytes(value.publicKey, xwingPublicKeyBytes) };
}

export async function sealXwing(key: Uint8Array, info: Uint8Array, aad: Uint8Array, msg: Uint8Array) {
  if (msg.length !== 32) throw new Error('Invalid keyring secret length.');
  return bytes((await loadPQ()).xwingSeal(key, info, aad, msg), xwingPacketBytes);
}

export async function openXwing(seed: Uint8Array, info: Uint8Array, aad: Uint8Array, packet: Uint8Array) {
  return bytes((await loadPQ()).xwingOpen(seed, info, aad, packet), 32);
}
