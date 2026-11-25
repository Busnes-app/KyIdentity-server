import { describe, expect, it } from 'vitest';
import {
  approveTransfer, decodeKeyringBytes, encodeKeyringBytes, formatRecoveryKey,
  importKeyringSecret, newKeyringSecret, newTransfer, newWrappedAppKey, openTransfer,
  parseRecoveryKey, parseTransferCode, transferCode, unwrapAppKey, unwrapRoot, wrapRoot,
} from './keyringCrypto';
import type { RingContext, WrapperBinding } from './keyringCrypto';

const context: RingContext = {
  issuer: 'https://identity.example.test', org_id: 'org-A', user_id: 'subject-55',
  keyring_version: '26142ca4-a93c-4dc3-b314-dad35b7fb82f',
};
const binding: WrapperBinding = {
  context, id: '370e28b9-4b06-4e4d-89a6-081dd13be902', kind: 'device',
};
const vector = 'AAECAwQFBgcICQoLMz7A_2Rr9hoImes4Y1C8cOGmq38Ljj1PxG5ie_yBTGwUUtQEQ9mrL5xDJQ8dF-vu';

function tamper(sealed: string) {
  const bytes = decodeKeyringBytes(sealed, 60);
  bytes[30] ^= 0x80;
  return encodeKeyringBytes(bytes);
}

describe('Suite keyring wire v1', () => {
  it('generates independent 256-bit roots and wraps them with non-extractable browser material', async () => {
    const root = newKeyringSecret();
    expect(root).toHaveLength(32);
    expect(root).not.toEqual(newKeyringSecret());
    const device = await importKeyringSecret(newKeyringSecret());
    expect(device.extractable).toBe(false);
    const sealed = await wrapRoot(binding, device, root);
    expect(await wrapRoot(binding, device, root)).not.toBe(sealed);
    expect(await unwrapRoot(binding, device, sealed)).toEqual(root);
  });

  it('opens the fixed interoperability vector and authenticates every wrapper coordinate', async () => {
    const device = await importKeyringSecret(new Uint8Array(32).fill(17));
    expect(await unwrapRoot(binding, device, vector)).toEqual(new Uint8Array(32).fill(34));
    for (const key of ['issuer', 'org_id', 'user_id', 'keyring_version'] as const) {
      await expect(unwrapRoot({ ...binding, context: { ...context, [key]: 'elsewhere' } }, device, vector)).rejects.toThrow();
    }
    for (const changed of [{ ...binding, id: crypto.randomUUID() }, { ...binding, kind: 'recovery' } as const]) {
      await expect(unwrapRoot(changed, device, vector)).rejects.toThrow();
    }
    await expect(unwrapRoot(binding, device, tamper(vector))).rejects.toThrow();
  });

  it('restores solely from a printable kit and replaces the recovery key on rotation', async () => {
    const root = newKeyringSecret();
    const recovery = newKeyringSecret();
    const kit = formatRecoveryKey(recovery);
    expect(kit).toMatch(/^KYR1(?:-[0-9A-F]{8}){8}$/);
    const wire = { ...binding, kind: 'recovery' } as const;
    const sealed = await wrapRoot(wire, await importKeyringSecret(recovery), root);
    const reopened = await importKeyringSecret(parseRecoveryKey(' ' + kit.toLowerCase() + '\n'));
    expect(await unwrapRoot(wire, reopened, sealed)).toEqual(root);
    expect(() => parseRecoveryKey(kit.slice(0, -1))).toThrow();
    const rotated = await wrapRoot(wire, await importKeyringSecret(newKeyringSecret()), root);
    await expect(unwrapRoot(wire, reopened, rotated)).rejects.toThrow();
  });

  it('keeps application wrapping keys and random subkeys isolated by app and version', async () => {
    const root = newKeyringSecret();
    const app = { context, client: 'app-a', version: 1 };
    const issued = await newWrappedAppKey(app, root);
    expect(issued.subkey).not.toEqual(root);
    expect(await unwrapAppKey(app, root, issued.sealed)).toEqual(issued.subkey);
    const next = await newWrappedAppKey({ ...app, version: 2 }, root);
    expect(next.subkey).not.toEqual(issued.subkey);
    await expect(unwrapAppKey({ ...app, version: 2 }, root, issued.sealed)).rejects.toThrow();
    await expect(unwrapAppKey({ ...app, client: 'app-b' }, root, issued.sealed)).rejects.toThrow();
    await expect(unwrapAppKey(app, issued.subkey, issued.sealed)).rejects.toThrow();
  });

  it('authenticates recipient and sender keys, approval code, ring and ciphertext', async () => {
    const root = newKeyringSecret();
    const receiving = await newTransfer(context);
    const unrelated = await newTransfer(context);
    expect(receiving.privateKey.extractable).toBe(false);
    const code = parseTransferCode(transferCode(receiving));
    const response = await approveTransfer(context, code, receiving.request, root);
    expect(await openTransfer(context, receiving, response)).toEqual(root);
    await expect(approveTransfer(context, code, { ...receiving.request, recipient_key: unrelated.request.recipient_key }, root)).rejects.toThrow();
    await expect(approveTransfer(context, { ...code, secret: unrelated.secret }, receiving.request, root)).rejects.toThrow();
    await expect(approveTransfer({ ...context, org_id: 'other' }, code, receiving.request, root)).rejects.toThrow();
    await expect(openTransfer(context, unrelated, response)).rejects.toThrow();
    await expect(openTransfer(context, receiving, { ...response, sealed: tamper(response.sealed) })).rejects.toThrow();
    await expect(openTransfer(context, receiving, { ...response, sender_key: unrelated.request.recipient_key })).rejects.toThrow();
  });
});
