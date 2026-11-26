import { describe, expect, it } from 'vitest';
import {
  approveTransfer, buildHandoffErrorURL, buildHandoffRedirectURL, decodeKeyringBytes,
  encodeKeyringBytes, formatRecoveryKey, importKeyringSecret, newHandoffPair,
  newKeyringSecret, newTransfer, newWrappedAppKey, openHandoffKey, openTransfer,
  parseRecoveryKey, parseTransferCode, sealHandoffKey, transferCode, unwrapAppKey,
  unwrapRoot, wrapRoot,
} from './keyringCrypto';
import type { HandoffBinding, RingContext, WrapperBinding } from './keyringCrypto';

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

  it('seals and opens cross-origin OIDC app subkeys bound to code, client, redirect URI and keys', async () => {
    const appKey = newKeyringSecret();
    const recipient = await newHandoffPair();
    const unrelated = await newHandoffPair();
    expect(recipient.privateKey.extractable).toBe(false);

    const handoff: HandoffBinding = {
      context,
      client: 'kypost',
      version: 1,
      code: 'auth-code-12345',
      redirect_uri: 'https://mail.example/cb',
      recipient_key: recipient.point,
    };

    const payload = await sealHandoffKey(handoff, appKey);
    expect(payload.sender_key).toHaveLength(87);
    expect(payload.sealed).toHaveLength(80);
    expect(await openHandoffKey(handoff, recipient.privateKey, payload)).toEqual(appKey);

    for (const key of ['issuer', 'org_id', 'user_id', 'keyring_version'] as const) {
      await expect(openHandoffKey({ ...handoff, context: { ...context, [key]: 'tampered' } }, recipient.privateKey, payload)).rejects.toThrow();
    }
    await expect(openHandoffKey({ ...handoff, client: 'kynotes' }, recipient.privateKey, payload)).rejects.toThrow();
    await expect(openHandoffKey({ ...handoff, version: 2 }, recipient.privateKey, payload)).rejects.toThrow();
    await expect(openHandoffKey({ ...handoff, code: 'other-code' }, recipient.privateKey, payload)).rejects.toThrow();
    await expect(openHandoffKey({ ...handoff, redirect_uri: 'https://evil.example/cb' }, recipient.privateKey, payload)).rejects.toThrow();
    await expect(openHandoffKey({ ...handoff, recipient_key: unrelated.point }, recipient.privateKey, payload)).rejects.toThrow();
    await expect(openHandoffKey(handoff, unrelated.privateKey, payload)).rejects.toThrow();
    await expect(openHandoffKey(handoff, recipient.privateKey, { ...payload, sealed: tamper(payload.sealed) })).rejects.toThrow();
    await expect(openHandoffKey(handoff, recipient.privateKey, { ...payload, sender_key: unrelated.point })).rejects.toThrow();
  });

  it('builds fragment-only handoff callback URLs and rejects unsafe redirect schemes', async () => {
    const recipient = await newHandoffPair();
    const handoff: HandoffBinding = {
      context,
      client: 'kypost',
      version: 3,
      code: 'c-99',
      redirect_uri: 'https://mail.example/cb?existing=1',
      recipient_key: recipient.point,
    };
    const payload = await sealHandoffKey(handoff, newKeyringSecret());
    const url = new URL(buildHandoffRedirectURL(handoff.redirect_uri, 'c-99', 'st-1', {
      ...payload,
      key_version: 3,
      keyring_version: context.keyring_version,
    }));
    expect(url.searchParams.get('existing')).toBe('1');
    expect(url.searchParams.get('code')).toBe('c-99');
    expect(url.searchParams.get('state')).toBe('st-1');
    expect(url.searchParams.get('kh')).toBeNull();
    const frag = new URLSearchParams(url.hash.slice(1));
    expect(frag.get('kh')).toBe(payload.sealed);
    expect(frag.get('kh_pk')).toBe(payload.sender_key);
    expect(frag.get('kh_kv')).toBe('3');
    expect(frag.get('kh_rv')).toBe(context.keyring_version);

    const noKey = new URL(buildHandoffRedirectURL('https://mail.example/cb', 'c-99', 'st-1'));
    expect(noKey.hash).toBe('');
    expect(noKey.searchParams.get('code')).toBe('c-99');

    const errURL = new URL(buildHandoffErrorURL('https://mail.example/cb', 'st-1', 'access_denied', 'Cancelled'));
    expect(errURL.searchParams.get('error')).toBe('access_denied');
    expect(errURL.searchParams.get('state')).toBe('st-1');

    expect(() => buildHandoffRedirectURL('javascript:alert(1)', 'c', 's')).toThrow();
    expect(() => buildHandoffErrorURL('data:text/html,hi', 's', 'access_denied', '')).toThrow();
  });
});

