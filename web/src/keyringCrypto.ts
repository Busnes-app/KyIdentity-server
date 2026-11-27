import { newXwingPair, openXwing, sealXwing, xwingMarker, xwingPacketBytes, xwingPublicKeyBytes } from './pqCrypto';

export type RingContext = {
  issuer: string;
  org_id: string;
  user_id: string;
  keyring_version: string;
};

export type WrapperKind = 'device' | 'recovery' | 'prf';

const domain = 'ky-keyring/1';
const zeroSalt = new Uint8Array(32);
const utf8 = new TextEncoder();

export const newKeyringSecret = () => crypto.getRandomValues(new Uint8Array(32));

export function encodeKeyringBytes(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function decodeKeyringBytes(text: string, length: number): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(text) || text.length !== Math.ceil(length * 8 / 6)) {
    throw new Error('Invalid keyring encoding.');
  }
  const bytes = Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
  if (bytes.length !== length || encodeKeyringBytes(bytes) !== text) throw new Error('Invalid keyring encoding.');
  return bytes;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

export function formatRecoveryKey(secret: Uint8Array): string {
  return 'KYR1-' + (hex(secret).toUpperCase().match(/.{8}/g) ?? []).join('-');
}

export function parseRecoveryKey(code: string): Uint8Array<ArrayBuffer> {
  const normalized = code.trim().toUpperCase();
  if (!/^KYR1(?:-[0-9A-F]{8}){8}$/.test(normalized)) throw new Error('Enter the full KYR1 key from your Emergency Kit.');
  const pairs = normalized.slice(5).replaceAll('-', '').match(/.{2}/g) ?? [];
  return Uint8Array.from(pairs, p => Number.parseInt(p, 16));
}

export function keyringScope(c: RingContext) {
  return [c.issuer, c.org_id, c.user_id, c.keyring_version];
}

function transcript(parts: (string | number)[]) {
  return utf8.encode(JSON.stringify(parts));
}

function aad(c: RingContext, kind: string, ...parts: (string | number)[]) {
  return transcript([domain, kind, ...keyringScope(c), ...parts]);
}

export function importKeyringSecret(bytes: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', bytes, 'HKDF', false, ['deriveKey']);
}

async function wrapKey(material: CryptoKey, info: Uint8Array<ArrayBuffer>, salt = zeroSalt) {
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info }, material,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function seal(material: CryptoKey, plaintext: Uint8Array<ArrayBuffer>, info: Uint8Array<ArrayBuffer>, salt = zeroSalt) {
  const key = await wrapKey(material, info, salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: info }, key, plaintext);
  const packed = new Uint8Array(60);
  packed.set(iv);
  packed.set(new Uint8Array(ciphertext), iv.length);
  return encodeKeyringBytes(packed);
}

async function open(material: CryptoKey, packet: string, info: Uint8Array<ArrayBuffer>, salt = zeroSalt) {
  const key = await wrapKey(material, info, salt);
  const bytes = decodeKeyringBytes(packet, 60);
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytes.subarray(0, 12), additionalData: info }, key, bytes.subarray(12)));
}

export type WrapperBinding = { context: RingContext; id: string; kind: WrapperKind };

export function wrapRoot(binding: WrapperBinding, material: CryptoKey, root: Uint8Array<ArrayBuffer>) {
  return seal(material, root, aad(binding.context, 'wrapper', binding.id, binding.kind));
}

export function unwrapRoot(binding: WrapperBinding, material: CryptoKey, sealed: string) {
  return open(material, sealed, aad(binding.context, 'wrapper', binding.id, binding.kind));
}

type AppBinding = { context: RingContext; client: string; version: number };

export async function newWrappedAppKey(binding: AppBinding, root: Uint8Array<ArrayBuffer>) {
  const subkey = newKeyringSecret();
  const material = await importKeyringSecret(root);
  return { subkey, sealed: await seal(material, subkey, aad(binding.context, 'app', binding.client, binding.version)) };
}

export async function unwrapAppKey(binding: AppBinding, root: Uint8Array<ArrayBuffer>, sealed: string) {
  return open(await importKeyringSecret(root), sealed, aad(binding.context, 'app', binding.client, binding.version));
}

export async function newDeviceCapability() {
  const capability = encodeKeyringBytes(newKeyringSecret());
  const digest = await crypto.subtle.digest('SHA-256', utf8.encode(capability));
  return { capability, device_hash: hex(new Uint8Array(digest)) };
}

type TransferRequest = { recipient_key: string; request_mac: string };
type TransferResponse = { sender_key: string; sealed: string };
export type PendingTransfer = {
  id: string;
  secret: Uint8Array<ArrayBuffer>;
  privateKey: Uint8Array<ArrayBuffer>;
  request: TransferRequest;
};

async function transferPair() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  return { point: encodeKeyringBytes(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))), privateKey: pair.privateKey };
}

async function transferMAC(secret: Uint8Array<ArrayBuffer>) {
  return crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function transferMaterial(privateKey: CryptoKey, peer: string) {
  const publicKey = await crypto.subtle.importKey('raw', decodeKeyringBytes(peer, 65),
    { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256));
  try {
    return await importKeyringSecret(shared);
  } finally {
    shared.fill(0);
  }
}

export function isKeyringID(text: unknown): text is string {
  return typeof text === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(text);
}

export function parseTransferCode(code: string) {
  const [prefix, id, secret, ...extra] = code.trim().split('.');
  if (prefix !== 'KYT2' || !isKeyringID(id) || !secret || extra.length) throw new Error('Enter the full KYT2 approval code. Reload both browsers to upgrade an older code.');
  return { id, secret: decodeKeyringBytes(secret, 32) };
}

export async function newTransfer(context: RingContext): Promise<PendingTransfer> {
  const id = crypto.randomUUID();
  const secret = newKeyringSecret();
  const { point, privateKey } = await newHandoffPair();
  const mac = await crypto.subtle.sign('HMAC', await transferMAC(secret), aad(context, 'transfer-xwing/2', id, point));
  return { id, secret, privateKey, request: { recipient_key: point, request_mac: encodeKeyringBytes(new Uint8Array(mac)) } };
}

export function transferCode(pending: PendingTransfer) {
  return ['KYT2', pending.id, encodeKeyringBytes(pending.secret)].join('.');
}

// The approval secret is part of HPKE info, never sent to the relay. Even disclosure
// of the KEM shared secret cannot reproduce the HPKE schedule without this secret.
function transferInfo(context: RingContext, id: string, recipient: string, secret: Uint8Array) {
  const publicAAD = aad(context, 'transfer-xwing/2', id, recipient);
  const label = utf8.encode('kyidentity/keyring-transfer/2\0');
  const info = new Uint8Array(label.length + publicAAD.length + 1 + secret.length);
  info.set(label);
  info.set(publicAAD, label.length);
  info.set(secret, label.length + publicAAD.length + 1);
  return { info, publicAAD };
}

export async function approveTransfer(context: RingContext, code: ReturnType<typeof parseTransferCode>, request: TransferRequest,
  root: Uint8Array<ArrayBuffer>): Promise<TransferResponse> {
  const recipient = decodeKeyringBytes(request.recipient_key, xwingPublicKeyBytes);
  const valid = await crypto.subtle.verify('HMAC', await transferMAC(code.secret), decodeKeyringBytes(request.request_mac, 32),
    aad(context, 'transfer-xwing/2', code.id, request.recipient_key));
  if (!valid) throw new Error('This approval code does not match the requesting device.');
  const { info, publicAAD } = transferInfo(context, code.id, request.recipient_key, code.secret);
  try {
    return { sender_key: xwingMarker, sealed: encodeKeyringBytes(await sealXwing(recipient, info, publicAAD, root)) };
  } finally {
    info.fill(0);
  }
}

export async function openTransfer(context: RingContext, pending: PendingTransfer, response: TransferResponse) {
  if (response.sender_key !== xwingMarker) throw new Error('Unsupported transfer format. Reload both browsers.');
  const { info, publicAAD } = transferInfo(context, pending.id, pending.request.recipient_key, pending.secret);
  try {
    return await openXwing(pending.privateKey, info, publicAAD, decodeKeyringBytes(response.sealed, xwingPacketBytes));
  } finally {
    info.fill(0);
  }
}

export function wipeTransfer(pending: PendingTransfer | null | undefined) {
  pending?.secret.fill(0);
  pending?.privateKey.fill(0);
}

export type HandoffBinding = {
  context: RingContext;
  client: string;
  version: number;
  code: string;
  redirect_uri: string;
  recipient_key: string;
  nonce: string;
};

export type HandoffPayload = {
  sender_key: string;
  sealed: string;
};

// New recipients always request PQ; only an explicitly supplied 65-byte P-256
// recipient selects the unchanged legacy format. Never retry PQ as classical.
export async function newHandoffPair() {
  const pair = await newXwingPair();
  return { point: encodeKeyringBytes(pair.publicKey), privateKey: pair.privateKey };
}

export function handoffKeyLength(key: string): 65 | 1216 {
  const length = key.length === 87 ? 65 : xwingPublicKeyBytes;
  decodeKeyringBytes(key, length);
  return length;
}

function handoffAAD(binding: HandoffBinding) {
  if (typeof binding.nonce !== 'string') throw new Error('Missing handoff nonce binding.');
  return aad(binding.context, 'handoff-xwing/2', binding.client, binding.version,
    binding.code, binding.redirect_uri, binding.recipient_key, binding.nonce);
}

function handoffInfo(publicAAD: Uint8Array) {
  const label = utf8.encode('kyidentity/keyring-handoff/2\0');
  const info = new Uint8Array(label.length + publicAAD.length);
  info.set(label);
  info.set(publicAAD, label.length);
  return info;
}

export async function sealHandoffKey(binding: HandoffBinding, appKey: Uint8Array<ArrayBuffer>): Promise<HandoffPayload> {
  if (handoffKeyLength(binding.recipient_key) === xwingPublicKeyBytes) {
    const publicAAD = handoffAAD(binding);
    const sealed = await sealXwing(decodeKeyringBytes(binding.recipient_key, xwingPublicKeyBytes),
      handoffInfo(publicAAD), publicAAD, appKey);
    return { sender_key: xwingMarker, sealed: encodeKeyringBytes(sealed) };
  }
  const sender = await transferPair();
  const material = await transferMaterial(sender.privateKey, binding.recipient_key);
  const info = aad(binding.context, 'handoff', binding.client, binding.version,
    binding.code, binding.redirect_uri, binding.recipient_key, sender.point);
  return { sender_key: sender.point, sealed: await seal(material, appKey, info) };
}

export async function openHandoffKey(binding: HandoffBinding, recipientPrivateKey: CryptoKey | Uint8Array<ArrayBuffer>, response: HandoffPayload) {
  if (handoffKeyLength(binding.recipient_key) === xwingPublicKeyBytes) {
    if (!(recipientPrivateKey instanceof Uint8Array) || response.sender_key !== xwingMarker) {
      throw new Error('Invalid X-Wing handoff.');
    }
    const publicAAD = handoffAAD(binding);
    return openXwing(recipientPrivateKey, handoffInfo(publicAAD), publicAAD, decodeKeyringBytes(response.sealed, xwingPacketBytes));
  }
  if (recipientPrivateKey instanceof Uint8Array || response.sender_key === xwingMarker) throw new Error('Invalid legacy handoff.');
  const material = await transferMaterial(recipientPrivateKey, response.sender_key);
  const info = aad(binding.context, 'handoff', binding.client, binding.version,
    binding.code, binding.redirect_uri, binding.recipient_key, response.sender_key);
  return open(material, response.sealed, info);
}

function validatedRedirectTarget(redirectURI: string): URL {
  const target = new URL(redirectURI);
  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    throw new Error('Invalid application redirect URI.');
  }
  return target;
}

export function buildHandoffRedirectURL(
  redirectURI: string,
  code: string,
  state: string,
  handoff?: HandoffPayload & { key_version: number; keyring_version: string },
): string {
  const target = validatedRedirectTarget(redirectURI);
  target.searchParams.set('code', code);
  if (state) target.searchParams.set('state', state);
  if (handoff) {
    target.hash = new URLSearchParams({
      kh: handoff.sealed,
      kh_pk: handoff.sender_key,
      kh_kv: String(handoff.key_version),
      kh_rv: handoff.keyring_version,
    }).toString();
  } else {
    target.hash = '';
  }
  return target.toString();
}

export function buildHandoffErrorURL(redirectURI: string, state: string, error: string, description: string): string {
  const target = validatedRedirectTarget(redirectURI);
  target.searchParams.set('error', error);
  if (description) target.searchParams.set('error_description', description);
  if (state) target.searchParams.set('state', state);
  target.hash = '';
  return target.toString();
}

