/**
 * A Google access token FCM refuses must not be served from KV until its TTL.
 *
 *   node --test workers/fcn/src/fcm-token-cache.test.mts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { registerHooks } from "node:module";

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith(".") && !/\.[cm]?[jt]s$/.test(specifier)) {
      return nextResolve(specifier + ".ts", context);
    }
    return nextResolve(specifier, context);
  },
});

const { sendFcmMessage, accessTokenCacheKey } = await import("./fcm.ts");

async function testPrivateKeyPem(): Promise<string> {
  const pair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
  return `-----BEGIN PRIVATE KEY-----\n${Buffer.from(pkcs8).toString("base64")}\n-----END PRIVATE KEY-----\n`;
}

function mapCache(store: Map<string, string>) {
  return {
    get: async (k: string) => store.get(k) ?? null,
    put: async (k: string, v: string) => void store.set(k, v),
    delete: async (k: string) => void store.delete(k),
  } as unknown as KVNamespace;
}

const config = {
  clientEmail: "relay@example.iam.gserviceaccount.com",
  privateKeyPem: await testPrivateKeyPem(),
  projectId: "kysecurity-mobile-relay-test",
};

/** Stubs Google: the token endpoint mints "fresh-token", sends answer from `sends` in order. */
async function sendWith(sends: Response[], store: Map<string, string>) {
  const bearers: string[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    if (url.startsWith("https://oauth2.googleapis.com/")) {
      return new Response(JSON.stringify({ access_token: "fresh-token", expires_in: 3600 }), { status: 200 });
    }
    bearers.push((init.headers as Record<string, string>).Authorization);
    return sends.shift() ?? new Response("{}", { status: 200 });
  }) as typeof fetch;
  try {
    return { result: await sendFcmMessage(config, mapCache(store), { token: "t", title: "t", body: "b" }), bearers };
  } finally {
    globalThis.fetch = realFetch;
  }
}

test("the cache key names the service account", () => {
  assert.ok(accessTokenCacheKey(config).includes(config.clientEmail));
});

test("a 401 drops the cached access token and retries once with a fresh one", async () => {
  const store = new Map([[accessTokenCacheKey(config), "revoked-token"]]);
  const { result, bearers } = await sendWith([new Response("{}", { status: 401 })], store);
  assert.deepEqual(result, { ok: true });
  assert.deepEqual(bearers, ["Bearer revoked-token", "Bearer fresh-token"]);
  assert.equal(store.get(accessTokenCacheKey(config)), "fresh-token");
});

test("a second 401 fails after one retry and leaves no cached token", async () => {
  const store = new Map([[accessTokenCacheKey(config), "revoked-token"]]);
  const { result, bearers } = await sendWith(
    [new Response("{}", { status: 401 }), new Response("{}", { status: 401 })],
    store,
  );
  assert.equal(result.ok, false);
  assert.equal(bearers.length, 2);
  assert.equal(store.has(accessTokenCacheKey(config)), false);
});

test("a KV write over quota still sends, and later sends reuse the token", async () => {
  const quotaCache = {
    get: async () => null,
    put: async () => {
      throw new Error("KV put() limit exceeded for the day.");
    },
    delete: async () => {},
  } as unknown as KVNamespace;
  const quotaConfig = { ...config, clientEmail: "quota@example.iam.gserviceaccount.com" };
  let mints = 0;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string) => {
    if (url.startsWith("https://oauth2.googleapis.com/")) {
      mints++;
      return new Response(JSON.stringify({ access_token: "fresh-token", expires_in: 3600 }), { status: 200 });
    }
    return new Response("{}", { status: 200 });
  }) as typeof fetch;
  try {
    const message = { token: "t", title: "t", body: "b" };
    assert.deepEqual(await sendFcmMessage(quotaConfig, quotaCache, message), { ok: true });
    assert.deepEqual(await sendFcmMessage(quotaConfig, quotaCache, message), { ok: true });
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(mints, 1);
});
