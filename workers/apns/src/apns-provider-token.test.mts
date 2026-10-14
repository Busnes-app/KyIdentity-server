/**
 * Apple rejecting our cached provider token must not keep failing sends.
 *
 * Apple answers 403 `ExpiredProviderToken` / `InvalidProviderToken`; the old
 * substring check looked for "expiredtoken"/"invalidtoken", matched neither, and
 * kept serving the rejected token from KV until its TTL ran out.
 *
 *   node --test workers/apns/src/apns-provider-token.test.mts
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

const { sendApnsMessage, providerTokenCacheKey, apnsReason } = await import("./apns.ts");

async function testAuthKeyPem(): Promise<string> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
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
  authKey: await testAuthKeyPem(),
  keyId: "KEY123",
  teamId: "TEAM456",
  topic: "app.busnes.kyauth",
  environment: "production" as const,
};
const message = { token: "a".repeat(64), title: "t", body: "b" };

async function sendWith(responses: Response[], store: Map<string, string>) {
  const auths: string[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (_url: string, init: RequestInit) => {
    auths.push((init.headers as Record<string, string>).authorization);
    return responses.shift() ?? new Response("", { status: 200 });
  }) as typeof fetch;
  try {
    return { result: await sendApnsMessage(config, mapCache(store), message), auths };
  } finally {
    globalThis.fetch = realFetch;
  }
}

test("the cache key names the signing team and key", () => {
  const key = providerTokenCacheKey(config);
  assert.ok(key.includes("TEAM456") && key.includes("KEY123"), key);
  assert.notEqual(key, providerTokenCacheKey({ ...config, keyId: "OTHER" }));
});

test("reasons are matched exactly, not by substring", () => {
  assert.equal(apnsReason(JSON.stringify({ reason: "ExpiredProviderToken" })), "ExpiredProviderToken");
  assert.equal(apnsReason("<html>ExpiredProviderToken</html>"), "");
});

for (const reason of ["ExpiredProviderToken", "InvalidProviderToken"]) {
  test(`403 ${reason} drops the cached token and retries once with a fresh one`, async () => {
    const store = new Map([[providerTokenCacheKey(config), "stale-provider-token"]]);
    const { result, auths } = await sendWith(
      [new Response(JSON.stringify({ reason }), { status: 403 }), new Response("", { status: 200 })],
      store,
    );
    assert.deepEqual(result, { ok: true });
    assert.equal(auths.length, 2);
    assert.equal(auths[0], "bearer stale-provider-token");
    assert.notEqual(auths[1], auths[0]);
    assert.notEqual(store.get(providerTokenCacheKey(config)), "stale-provider-token");
  });
}

test("a second rejection stops after one retry and leaves no cached token", async () => {
  const store = new Map<string, string>();
  const rejected = () => new Response(JSON.stringify({ reason: "InvalidProviderToken" }), { status: 403 });
  const { result, auths } = await sendWith([rejected(), rejected()], store);
  assert.equal(result.ok, false);
  assert.equal(auths.length, 2);
  assert.equal(store.has(providerTokenCacheKey(config)), false);
});

test("other 403 reasons are not retried", async () => {
  const store = new Map<string, string>();
  const { result, auths } = await sendWith(
    [new Response(JSON.stringify({ reason: "Forbidden" }), { status: 403 })],
    store,
  );
  assert.equal(result.ok, false);
  assert.equal(auths.length, 1);
});
