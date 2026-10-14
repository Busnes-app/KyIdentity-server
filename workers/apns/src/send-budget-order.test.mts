/**
 * What the daily budget is allowed to charge for.
 *
 * The budget exists to bound what the relay spends against the operator's APNs
 * quota. A request refused at the token-ownership claim never reaches Apple, so
 * charging it is not conservative — it is wrong, and it is an amplification: any
 * holder of any valid key could spend the entire day's budget by sending to
 * device tokens they do not own, delivering nothing, and every legitimate
 * self-hoster is refused for the rest of the day. That turns a cost ceiling into
 * a cheap total outage, which is the opposite of the trade it exists to make.
 *
 * So the order is: minute limit, claim, THEN budget, then dispatch. A budget
 * refusal after the claim settles it as undelivered, which releases it — the
 * same close-out every other post-claim failure path uses.
 *
 *   node --test worker-apns/src/send-budget-order.test.mts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { registerHooks } from "node:module";

const durableObjectStub =
  "data:text/javascript," +
  encodeURIComponent("export class DurableObject{constructor(ctx,env){this.ctx=ctx;this.env=env}}");

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "cloudflare:workers") {
      return { url: durableObjectStub, shortCircuit: true };
    }
    if (specifier.startsWith(".") && !/\.[cm]?[jt]s$/.test(specifier)) {
      return nextResolve(specifier + ".ts", context);
    }
    return nextResolve(specifier, context);
  },
});

const worker = await import("./index.ts");
const { RelayCoordinator } = await import("../../../push-relay-shared/relay-coordinator.ts");
const { KEY_PREFIX, KEY_INDEX_PREFIX, BOUND_TOKEN_PREFIX, sha256Hex } = await import(
  "../../../push-relay-shared/push-relay-common.ts"
);

const AUTH_KEY = "-----BEGIN PRIVATE KEY-----\nMHc=\n-----END PRIVATE KEY-----";
const API_KEY = "relay-key-under-test";
/** A 32-byte hex device token, distinct per seed. */
const device = (seed: string) => seed.repeat(64 / seed.length);

function storage() {
  const cells = new Map();
  return {
    cells,
    async get(key) {
      return cells.get(key);
    },
    async put(keyOrEntries, value) {
      if (typeof keyOrEntries === "string") {
        cells.set(keyOrEntries, value);
        return;
      }
      for (const [k, v] of Object.entries(keyOrEntries)) cells.set(k, v);
    },
    async delete(keys) {
      for (const key of Array.isArray(keys) ? keys : [keys]) cells.delete(key);
    },
  };
}

/** A fully configured APNs env with a budget of exactly one send. */
async function env(kvEntries: [string, unknown][] = []) {
  const kv = new Map(kvEntries);
  kv.set(KEY_PREFIX + (await sha256Hex(API_KEY)), {
    id: "key-under-test",
    label: "test",
    enabled: true,
    createdAt: "2026-01-01T00:00:00Z",
  });
  const instances = new Map();
  return {
    instances,
    APNS_AUTH_KEY: AUTH_KEY,
    APNS_KEY_ID: "KEYID12345",
    APNS_TEAM_ID: "TEAMID1234",
    APNS_TOPIC: "com.kysecurity.mobile",
    APNS_ENVIRONMENT: "production",
    APNS_TOKEN_CACHE: {
      async get() {
        return "cached-provider-token"; // skip ES256 signing; nothing here reaches Apple
      },
      async put() {},
      async delete() {},
    },
    RELAY_DAILY_BUDGET: "1",
    // No limiter binding in this harness; the minute tier is covered elsewhere.
    RATELIMIT_FAIL_OPEN: "true",
    API_KEYS: {
      async get(key: string) {
        const value = kv.get(key);
        return value === undefined ? null : value;
      },
    },
    RELAY_COORDINATOR: {
      idFromName: (name: string) => name,
      get(name: string) {
        if (!instances.has(name)) instances.set(name, new RelayCoordinator({ storage: storage() }, {}));
        return instances.get(name);
      },
    },
    USAGE_ANALYTICS: { writeDataPoint() {} },
  };
}

const ctx = { waitUntil(p: Promise<unknown>) { void p; } };

function send(e: unknown, token: string) {
  return worker.default.fetch(
    new Request("https://relay.example/send", {
      method: "POST",
      headers: { Authorization: "Bearer " + API_KEY },
      body: JSON.stringify({ token, title: "t", body: "b" }),
    }),
    e,
    ctx,
  );
}

/** Marks a device token as already owned by another key, via the legacy index. */
async function ownedByAnother(token: string): Promise<[string, unknown][]> {
  return [
    [BOUND_TOKEN_PREFIX + (await sha256Hex(token)), "key-someone-else"],
    [KEY_INDEX_PREFIX + "key-someone-else", "raw-other"],
    [
      KEY_PREFIX + "raw-other",
      { id: "key-someone-else", label: "other", enabled: true, createdAt: "2026-01-01T00:00:00Z" },
    ],
  ];
}

test("a send refused at the ownership claim does not spend the daily budget", async () => {
  const taken = device("0a");
  const e = await env(await ownedByAnother(taken));

  // Stub Apple so a send that DOES get through can be told apart from one that
  // never reached dispatch.
  const realFetch = globalThis.fetch;
  let appleCalls = 0;
  globalThis.fetch = (async () => {
    appleCalls++;
    return new Response("", { status: 200 });
  }) as typeof fetch;

  try {
    const denied = await send(e, taken);
    assert.equal(denied.status, 403, "expected the claim to be refused");
    assert.equal(appleCalls, 0, "a refused claim reached Apple");

    // The budget is 1. If the refusal above consumed it, this legitimate send
    // to a free token is refused 429 and the relay is down for the day on
    // traffic that delivered nothing.
    const allowed = await send(e, device("0b"));
    assert.equal(
      allowed.status,
      200,
      `the refused send spent the budget; this legitimate send got ${allowed.status}`,
    );
    assert.equal(appleCalls, 1);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("the budget still bounds sends that do reach the provider", async () => {
  // The guard above must not have turned the budget off: the second delivering
  // send, against a budget of 1, is still refused.
  const e = await env();

  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response("", { status: 200 })) as typeof fetch;

  try {
    assert.equal((await send(e, device("01"))).status, 200);

    const over = await send(e, device("02"));
    assert.equal(over.status, 429, "the budget did not bound a second delivering send");
    assert.equal(over.headers.get("Retry-After") !== null, true, "429 carried no Retry-After");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("an aliased or malformed token is refused before the claim, the budget or Apple", async () => {
  // fetch normalizes `/3/device/a/../VICTIM` to VICTIM, so an alias that reached
  // the hash got a fresh, unpinned claim on someone else's device.
  const victim = device("0c");
  const e = await env(await ownedByAnother(victim));

  const realFetch = globalThis.fetch;
  const urls: string[] = [];
  globalThis.fetch = (async (url: string) => {
    urls.push(url);
    return new Response("", { status: 200 });
  }) as typeof fetch;

  try {
    for (const alias of [
      `a/../${victim}`,
      `%2e%2e/${victim}`,
      `${victim}#x`,
      `${victim}?x`,
      `${victim.slice(0, 32)} ${victim.slice(32)}`,
      victim.slice(2),
      victim + "0".repeat(200),
    ]) {
      const refused = await send(e, alias);
      assert.equal(refused.status, 400, `${JSON.stringify(alias)} answered ${refused.status}`);
      assert.equal((await refused.json()).error, "invalid token");
    }
    assert.equal(e.instances.size, 0, "a refused token touched a coordinator or the budget");

    // Case folds onto the victim's own pin rather than a fresh one.
    assert.equal((await send(e, victim.toUpperCase())).status, 403);
    assert.equal(urls.length, 0, "a refused token reached Apple");

    // Budget is 1: none of the refusals above may have spent it.
    const free = device("0d");
    assert.equal((await send(e, ` ${free.toUpperCase()} `)).status, 200);
    assert.deepEqual(urls, [`https://api.push.apple.com/3/device/${free}`]);
  } finally {
    globalThis.fetch = realFetch;
  }
});
