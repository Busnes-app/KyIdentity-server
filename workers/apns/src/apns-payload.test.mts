/**
 * The APS payload a sign-in push carries.
 *
 * `mutable-content` is what hands the alert to KyAuth iOS's notification
 * service extension, which replaces it with fixed text. Dropping it is silent:
 * pushes still arrive and the app still opens them, only the alert text is
 * wrong.
 *
 *   node --test workers/apns/src/apns-payload.test.mts
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

const { apnsPayload } = await import("./apns.ts");

test("a sealed sign-in push runs the notification service extension", () => {
  const payload = apnsPayload({
    token: "t",
    title: "Sign-in request",
    body: "Open KyAuth to review.",
    data: { type: "mfa_challenge", kyauth: "sealed" },
  });
  assert.deepEqual(payload, {
    aps: {
      alert: { title: "Sign-in request", body: "Open KyAuth to review." },
      sound: "default",
      "mutable-content": 1,
      category: "MFA_CHALLENGE",
    },
    type: "mfa_challenge",
    kyauth: "sealed",
  });
});

test("only a sign-in push gets the approval category", () => {
  const payload = apnsPayload({ token: "t", title: "x", body: "y" }) as { aps: Record<string, unknown> };
  assert.equal(payload.aps.category, undefined);
  assert.equal(payload.aps["mutable-content"], 1);
});
