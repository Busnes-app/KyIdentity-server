# KySecurity mobile push relay

## Purpose

Shared Cloudflare Worker logic for the KySecurity Mobile App push relays used by KyIdentity and KyPassword. Provider-specific code lives in `workers/fcn/` and `workers/apns/`.

## Local contracts

- Secrets and live `wrangler.toml` files are never committed or logged.
- The three public routes are `/health`, `/register`, and `/send`; rate limits and token ownership fail closed when their bindings are absent.
- The `RelayCoordinator` is authoritative for token claims and one active self-registered key per IP. Do not replace its serialized operations with KV check-then-write logic.
- A key `/register` displaces leaves a `superseded:<hash>` tombstone, and only that key gets `/send`'s 401 `code: key_superseded` (`denyUnknownKey`), which tells KyIdentity to re-register. Unknown or hand-deleted keys stay a plain 401.
- Device tokens are pinned by sha256, so `readSendPayload` reduces each to its provider's one canonical spelling (`apnsToken`, `fcmToken`) or refuses it (400) before the minute limiter, the token hash, the claim, the budget or the provider call. Only that canonical value may be hashed or sent.
- Provider error bodies never reach callers. Keep relay errors coarse and use the existing bounded structured logs for operator diagnostics.

## Verification

Run both Worker typechecks and the Node behavior suites after changing shared relay code.
