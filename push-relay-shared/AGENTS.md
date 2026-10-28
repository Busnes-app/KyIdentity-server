# KySecurity mobile push relay

## Purpose

Shared Cloudflare Worker logic for the KySecurity Mobile App push relays used by KyIdentity and KyPassword. Provider-specific code lives in `workers/fcn/` and `workers/apns/`.

## Local contracts

- `push-relay-shared/` is copied byte-for-byte between KyIdentity-server and KyPost-Server, except this AGENTS.md. Change both in the same pair of PRs; nothing checks it for you (`diff -r` the two directories).
- Secrets and live `wrangler.toml` files are never committed or logged. Neither are API keys or their hashes.
- The three public routes are `/health`, `/register`, and `/send`; rate limits and token ownership fail closed when their bindings are absent.
- The `RelayCoordinator` is authoritative for token claims and for key records: the `keys` table in its `relay-keys` instance (`KEY_REGISTRY`). `/register` supersedes the IP's active keys and inserts the new one in one `transactionSync`; one active key per IP is that query. Do not move either back to KV check-then-write, and write nothing to KV: the free plan's 1,000 writes a day is what took push down on 2026-10-26.
- `API_KEYS` is read-only legacy. `lookupKey` asks the registry first and copies a key found only in KV into it on first use (`importKey`); once a row exists KV has no say. A KV key whose IP has registered in the registry since it was created is copied in as `superseded`.
- `denyKey` codes are a contract with the Go servers: `key_superseded` and `key_unknown` (no row, no KV record) mean re-register; a revoked key (operator `UPDATE ... status = 'revoked'` in Data Studio) gets a plain 401 and must stay refused. Never answer `key_unknown` for a key the relay knows.
- Active keys are cached per isolate for `KEY_CACHE_TTL_MS` (30 s), keyed by hash. That is the longest a revocation or out-of-band supersede takes to bite.
- Device tokens are pinned by sha256, so `readSendPayload` reduces each to its provider's one canonical spelling (`apnsToken`, `fcmToken`) or refuses it (400) before the minute limiter, the token hash, the claim, the budget or the provider call. Only that canonical value may be hashed or sent.
- Provider credentials (Google access tokens, APNs provider JWTs) are cached only through `token-cache.ts`: KV writes have a daily account quota, and a refused write must not fail a send or force a new token per send.
- Provider error bodies never reach callers. Keep relay errors coarse and use the existing bounded structured logs for operator diagnostics.

## Verification

Run both Worker typechecks and the Node behavior suites after changing shared relay code. The registry's SQL runs against real SQLite in tests (`durable-storage.mts`, `node:sqlite`); key lifecycle cases live in `relay-keys.test.mts`.
