# KySecurity mobile push relay

## Purpose

Shared Cloudflare Worker logic for the KySecurity Mobile App push relays used by KyIdentity and KyPassword. Provider-specific code lives in `workers/fcn/` and `workers/apns/`.

## Local contracts

- Secrets and live `wrangler.toml` files are never committed or logged.
- The three public routes are `/health`, `/register`, and `/send`; rate limits and token ownership fail closed when their bindings are absent.
- The `RelayCoordinator` is authoritative for token claims and one active self-registered key per IP. Do not replace its serialized operations with KV check-then-write logic.
- Provider error bodies never reach callers. Keep relay errors coarse and use the existing bounded structured logs for operator diagnostics.

## Verification

Run both Worker typechecks and the Node behavior suites after changing shared relay code.
