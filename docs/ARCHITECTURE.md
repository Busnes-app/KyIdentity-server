# Architecture

[Product overview](../README.md) · [Standalone installation](../INSTALL.md)

Commands and unlinked file paths below are relative to the repository root.

## Architecture & Standard Library Philosophy

Following the **Ponytail** engineering philosophy (*use the smallest correct change, prefer native platform APIs, minimize external bloat*), the backend uses the Go standard library for HTTP, token signing and cryptographic primitives, with the external modules listed in `go.mod`.

```
                           ┌───────────────────────────────┐
                           │      React Web Frontend       │
                           │  (Embedded via Go embed/fs)   │
                           └───────────────┬───────────────┘
                                           │
                                           ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             KyIdentity Server (Go)                                 │
├──────────────────┬───────────────────┬─────────────────────┬─────────────────────┤
│   HTTP Routing   │   OIDC / OAuth    │     MFA & TOTP      │    Sync Engine      │
│  (net/http 1.22) │ (crypto/rsa, jwks)│ (crypto/hmac, sha1) │ (net/http, sha256)  │
├──────────────────┴───────────────────┴─────────────────────┴─────────────────────┤
│                          SQLite Database Engine                                  │
│             (database/sql abstraction + modernc.org/sqlite)                      │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Standard Library Implementations

| Subsystem | Standard Library Components Used | Avoided External Dependencies |
| :--- | :--- | :--- |
| **HTTP Routing & API** | `net/http` (Go 1.22+ pattern routing), `context`, `net` | *No Gin, Fiber, Chi, or Gorilla Mux* |
| **OIDC, OAuth 2.0 & JWT** | `crypto/rsa`, `crypto/sha256`, `encoding/base64`, `encoding/json` | *No `golang-jwt`, `go-jose`, or `ory`* |
| **TOTP / 2FA Engine** | `crypto/hmac`, `crypto/sha1`, `encoding/base32`, `encoding/binary` | *No third-party TOTP libraries* |
| **At-Rest Encryption** | `crypto/aes` + `crypto/cipher` (AES-256-GCM, a per-purpose HMAC-derived key and the row identity as associated data, so a secret copied to another row or purpose does not decrypt) | *No third-party encryption packages* |
| **Sync Webhooks** | `net/http` client + `crypto/hmac` + `crypto/sha256` | *No webhook frameworks* |
| **Embedded Frontend** | `embed` + `io/fs` (React SPA served from binary memory) | *No packr or go-bindata* |
| **Database Access** | `database/sql` | *No GORM, Ent, or ORM frameworks* |

### Direct Dependencies

The direct modules in [go.mod](../go.mod) are the authoritative dependency list:

- `github.com/Busnes-app/ky-primitives`: shared Ky security and recovery components.
- `github.com/SherClockHolmes/webpush-go`: Web Push delivery.
- `github.com/fxamacker/cbor/v2`: CBOR encoding/decoding used by authenticator protocols.
- `github.com/google/uuid`: identifiers.
- `golang.org/x/crypto`: extended cryptographic implementations.
- `modernc.org/sqlite`: SQLite without a CGO dependency.

---
