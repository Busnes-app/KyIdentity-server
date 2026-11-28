# Key Steward, design

Date: 2026-11-28. **Status: draft for the owner's approval.** Nothing here is built.

The **Key Steward** is one key per Enterprise install that can open every KyDrive vault on
it. It is how an Enterprise organisation recovers the files of a member who lost every
device, or hands a leaver's files to a successor. It is the vault spec's escrow key
(kydrive-server `docs/superpowers/specs/2026-11-22-e2e-vault-design.md:318-340`) under a
new name, and its design follows that section unless this note says otherwise.

Owner decisions (28 Nov, not reopened here):

1. The Key Steward exists **only on Enterprise deployments**, never on the shared install
   (kydrive-server `docs/superpowers/specs/2026-11-28-whole-drive-e2e-decisions.md:30`, D12
   at `:56-63`).
2. **KyIdentity owns the steward's public key. KyDrive enforces wraps to it.**
3. A leaver's files are handed over only by a member re-wrapping keys or through the Key
   Steward (decisions `:32`, D14). The server handover (`internal/drive/handover.go:98`)
   goes.
4. "We say E2E and mean it" (decisions `:15`). The steward's private key never reaches any
   server, KyIdentity included.

Line references are to KyIdentity-server `origin/master` at `3b22a50` and kydrive-server
`origin/master` at `66b5454` (prefixed `kydrive:`). "Unproven" marks a claim this note did
not check in code or by running it.

## What changes from the vault spec

The vault spec was written before the vault code. What `master` built differs in ways this
design has to follow:

- A vault record carries the whole signed membership state, with each member's wrap inside
  it (`kydrive:internal/vault/record.go:24-51`). There are no separate `drive_vault_members`
  or `drive_vault_escrow` tables. So the steward's wrap goes **inside the signed state**
  too, next to the members' wraps.
- Only a `manager` may sign a record (`kydrive:internal/vault/record.go:144`). The vault spec
  let every member add, remove and rotate.
- There is no `escrowable` or `personal`/`shared` marker in `create` yet.
- Under whole-drive E2E every workspace is a vault (decisions doc `:5-6`), so on an
  Enterprise install the steward covers all of a member's files, personal ones included.
  That is what decision 3 needs.

## Keys and statements

The steward key is the same shape as a member's vault key
(`kydrive:internal/drive/vault.go:14-24`): an age hybrid recipient (ML-KEM-768 + X25519)
and a `ky-primitives/hybridsig` signing key (ML-DSA-65 + Ed25519). Its **fingerprint** is
computed exactly as `VaultKey.Fingerprint` (`kydrive:internal/drive/vault.go:21-24`), so
every client and both servers compute one value one way.

Every change to the steward is a **steward statement**: canonical JSON, signed with
hybridsig under its own domain `ky-key-steward-v1`.

| Field | Meaning |
|---|---|
| `issuer` | The KyIdentity issuer URL. A statement made for one install is refused on another. |
| `serial` | 1, 2, 3 … with no gaps. |
| `action` | `register`, `rotate` or `retire`. |
| `recipient`, `signing` | The steward's public keys (`register`, `rotate`). |
| `fingerprint` | Their fingerprint. |
| `previous` | The fingerprint of the steward this replaces (`rotate`, `retire`). |
| `created` | Time, informational. |
| `signature` | By the statement's own signing key (proof of possession). |
| `previous_signature` | `rotate` only: by the previous steward's signing key. |

The statements form a chain. A client that pinned serial 3 can check serials 4, 5 … up to
the current one with no human involved, as long as each `rotate` is signed by the key
before it.

## 1. What KyIdentity owns

KyIdentity registers, rotates, retires and publishes statements. It never makes a key and
never holds a private one. It checks each statement before storing it: the signature,
`issuer` equal to its own, the next `serial`, and for `rotate` the previous key's signature.

It reuses what it already has:

- **Admin route and step-up.** A new pane under Administration › Suite settings, beside
  the suite email domains and default theme (`internal/api/server.go:392-394`,
  `web/src/components/AdminSuiteSettings.tsx`). The routes go in the same admin route table
  with `permAdmin` and step-up on (the `stepUp` column, `internal/api/permissions.go:92`;
  the grant is single-use, `internal/api/stepup.go:40-57`):
  - `GET /api/admin/key-steward`: the chain and the current fingerprint.
  - `POST /api/admin/key-steward`: body is one statement, `register`, `rotate` or `retire`.
  The admin uploads the public statement file that the desktop app exported (section 2).
  The browser handles only public material.
- **Audit.** Same pattern as the suite settings: `audit.Prepare` before the write, the row
  committed in the same transaction, `Committed()` after
  (`internal/api/suite_settings_handlers.go:118-123`, `internal/audit/audit.go:114`). Actions
  `admin.key_steward_registered`, `…_rotated`, `…_retired`, with serial and fingerprints in
  the details. A refused statement is audited as `failure` with the reason.
- **Storage.** A new table `key_stewards(serial PK, fingerprint, statement, registered_at,
  registered_by)` in a new migration on both backends (AGENTS.md "Database backends"). It
  is a platform table, not org-owned, and goes in the tenancy classification test
  (`internal/store/tenancy_test.go`). A table, not a `system_settings` key, because clients
  need the whole chain.
- **Publishing.** Two copies, so a client can compare two servers:
  - `GET /api/suite/key-steward` for suite apps, with the suite directory's client
    authentication, rate limits and `no-store` (`docs/SUITE-DIRECTORY.md:11-16`,
    `internal/api/server.go:239-245`). It returns `{"chain": [...]}`, or
    `404 {"error":"no_steward"}`. Each read is audited like `suite.peer.issue`
    (`internal/api/suite_handlers.go:216`).
  - `GET /api/key-steward`, public, like `GET /api/appearance`
    (`internal/api/server.go:268`). Clients read it straight from KyIdentity. Public keys
    are not secret; the cost is that anyone can see the install has a steward.
  - A client for both goes in `ky-primitives/suitedir`, the way KyDrive reads peers today
    (`kydrive:internal/api/kypost.go:174`).

KyIdentity has no "signed suite config" mechanism today: suite answers are authenticated by
client credentials, and suite webhooks by `ky-primitives/syncauth` (`docs/SUITE-DIRECTORY.md:84-87`).
Neither stops KyIdentity itself from lying, so the statement carries its own signatures
instead, and clients pin (section 5).

## 2. Where the private key lives

- **Generated in the KyDrive desktop app**, as the vault spec says
  (`kydrive:docs/superpowers/specs/2026-11-22-e2e-vault-design.md:320`). That app is signed,
  already has the age and hybridsig core (`kydrive-desktop/core`), and is the app that
  opens a vault with the steward anyway (section 4). KyIdentity gets no native tool.
  This puts a small admin screen in the desktop app, which is in willowbank's area
  (kydrive-desktop `feat/vault-native`). This note only proposes it.
- The app shows the fingerprint, then exports the private key **once**, as a file, as text
  and as a QR code. It exports only the seeds (age hybrid identity, ML-DSA-65 and Ed25519
  seeds), so the text and QR stay short (unproven: exact length). Open question 2 covers
  passphrase protection.
- It also writes the **public** statement file, signed by the new key, for the admin to
  upload to KyIdentity.
- The app keeps no copy after export: it does not keep the private key in the OS
  keystore. To rotate, retire or open a vault, the admin imports it again, the app uses it
  in memory for that one operation, then drops it.
- The private key is never uploaded, to KyIdentity, KyDrive or anywhere else. No route in
  either server accepts a field that could carry it. A test checks that no handler accepts
  the private seed format.

## 3. Enterprise-only enforcement at every layer

**How KyIdentity tells Enterprise from shared today: it can't, except by tenancy mode.**
There is no licence, edition or plan flag on an install. A search of `internal` and `cmd`
for `licen[cs]e` and `edition` finds nothing. `orgs.kind` holds only `default`,
`customer` and `staff`; `enterprise` is refused by name (`internal/store/customer_kind_test.go:18`).
Enterprise is defined as "a dedicated install in single-tenant mode"
(`docs/superpowers/specs/2026-11-19-tenancy-design.md:1351-1357`), and every other paid plan
is an org on the shared, multi-tenant install (`:37-41`). So **single-tenant is exactly the
security line**: the steward must never exist where the operator is the only administrator.

What single-tenant does not tell apart is a paying Enterprise customer from anyone else
self-hosting the public image. The smallest marker is an opt-in:

- **Proposed marker:** `KYIDENTITY_KEY_STEWARD=on`, off by default. With it off, the steward
  routes answer `404`. With `KYIDENTITY_TENANCY=multi` it refuses to start. It is a deliberate
  switch, not a licence: the code is public, so a licence check could be patched out and
  protects nothing. Open question 1 asks whether the owner wants a licence anyway.

The layers:

| Layer | Rule | Where it hooks in |
|---|---|---|
| KyIdentity config | `KYIDENTITY_KEY_STEWARD=on` with `KYIDENTITY_TENANCY=multi` refuses to start. | `internal/config/config.go:346-360` |
| KyIdentity startup | A multi-tenant start refuses if `key_stewards` has any row. The recorded mode can't change (`cmd/kyidentity/replica.go:66-73`), so this is a second layer for a database copied by hand. | `checkTenancy`, `cmd/kyidentity/replica.go:66` |
| KyIdentity routes | Every steward route answers `404` in multi-tenant mode, admin and suite alike, like the routes listed as off for multi-tenant (`docs/superpowers/specs/2026-11-19-tenancy-design.md:1348-1349`). | the route table, `internal/api/server.go:392` |
| KyIdentity store | An insert into `key_stewards` raises when `system_settings.tenancy_mode='multi'`, by trigger. Same predicate as `orgEnrollmentEnabled` (`internal/store/org_enrollment.go:13`). | new migration |
| KyDrive config | In multi-tenant mode KyDrive never reads `/api/suite/key-steward`. | `kydrive:internal/config/config.go:266-275` |
| KyDrive store | In multi-tenant mode a vault record that carries a steward wrap, or a `steward-access` record, is refused. A multi-tenant start refuses if the cached steward table has a row. | `CommitVaultRecord`, `kydrive:internal/drive/vault.go:123` |
| Clients | Refuse a steward for an account whose ID token has an `org_id` claim, which only multi-tenant tokens carry (tenancy D4, `docs/superpowers/specs/2026-11-19-tenancy-design.md:53`). Also refuse it for any origin on the app's built-in list of hosted-service origins. | desktop core (willowbank's area) |
| Public images | Multi-tenant is off in every release build: `multiTenantBuild = false` (`internal/config/gate_release.go:5-7`, `kydrive:internal/config/gate_release.go:5-8`). The `kye2e` tag that turns it on appears in neither repo's `Dockerfile` nor workflows (checked by grep). The steward has no default key, so it stays off until an admin registers one. | unchanged |

The server rows stop mistakes and a single compromised server. They cannot stop the
hosted service's own operator, who runs both KyIdentity and KyDrive there and could change
either. Against that operator, only the signed client's built-in list of hosted origins
holds. The `org_id` check also comes from a token that operator issues.

Tests: each row gets a test that fails with its check removed. One case is a multi-tenant
KyDrive that refuses a hand-made record with a steward wrap. Another is a client that
refuses a steward for an `org_id` account.

## 4. How KyDrive learns the key and enforces wraps

**Learning it.** KyDrive reads the chain from `GET /api/suite/key-steward` at start and
every 10 minutes, verifies it (signatures, issuer equal to `KY_KYSIGNON_ISSUER`, serials, the
previous key's signature on each `rotate`), and caches it in a one-table store
`drive_key_steward(serial, statement)`. It serves the chain to devices at
`GET /api/vault/steward` beside the other vault routes (`kydrive:internal/api/vault.go:15-32`).
If KyIdentity cannot be reached, it keeps the cached chain. It never drops back to "no
steward" because a fetch failed. Only a verified `retire` stops enforcement.

**The signed state.** `vault.State` gets one optional field, `steward`,
`{fingerprint, wrap}`. It holds the current generation wrapped to the steward's recipient.
Because it is inside the state, the manager's signature covers it
(`kydrive:internal/vault/record.go:83-93`). The server cannot add, swap or remove a steward
wrap without breaking the record.

**Server checks**, in `CommitVaultRecord` (`kydrive:internal/drive/vault.go:123-215`), when
a steward is registered:

- A `create`, and every record that makes a new generation (`remove`, `role`, `rotate`,
  `kydrive:internal/vault/record.go:175`), must carry `steward` with the current
  fingerprint and a non-empty wrap. Otherwise it is refused with `409 steward_wrap_required`.
- A record that keeps the generation (`add`) must keep `steward` unchanged.
- The server can check that the wrap is present and names the right fingerprint. It
  cannot check that the wrap opens (vault spec, Residual risks, `:378`, "honest-client only").
- With no steward registered, `steward` must be absent.

**Back-fill.** A new change, `steward`, which a manager signs, sets or replaces
`state.steward` and keeps the generation. A manager's client sends it when it opens a vault
whose head has no steward wrap, or one for an older steward fingerprint. A vault whose only
managers never open it stays without a wrap. KyDrive's admin screen lists such vaults by ID
and head only, never by name, as the vault spec says (`:325-327`).

flintmere's recovery work adds a `rekey` change to `VerifyRecord` (board post 9849). The
`steward` change is a separate case in the same switch. Whoever merges second rebases.

**Steward access.** It takes two server events, and both are audited, as in the vault spec
(`:329-339`):

1. **Request.** On KyDrive, an administrator, with a fresh step-up, asks for steward access
   to one vault for one named successor (themselves or another account). KyDrive's step-up is
   tied to a browser session (`kydrive:internal/api/step_up.go:27-36`), and SSO accounts
   confirm through KyIdentity (`:46-48`). Vault routes take signed device requests instead
   (`kydrive:internal/api/vault.go:56`). So the request is made in the web app with step-up,
   like device approval (`kydrive:internal/api/devices.go:28`). It creates a one-time grant,
   bound to the admin's linked desktop device, the vault and the successor, valid for 5
   minutes. Audit: `vault.steward_access_requested` (actor, vault, successor; no names).
2. **Fetch and commit.** The desktop device, signing as usual, calls
   `POST /api/vaults/{id}/steward-access` with the grant. KyDrive spends the grant and
   returns the vault's records. This is the only route that gives a non-member anything of a
   vault, and it gives the log and wraps, not file ciphertext. The desktop app verifies the
   log and the witness checkpoint, opens the steward wrap with the imported private key, and
   wraps the vault key to the successor. It then commits a **`steward-access`** record
   (the vault spec's `escrow-access`, renamed). That record:
   - is signed by the steward's signing key, not by a member;
   - names the steward fingerprint in `signer`;
   - adds exactly one member, the successor, as `manager`, so they can then add or remove
     others. It keeps the generation.

   `VerifyRecord` takes the steward's pinned key for this one change only, and checks that
   `before.State.steward.fingerprint` names it. Audit: `vault.steward_access` (actor,
   vault, successor). It is the same `event` call as every record
   (`kydrive:internal/drive/vault.go:213`).

From then on the successor reads through the ordinary member routes. The `steward-access`
record is in the log, so every member's client shows, in words, that the Key Steward was
used, by whom, for whom and when. The server cannot see the local unwrap. The grant, the
route call and the record are what it audits.

For a leaver, the successor then moves or keeps the files as an ordinary manager. That is
the handover of decision 3, with no server-side handover.

## 5. Key authenticity

The threat (vault spec `:342-355`): a server hands out a steward key it controls, and
receives every vault key wrapped to it. Here either KyIdentity or KyDrive could try.

- **Two sources at first sight.** At first sight a client fetches the chain from KyDrive
  (`/api/vault/steward`) and from KyIdentity (`/api/key-steward`), and pins only when both
  match. Changing the key then means changing both servers. On an Enterprise install both
  belong to the same customer, so this helps against one compromised server, not against
  the customer's own admin. That is intended: the admin holds the steward.
- **Optional managed pin.** The desktop app reads an optional `steward_fingerprint` from its
  managed configuration (MDM or a config file the IT team deploys). When it is set, a
  client refuses any other steward from the first contact on. This closes first-contact
  substitution for organisations that use it. Enterprise customers usually manage their
  devices. The app's config format is unproven here.
- **Pinned for good.** After first sight a client accepts a new steward only through a
  `rotate` signed by the pinned key. A new `register` that is not chained to it, which is
  what a lost-key replacement looks like, is shown as a loud warning. The client wraps
  nothing to it until the user confirms the new fingerprint.
- **Per vault.** Each record carries the steward fingerprint inside the manager-signed state,
  so a server cannot swap the steward for one vault without the client seeing it.
- **Shown.** The current steward fingerprint is shown in every client's vault settings and
  in KyIdentity's admin pane. The client says, in those words, that the steward can open
  every vault on this install.
- **Retire.** A `retire` signed by the steward stops new wraps. A server could forge a
  missing steward, but that only stops new wraps, so it costs recoverability, never
  confidentiality. Clients still show "steward retired" and when. Retiring does not make the
  old wraps useless: whoever holds the old private key can still open every generation it
  wrapped. If the key may have leaked, open question 4 applies.

Key transparency for the steward chain is a later step, as it is for member keys (vault
spec `:355`).

## 6. Other suite apps

KyMessages, KyNotes and KyPost may want the same steward later, so one Enterprise key could
recover a leaver's chats, notes or mail. The statement already names the issuer, not an
app, and KyIdentity publishes it suite-wide, so nothing here would block that. This note
does not design it. See open question 5.

## 7. Questions for the owner

1. **The Enterprise marker.** (a) Single-tenant alone: any self-hosted install may register
   a steward. (b) **Recommended:** single-tenant plus the opt-in `KYIDENTITY_KEY_STEWARD=on`.
   (c) A signed Enterprise licence file checked at start. Why (b): single-tenant is already
   the security line, and the opt-in stops it being turned on by accident. A licence
   protects nothing in public code. It only matters if the steward is meant to be a paid
   feature.
2. **How the exported private key is protected.** (a) Plaintext seeds, kept offline by the
   admin. (b) **Recommended:** the file is age-encrypted to a passphrase the admin picks,
   and the text and QR come in plaintext and passphrase-encrypted forms. (c) Split M-of-N
   (Shamir) among several officers. Why (b): one paper copy is easy to keep. (c) is stronger
   but is new code and a new way to lose the key. It could come later.
3. **Who may use the steward.** (a) Any KyDrive administrator, with step-up. (b)
   **Recommended:** (a), and a member's client also shows the access in their own vault
   history. (c) Two administrators must approve. Why (b): it matches the vault spec. The
   access is visible and audited, and a single holder already holds the private key.
4. **After a retire, or a suspected leak.** (a) Clients only stop wrapping to the old
   steward. (b) **Recommended:** a `retire` or unchained replacement marks every vault
   "rotate on next open", and a manager's client rotates the vault key then. (c) No
   automatic step. Why (b): until rotation, the old key still opens new versions in that
   generation. Rotation costs one record per vault and no re-encryption of files.
5. **Other suite apps.** (a) KyDrive only. (b) **Recommended:** KyDrive only now, with the
   statement and KyIdentity routes kept app-neutral so KyMessages, KyNotes and KyPost can
   use the same steward in their own E2E designs. (c) Design all four now. Why (b): the other
   apps' E2E designs don't exist yet.
6. **Generating the key: the KyDrive desktop app or a separate tool.** (a) **Recommended:**
   the KyDrive desktop app, as the vault spec says. (b) A small standalone KyIdentity
   steward tool. Why (a): it already holds the crypto core and must open vaults with the
   steward. (b) would make sense only if question 5 goes to (c).
7. **The steward-access step-up on a desktop device.** (a) **Recommended:** approved in the
   KyDrive web app with step-up, giving a one-time grant to the desktop device (section 4).
   (b) The desktop app re-authenticates with KyIdentity (`max_age=0`, checked via
   `auth_time`, `internal/oauth/authentication_request.go:47`) and shows the ID token to
   KyDrive. Why (a): it reuses KyDrive's existing step-up and device approval. (b) is
   unproven for the desktop sign-in.

## Build plan (after approval)

1. **KyIdentity:** the `key_stewards` table, statement checks, admin and suite routes, the
   opt-in and every multi-tenant refusal, audit, the admin pane, and the `suitedir` client.
2. **KyDrive server:** the steward cache, `state.steward` checks, the `steward` and
   `steward-access` changes, the grant, the routes, the multi-tenant refusals, audit, and
   the admin list of vaults without a wrap. This builds on S1/S2 and the recovery key
   (lichenford's build order, item 4).
3. **Desktop (willowbank's area):** key generation and export, wrapping, back-fill, the
   access flow, pinning from two sources, and the managed pin.

Each security rule gets a test that fails without it.
