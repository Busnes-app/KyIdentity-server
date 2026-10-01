**Repo:** kyidentity-server, kyauth-android
**PR:** #68 — https://github.com/Busnes-app/KyIdentity-server/pull/68
**PR:** KyAuth #16 — https://github.com/Busnes-app/KyAuth-android/pull/16
**Worktree:** none (plan only)

# Attestation verification plan

Date: 2026-09-30. Owner: wren. Scope: everything in KyIdentity #68 and KyAuth #16 that
was compiled, unit-tested or reasoned about but never observed on real hardware or a
real deployment. Spec: `kyauth-android/docs/superpowers/specs/2026-09-30-device-signon-attestation-design.md`.

Record each check below as PASS, FAIL or SKIPPED with the date, the KyAuth build
(Play, release or debug), the phone model and the KyIdentity commit. A FAIL is a bug
report, not a note; file it before moving on.

## Evidence already available

- KyIdentity: 33-case refusal table against a test CA, chain/key/level/policy/app-id
  checks, status-list staleness, grade persisted in the same statement as the key,
  grant evidence from the assertion `iat`, locked-bootloader setting, daily sweep.
  Race suite green; security audit P2 resolved.
- KyAuth: challenge derivation matches the server byte for byte; on emulator Pixel_10
  (software KeyMint) the regenerated key has an attestation chain whose leaf carries
  the extension with the given challenge and whose key equals the registered SPKI.
  The emulator grades `none`, which is the honest emulator result.
- Nothing below has been observed. Emulators cannot produce a passing chain.

## Setup

- A KyIdentity at or after #68, reachable over HTTPS, with
  `KYIDENTITY_ATTESTATION_STATUS_URL` left at its default and
  `KYIDENTITY_KYAUTH_CERT_SHA256` left at its default (the Play digest).
- A Play-installed KyAuth at or after #16 on a phone with a secure lock screen. Note
  whether the phone has StrongBox (Pixel 3 and later, most Samsung flagships).
- One user with push MFA enrolled and organisation MFA mandatory, one KyPost (or any
  consumer) app registered for device sign-on.

## 1. The positive path

1. Pair the phone (QR or manual PIN). Expected: pairing succeeds; KyAuth Settings shows
   "Attested: StrongBox" or "Attested: TEE" with "Bootloader locked." on the next line.
2. KyIdentity devices page for that user. Expected: the same badge; boot state
   `locked-verified`. Audit log: `device.registered` with `attestedLevel`,
   `bootState: locked-verified` and an empty `attestationReason`.
3. Capture the chain. From the server, read `attestation_serials` for the device, and
   from the audit row confirm the level. Then export the raw chain for the golden
   fixture: temporarily log or dump the `attestation` array from one registration
   (do not commit the dump itself; commit only the certificates, which are public).
   Add it as `internal/attest/testdata/<phone>-<date>.json` with a test that expects
   `tee` or `strongbox` against the embedded roots and a frozen `Now`. This also
   proves Go's `x509.ParseCertificate` and `CheckSignatureFrom` accept a real device
   chain.
4. Push MFA with the new key. Approve one push challenge. Expected: approved; the
   server verifies the signature with the rotated key.
5. Sign in to the consumer app with the KyIdentity account. Expected: success for an
   account with MFA mandatory. Decode the ID token: `amr` is `["hwk","user","mfa"]`,
   `acr` is `urn:kysignon:acr:mfa`, `attested` is `tee` or `strongbox`, `auth_time`
   equals the assertion's `iat` (within a second of the biometric prompt). Audit:
   `device.signon`.

## 2. Failure paths never executed on a device

6. Failed re-pair. On the paired phone, scan a pairing QR, wait past its expiry, then
   confirm. Expected: a dialog saying the phone is no longer paired and must be paired
   again, with the server's reason; the app returns to the pairing screen; the
   KyIdentity login passkey still signs in afterwards. Then pair again. Expected: a new
   key, attested again.
7. Unpair from Settings, then pair again. Expected: Unpair removes the login passkey
   (unlike the failed re-pair); re-pair attests.
8. Phone with no secure lock screen (remove the PIN temporarily, or use a spare
   phone). Expected: pairing fails with the keystore's error, not a silent `none`.
   Restore the PIN.
9. Debug or sideloaded KyAuth build (not Play-signed). Pair. Expected: pairing
   succeeds at level `none`; Settings says "The server did not accept this build's
   attestation. Pairing again will not help until the server trusts this build."
   Audit reason: "attested app signature not pinned". Then add the build's digest to
   `KYIDENTITY_KYAUTH_CERT_SHA256`, restart, re-pair. Expected: attested.
10. Older server. Point KyAuth at a KyIdentity before #68 (or a stub that omits
    `device.attestedLevel`). Expected: pairing succeeds; Settings says "This KyIdentity
    server does not check attestation yet."

## 3. Server policy switches

11. Admin → enrollment policies → "Device sign-on" → turn on "Require a locked
    bootloader" (step-up prompt). Expected: audit `admin.attestation_configured` with
    old/new. Re-pair the locked phone. Expected: still attested.
12. With the setting on, pair a phone with an unlocked bootloader if one is available.
    Expected: level `none`, reason "bootloader not locked (unlocked)", Settings shows
    the "did not accept" hint. Turn the setting off and re-pair. Expected: attested,
    Settings shows "Bootloader unlocked." on the second line.
13. Sweep. With the setting on and an attested-but-unlocked device from step 12 (pair
    it with the setting off first), restart KyIdentity so housekeeping runs. Expected:
    audit `device.attestation_downgraded` with the reason; the devices page shows "Not
    attested"; the next sign-in from that phone is refused where MFA is mandatory.
14. App policy max age. Set the consumer app's sign-in policy to `fresh` with max age
    60 s. Sign in normally. Expected: issued, `expires_in` at most 60. Then, on a test
    client, mint an assertion, wait 90 s (inside the 300 s window), and exchange it.
    Expected: `invalid_grant` `signon_not_permitted`, no session, no issued token.
15. Organisation that disallows push. Set the enrollment policy's allowed methods to
    TOTP only. Sign in from the attested phone. Expected: `signon_not_permitted`.
    Restore the policy.
16. Attested device under the default policy, with an unattested second phone paired
    to the same user. Expected: the attested phone signs in; the unattested one is
    refused where MFA is mandatory and gets `amr ["pop"]` where it is not.

## 4. Operational

17. Status list unreachable. Set `KYIDENTITY_ATTESTATION_STATUS_URL` to an unreachable
    HTTPS host, restart, pair. Expected: level `none`, reason "status list
    unavailable", a startup log line for the failed refresh, and a retry log line on
    the next 15-minute housekeeping tick. Restore the URL; the next tick loads it and
    a re-pair attests. Already-attested devices were not downgraded meanwhile.
18. Status list disabled. Set the URL to empty. Expected: startup warning; pairing
    attests; `Stale()` never triggers refetches (no refresh log lines).
19. Roots refresh. Watch the daily refresh log. Expected: no "root not embedded"
    warning unless Google publishes a new root; if one appears, verify its fingerprint
    against https://android.googleapis.com/attestation/root before trusting it, then
    add it to `roots.json`.
20. Re-pair resets. Pair attested, then pair again from a build that cannot attest
    (step 9) with the same device identifier. Expected: the row drops to `none`; no
    stale grade survives the new key.

## 5. KyAuth instrumented test on hardware

21. On an UNPAIRED phone (the test deletes the production key alias), run
    `./gradlew :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.kysecurity.authenticator.pairing.DeviceSigningKeyAttestationTest`.
    Expected: 3 of 3 pass and `AttestationReason.leafSecurityLevel` reports 1 or 2.
    Also run `IdentityPasskeyKeyTest`; its four gated tests should run instead of
    skipping, which closes the separate "KyIdentity passkey hardware backing is
    unverified" item in the KyAuth AGENTS.md.

## Record

| # | Result | Date | Build / phone / server | Notes |
|---|--------|------|------------------------|-------|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |
| 7 | | | | |
| 8 | | | | |
| 9 | | | | |
| 10 | | | | |
| 11 | | | | |
| 12 | | | | |
| 13 | | | | |
| 14 | | | | |
| 15 | | | | |
| 16 | | | | |
| 17 | | | | |
| 18 | | | | |
| 19 | | | | |
| 20 | | | | |
| 21 | | | | |
