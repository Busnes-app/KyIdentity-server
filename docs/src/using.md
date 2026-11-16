# Everyday tasks

## Account lifecycle

Create the person in the central directory, assign only the required applications/groups and verify delivery at each downstream product. For offboarding, deactivate access and inspect downstream synchronization results; do not infer completion from one successful sign-in or one queued delivery.

## MFA

Configure TOTP, supported WebAuthn passkeys or KyAuth push approvals according to the account policy. Save single-use recovery codes securely. Approve only your own sign-in and match the number displayed by the browser. Revoke a lost device from Devices.

## Application access

Maintain explicit product administrator roles where required. Global identity administration does not imply access to all product data. Use the suite launcher to open assigned apps and verify ordinary and administrator access separately.

## HR provisioning

Where the generic HR integration is configured, KyIdentity stages the source UID, obtains the confirmed work address from KyPost, then creates the SSO account. A vendor-specific HR connector requires its own qualification; the generic workflow is not evidence of Workday compatibility.
