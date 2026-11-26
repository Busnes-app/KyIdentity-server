# Everyday tasks

## Account lifecycle

Create the person in the central directory, assign only the required applications/groups and verify delivery at each downstream product. For offboarding, deactivate access and inspect downstream synchronization results; do not infer completion from one successful sign-in or one queued delivery.

## MFA

Configure TOTP, supported WebAuthn passkeys or KyAuth push approvals according to the account policy. Save single-use recovery codes securely. Approve only your own sign-in and match the number displayed by the browser. Revoke a lost device from Devices.

## Set up and recover your suite keyring

In **Settings → Suite keyring**, choose **Set up keyring**. Print or download the
Suite Emergency Kit, store it somewhere you can reach without the trusted
browser, and re-enter its recovery key to finish. An Emergency Kit unlocks suite
keys after you sign in. Keep your MFA recovery codes separately so you can
recover your sign-in as well.

To link a new browser, sign in there and choose **Get approval code** in the
keyring. Enter that code on a trusted browser, confirm your identity, then
choose **Finish linking** on the new browser. If every trusted browser is lost,
sign in and choose **Use an Emergency Kit**. A compatible WebAuthn PRF passkey
can also unlock the keyring if one was registered beforehand.

Revoke lost browsers or keyring passkeys from the list of trusted methods.
When you rotate the Emergency Kit, confirm the replacement before discarding
the old copy.

## Application access

Maintain explicit product administrator roles where required. Global identity administration does not imply access to all product data. Use the suite launcher to open assigned apps and verify ordinary and administrator access separately.

## HR provisioning

Where the generic HR integration is configured, KyIdentity stages the source UID, obtains the confirmed work address from KyPost, then creates the SSO account. A vendor-specific HR connector requires its own qualification; the generic workflow is not evidence of Workday compatibility.
