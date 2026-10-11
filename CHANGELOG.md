# Changelog

## Unreleased

- Add UnifiedPush as a second push MFA transport: RFC 8291 encrypted, sent directly to the device's distributor, no relay needed. Push token refresh is now `kyidentity-push-token-v2`, which signs transport and keys; v1 is no longer accepted.
- Add administrator and step-up protected signed recovery evidence for paired KyPost systems, including current app scope, explicit inactive subjects and retained sync revisions. Refuse held authority and incomplete output; restore holds remain unchanged. See [the contract](docs/KYPOST_RECOVERY_EVIDENCE.md).
