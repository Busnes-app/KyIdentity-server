# Troubleshooting

- **OIDC callback rejected:** compare issuer, client ID and exact callback URI with the consuming product's registration.
- **User can sign in but lacks administration:** inspect the product's explicit app role; SSO alone is insufficient.
- **Directory change has not arrived:** inspect Suite sync delivery status and the configured connector. Resume an uncertain delivery only after checking the downstream result.
- **Push absent:** check device registration, notification permission and the selected FCM/APNs/UnifiedPush/Ubuntu Push transport.
- **Pairing code expired:** issue a fresh code and complete the flow within its lifetime.
- **Potentially compromised device:** revoke it and follow the account's recovery process; keep tokens and recovery codes out of reports.

When reporting a problem, include the product version, platform, failed task and a redacted error. Exclude pairing links, device secrets, recovery codes, custodian shares and private content.
