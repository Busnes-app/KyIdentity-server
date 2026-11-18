# Troubleshooting

- **OIDC callback rejected:** compare issuer, client ID and exact callback URI with the consuming product's registration.
- **User can sign in but lacks administration:** inspect the product's explicit app role; SSO alone is insufficient.
- **Directory change has not arrived:** inspect Suite sync delivery status and the configured connector. Resume an uncertain delivery only after checking the downstream result.
- **Push absent:** check device registration, notification permission and the selected FCM/APNs/UnifiedPush/Ubuntu Push transport.
- **Pairing code expired:** issue a fresh code and complete the flow within its lifetime.
- **A replica refuses to start:** the log names the settings that differ from the other replicas' (`this replica's configuration differs ... : KYIDENTITY_ISSUER_URL`), never their values. Give it the same values as the others. After changing a shared setting on purpose, stop every replica, change it everywhere, run `kyidentity accept-replica-config` once and start them. A different `KYIDENTITY_ENCRYPTION_KEY` is never accepted: supply the key the others use.
- **Requests answer 503 `request_timeout` or `temporarily_unavailable`:** the database did not answer in time. The request may still take effect once it does, so check before repeating a change; `/readyz` shows when the database is back.
- **Potentially compromised device:** revoke it and follow the account's recovery process; keep tokens and recovery codes out of reports.

When reporting a problem, include the product version, platform, failed task and a redacted error. Exclude pairing links, device secrets, recovery codes, custodian shares and private content.
