# Troubleshooting

- **OIDC callback rejected:** compare issuer, client ID and exact callback URI with the consuming product's registration.
- **User can sign in but lacks administration:** inspect the product's explicit app role; SSO alone is insufficient.
- **Directory change has not arrived:** inspect Suite sync delivery status and the configured connector. Resume an uncertain delivery only after checking the downstream result.
- **Push absent:** check device registration, notification permission and the selected FCM/APNs/UnifiedPush/Ubuntu Push transport.
- **Pairing code expired:** issue a fresh code and complete the flow within its lifetime.
- **A server on PostgreSQL refuses to start:** the log names the settings that differ from the configuration recorded by an earlier start (`this server's configuration differs ... : KYIDENTITY_ISSUER_URL`), never their values. This applies to a single server on PostgreSQL as well as to replicas. If the change was a mistake, give the server the recorded values. After changing a shared setting on purpose: stop every server, run `kyidentity accept-replica-config` once with the servers' full environment (with Compose, `docker compose run --rm --no-deps kyidentity-server accept-replica-config`), then start them. A different `KYIDENTITY_ENCRYPTION_KEY` is never accepted: supply the recorded key.
- **Requests answer 503 `request_timeout` or `temporarily_unavailable`:** the database did not answer in time. The request may still take effect once it does, so check before repeating a change; `/readyz` shows when the database is back.
- **The browser shows "could not check your session":** the server could not look the session up (a database outage) and answered 503. You are not signed out; choose Try again once the server answers. A sign-in link (`/oauth/authorize`) answers the same 503 as JSON for the same reason.
- **The backup page shows "Unknown":** its status could not be read. Pairing, pinning and the schedule are withheld until it can be; choose Refresh.
- **Potentially compromised device:** revoke it and follow the account's recovery process; keep tokens and recovery codes out of reports.

When reporting a problem, include the product version, platform, failed task and a redacted error. Exclude pairing links, device secrets, recovery codes, custodian shares and private content.
