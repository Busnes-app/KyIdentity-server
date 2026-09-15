# Logging

KyIdentity must emit structured, privacy-safe application logs to standard output
and standard error. It must not build or require a KySecurity-specific log
database, log search system, or long-term retention service.

Operators may route container logs to an existing platform such as Loki,
OpenSearch, Elasticsearch, Graylog, or another OpenTelemetry-compatible
collector.

Log login outcomes, authorization-code events, token issuance and revocation,
MFA challenges, recovery-code use, client changes, session revocation, and
administrative actions. Use request IDs and coarse actor identifiers where
useful.

Never log passwords, password-derived values, client secrets, access or refresh
tokens, signing keys, TOTP values, recovery codes, authorization codes, or raw
request bodies. Audit records must remain content-blind.

Do not add an embedded log database or product-specific log viewer. Operators
should use their existing logging platform for search, alerting, retention, and
access control.
