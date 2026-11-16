# Getting started

## Prepare the identity service

Follow the product reference for the server, database, HTTPS origin and durable secrets. Configure the reverse proxy and forwarded-address trust for the actual proxy. Complete bootstrap sign-in and establish a recovery method before enrolling MFA.

## Add an application

Register the product using its documented client identifier and exact OIDC callback URI. Configure the product with that issuer and its client credentials. Set up the product's supported provisioning connector separately: successful SSO does not prove directory sync or administrator access.

## Enrol a device

Generate a new pairing code on Devices and complete KyAuth pairing within 90 seconds. Test a number-matched push approval and retain a second way into the account. Application administrator identities and everyday identities have separate purposes and grants.
