# Throwaway Samba AD DC for the KyIdentity AD e2e test (scripts/e2e-samba-ad.sh).
# Provisioning happens at run time; the image only carries the packages.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache samba-dc samba-client krb5 openldap-clients openssl python3 bash
# The container idles until the test script copies in certificates and provisions.
CMD ["sleep", "infinity"]
