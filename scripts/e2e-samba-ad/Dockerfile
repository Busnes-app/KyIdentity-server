# Throwaway Samba AD DC for the KyIdentity AD e2e test (scripts/e2e-samba-ad.sh).
# Provisioning happens at run time; the image only carries the packages.
FROM alpine:3.24
RUN apk add --no-cache samba-dc samba-client krb5 openldap-clients openssl python3 bash
# The container idles until the test script copies in certificates and provisions.
CMD ["sleep", "infinity"]
