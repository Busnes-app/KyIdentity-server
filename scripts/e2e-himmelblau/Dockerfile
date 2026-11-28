# Himmelblau (Community Nightly packages) on Debian 13, for scripts/e2e-himmelblau.sh.
# Stable repositories need a subscription token; nightly is built from Himmelblau main.
# No systemd: rootless containers cannot give the units the namespaces they ask for, so the
# script runs himmelblaud directly as its own unprivileged user.
FROM debian:13@sha256:3cda3ca472ce45507a5109c6a3907093e24d9ae67d55954c9a07a45665dafba2
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gpg pamtester procps \
 && curl -fsSL https://packages.himmelblau-idm.org/himmelblau.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/himmelblau.gpg \
 && echo "deb [arch=amd64 signed-by=/etc/apt/trusted.gpg.d/himmelblau.gpg] https://packages.himmelblau-idm.org/nightly/latest/deb/debian13 ./" > /etc/apt/sources.list.d/himmelblau.list \
 && apt-get update && apt-get install -y --no-install-recommends himmelblau nss-himmelblau pam-himmelblau \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -s /usr/sbin/nologin himmelblaud \
 && printf 'auth required pam_himmelblau.so\naccount required pam_himmelblau.so\n' > /etc/pam.d/kyws-e2e
CMD ["sleep", "infinity"]
