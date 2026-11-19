# Himmelblau (Community Nightly packages) on Debian 13 with systemd, for scripts/e2e-himmelblau.sh.
# Stable repositories need a subscription token; nightly is built from Himmelblau main.
FROM debian:13
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gpg pamtester procps systemd systemd-sysv \
 && curl -fsSL https://packages.himmelblau-idm.org/himmelblau.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/himmelblau.gpg \
 && echo "deb [arch=amd64 signed-by=/etc/apt/trusted.gpg.d/himmelblau.gpg] https://packages.himmelblau-idm.org/nightly/latest/deb/debian13 ./" > /etc/apt/sources.list.d/himmelblau.list \
 && apt-get update && apt-get install -y --no-install-recommends himmelblau nss-himmelblau pam-himmelblau \
 && rm -rf /var/lib/apt/lists/*
CMD ["/sbin/init"]
