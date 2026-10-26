"""Prove the optional profile preserves resolved Compose configuration; start nothing."""

import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="kyidentity-profile-check-") as directory:
    fixture = Path(directory) / ".env"
    fixture.write_text(
        "KYIDENTITY_ISSUER_URL=https://identity.example.invalid\n"
        "KYIDENTITY_DNS=192.0.2.53\n"
        "KYIDENTITY_SECRET_KEY=" + "ab" * 32 + "\n"
        "KYIDENTITY_ENCRYPTION_KEY=" + "cd" * 32 + "\n"
    )
    env = {key: value for key, value in os.environ.items() if not key.startswith(
        ("COMPOSE_", "KYIDENTITY_", "KYSIGNON_", "PUSH_RELAY_", "APNS_RELAY_", "BOOTSTRAP_ADMIN_", "TRUSTED_PROXY_")
    )}
    def render(files):
        command = ["docker", "compose", "--project-name", "kyidentity-profile-check", "--env-file", str(fixture)]
        for file in files:
            command += ["-f", file]
        return json.loads(subprocess.check_output(command + ["config", "--format", "json"], cwd=root, env=env))
    for overlays in [[], ["docker-compose.build.yml"], ["docker-compose.lan-dns.yml"], ["docker-compose.build.yml", "docker-compose.lan-dns.yml"]]:
        files = ["docker-compose.yml", *overlays]
        baseline = render(files)
        configured = render([*files, "docker-compose.strong-crypto.yml"])
        assert configured["services"]["kyidentity-server"]["environment"].pop("GODEBUG") == "fips140=on"
        assert configured == baseline, "The strong profile changed another Compose setting"
print("All four Compose chains retain data, keys, credentials, image/build, network and DNS configuration.")
