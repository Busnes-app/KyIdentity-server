# Windows 11 domain-join proof: design

Date: 2026-11-19. Worker `ws-win11`. Follows the approved plan
(`ky-redesign/workstation-login/DESIGN.md`) and the Active Directory design
([`2026-11-19-active-directory-design.md`](2026-11-19-active-directory-design.md)).

## Goal

The AD connector and DC agent (#256) are proven with `kinit` and `smbclient` only. This adds
a re-runnable manual check, `scripts/e2e-win11-domain.sh`, that joins a fresh Windows 11 Pro
VM to the Samba AD DC KyIdentity feeds, and proves at the real Windows logon: join, logon,
password change, disable, cached logon, and the "Remove Change Password" baseline GPO. It is
a release check, not CI: it needs about 30 GB of disk and an hour.

No product code changes unless Windows logon fails because of KyIdentity or the agent.

## Threat model (of the test harness)

The harness is lab-only, and it must not weaken the shared host or leak anything.

- **The host.** The VM runs in a `dockurr/windows` container pinned by digest, capped by
  docker (`--memory 8g --memory-swap 8g --cpus 4 --pids-limit`), guest RAM 6 GB. It needs
  `/dev/kvm`, `/dev/net/tun` and `NET_ADMIN` (its NAT bridge lives in its own network
  namespace). The web viewer and RDP ports publish on `127.0.0.1` only, on an ephemeral
  host port so nothing collides with other workers. Every object is `kyws-win11-*` and
  only those are removed.
- **The VM is untrusted and disposable.** Microsoft's ISO is fetched by the container from
  Microsoft's servers. Nothing in the VM is trusted for the result except what the host
  reads back: files the VM writes to the shared folder, and QEMU screendumps the host takes
  itself.
- **The command channel** is a SYSTEM scheduled task that runs `.ps1` files the host drops
  in the shared folder (reached by address, so Windows uses NTLM to the guest share). That share is the container's own Samba on the container-internal
  bridge, reachable only from the VM; anything in the VM could write to it, which is local
  privilege escalation inside a throwaway lab VM. Accepted; documented. No WinRM listener is
  opened, so the VM exposes no remote-management port at all.
- **Secrets.** Test passwords are fixed fixtures for throwaway accounts, as in
  `TestSambaADEndToEnd`. AutoAdminLogon puts the logon password in the VM's registry
  (`DefaultPassword`, plaintext); the harness deletes it after each logon and the VM is
  deleted at the end. The DC administrator password is random per run, lives in a 0600
  work directory and reaches the VM only inside the join command file, which is deleted
  after use. Nothing secret is printed or written into the repository.
- **Network.** The VM reaches the DC through the container's NAT on a private docker
  network. KyIdentity runs in-process in `go test` on loopback; only the agent (on the host)
  talks to it. `PUSH_RELAY_URL` and `APNS_RELAY_URL` are empty. No mail is sent.

## Lab deviations from a real PC

`dockurr/windows` configures the VM for convenience, and a real fleet would not: UAC off,
Windows Firewall off, SMB guest access allowed and SMB signing not required (for its shared
folder), autologon of its local `Docker` administrator. Its answer file installs with
Microsoft's published generic Windows 11 Pro setup key, which selects the edition and
cannot activate; no `KEY` is passed and Windows stays unactivated (owner decision). None of
these changes how a domain logon is authenticated, but results are from this VM, not a
hardened image.

## Data stored and protection at rest

Nothing new in KyIdentity. The run keeps, until cleanup: the VM disk (docker volume
`kyws-win11-storage`, ~30 GB), the shared folder and work directory under a `mktemp -d`
(mode 0700). Cleanup removes all of them and reports `df` before and after.
`E2E_WIN11_KEEP=1` keeps the VM for debugging and prints how to remove it.

## Routes and listeners

No new KyIdentity route. Listeners the run opens:

| Listener | Bound to | Auth |
|---|---|---|
| noVNC web viewer (8006) | `127.0.0.1:<ephemeral>` | none (loopback only) |
| RDP (3389) | `127.0.0.1:<ephemeral>` | Windows logon |
| QEMU monitor | Unix socket inside the container | `docker exec` only |
| Samba share `Data` | container-internal bridge, VM only | guest |
| Samba AD DC (LDAPS, Kerberos, DNS, SMB) | private docker network | AD |
| KyIdentity (test) | `127.0.0.1:<ephemeral>` | as in production |

## How each step is proven

KyIdentity and the agent are driven from `TestWin11DomainEndToEnd` (skipped unless the
script runs it), which calls back into the script's `win_*` helpers, the same pattern as
`TestSambaADEndToEnd`'s `dc` helper. Whether a logon happened is decided only from SYSTEM's
view after the reboot: Security-log 4624 (logon type 2 online, 11 cached credentials), 4625
with its substatus, and `query user`. The user's own session adds a report (`whoami /upn`,
`klist`, the policy value), written locally and relayed by the poller, because a disabled or
offline user may not reach the share and `whoami /upn` blocks while the DC is unreachable.
Screendumps are evidence for a reader, not for the assertions.

1. Join: `Add-Computer` as the domain administrator, reboot, then `Test-ComputerSecureChannel`.
2. Interactive logon: AutoAdminLogon once as `KYWS\winuser` with the password the user set
   in KyIdentity; an online (type 2) logon, and the session reports the UPN and a
   `krbtgt/KYWS.TEST` ticket.
3. Password change in KyIdentity, agent delivery: autologon with the old password is refused
   (4625, `0xC000006A`), the new one logs on online.
4. Disable in KyIdentity, sync. Measured under Windows' default policy, then asserted under
   the baseline GPO: refused (4625, `0xC0000072`) with no logon at all, cached or not.
5. Cached logon, measured: the DC is made unreachable from the PC (a DROP rule in the VM
   container, which routes the VM), then the user logs on again; once for an active user and
   once for a user disabled in KyIdentity after their last online logon.
6. Baseline GPO (`samba-tool gpo create`/`load`/`setlink`, linked at the domain root):
   Remove Change Password (user) and Always wait for the network at computer startup and
   logon (computer). After `gpupdate` and a logon the user hive holds
   `DisableChangePassword=1`; screenshots of Ctrl-Alt-Del before and after.

### Found while building it

- Under Windows' default policy a user disabled in AD, with the DC **reachable**, still got a
  desktop at boot from cached credentials (4624 type 11); the background check failed with
  `0xC0000072` and the session stayed. Seen on every try (three). "Always wait for the network
  at computer startup and logon" makes Windows check the DC first, and the logon is refused.
  It joins the documented baseline.
- `docker pause` is no way to take a DC down: the frozen container's kernel still completes
  TCP handshakes, so Windows hangs instead of failing over. The DROP rule behaves like a DC
  that is off or a laptop off site.
- By name, SYSTEM's SMB client tried Kerberos for `cifs/host.lan` and its share writes
  blocked while the DC was unreachable; the poller reaches the share by address (NTLM).
- The host writes into the share behind Samba, so no lease break refreshes Windows' cached
  directory listing; the VM setup turns the SMB client's caches off.

## Defaults

- VM: Windows 11 Pro (`VERSION=11`), 6 GB guest RAM, 4 vCPU, 64 GB sparse disk, image
  pinned by digest. Override nothing else.
- Run removes everything unless `E2E_WIN11_KEEP=1`.
- `scripts/e2e-samba-ad.sh` gains `E2E_DC_PREFIX` (default `kyws-windows`, unchanged) so this
  run's DC is `kyws-win11-dc` and cannot collide with a concurrent `samba-ad` run.

## Not built

- No CI job (size, time, KVM). CI shellchecks the script only.
- No WinRM, no QEMU guest agent install, no RDP automation.
- No hardened GPO set beyond the one documented baseline item; NTLM restriction and LAPS
  are not exercised.
- No activation, Entra, Intune, KyQuickStart DC deployment.

## Multi-tenant mode

Nothing here stores data. The AD design's tenancy section already covers the connector;
a multi-tenant run would need a DC (and OU) per org, which this script would model as one
run per org.
