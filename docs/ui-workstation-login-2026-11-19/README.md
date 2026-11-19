# Workstation login, 2026-11-19

App connections gains a **Workstation login** button. It opens the Workstation login view (settings, group access, a generated `himmelblau.conf` and the break-glass note) and its Edit settings dialog. `/device` is the code entry and approval screen in the sign-in frame. The sessions list names a workstation session by its app. "Before" was built from `origin/master` at 09caf1c.

Driver: `capture.mjs` here, over `~/git/ky-redesign/captures/drivers/lib.mjs`. Each run starts from a fresh bootstrap with the relays off, on port 5391, at 1440x900 and 390x844 in Busnes Light and Dark. No shot overflows horizontally (all 32 report `overflow=0`). The issuer in the generated file is the capture server's loopback HTTP issuer; a real one is HTTPS.

| | 1440 light | 1440 dark | 390 light | 390 dark |
| --- | --- | --- | --- | --- |
| App connections, before | ![](kyidentity-app-connections-before-1440-light.png) | ![](kyidentity-app-connections-before-1440-dark.png) | ![](kyidentity-app-connections-before-390-light.png) | ![](kyidentity-app-connections-before-390-dark.png) |
| App connections, after | ![](kyidentity-app-connections-after-1440-light.png) | ![](kyidentity-app-connections-after-1440-dark.png) | ![](kyidentity-app-connections-after-390-light.png) | ![](kyidentity-app-connections-after-390-dark.png) |
| Workstation login | ![](kyidentity-workstation-login-after-1440-light.png) | ![](kyidentity-workstation-login-after-1440-dark.png) | ![](kyidentity-workstation-login-after-390-light.png) | ![](kyidentity-workstation-login-after-390-dark.png) |
| Edit settings dialog | ![](kyidentity-workstation-settings-after-1440-light.png) | ![](kyidentity-workstation-settings-after-1440-dark.png) | ![](kyidentity-workstation-settings-after-390-light.png) | ![](kyidentity-workstation-settings-after-390-dark.png) |
| /device, code entry | ![](kyidentity-device-enter-after-1440-light.png) | ![](kyidentity-device-enter-after-1440-dark.png) | ![](kyidentity-device-enter-after-390-light.png) | ![](kyidentity-device-enter-after-390-dark.png) |
| /device, approval | ![](kyidentity-device-confirm-after-1440-light.png) | ![](kyidentity-device-confirm-after-1440-dark.png) | ![](kyidentity-device-confirm-after-390-light.png) | ![](kyidentity-device-confirm-after-390-dark.png) |
| Settings → Account sessions, before | ![](kyidentity-sessions-before-1440-light.png) | ![](kyidentity-sessions-before-1440-dark.png) | ![](kyidentity-sessions-before-390-light.png) | ![](kyidentity-sessions-before-390-dark.png) |
| Settings → Account sessions, after (workstation session listed) | ![](kyidentity-sessions-after-1440-light.png) | ![](kyidentity-sessions-after-1440-dark.png) | ![](kyidentity-sessions-after-390-light.png) | ![](kyidentity-sessions-after-390-dark.png) |
