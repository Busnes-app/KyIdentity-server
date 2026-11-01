import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { LAUNCHER_ICONS, SUITE_ICONS, launcherIcon, suiteIconUrl } from './launcherIcons';

// The server rejects any icon name outside its allowlist, so the picker and the allowlist
// must be the same set. Read the Go source rather than trusting either side's memory.
function serverAllowlist(): string[] {
  const go = readFileSync(new URL('../../internal/api/admin_handlers.go', import.meta.url), 'utf8');
  const block = go.match(/var launcherIcons = map\[string\]bool\{([\s\S]*?)\n\}/);
  if (!block) throw new Error('launcherIcons map not found in admin_handlers.go');
  return [...block[1].matchAll(/"([a-z0-9-]+)":\s*true/g)].map((m) => m[1]).sort();
}

describe('launcher icons', () => {
  it('matches the server allowlist exactly, plus favicon', () => {
    const web = ['favicon', ...LAUNCHER_ICONS.map(([name]) => name)].sort();
    expect(web).toEqual(serverAllowlist());
  });

  it('has no duplicate names and resolves each to a component', () => {
    const names = LAUNCHER_ICONS.map(([name]) => name);
    expect(new Set(names).size).toBe(names.length);
    for (const name of names) expect(launcherIcon(name)).toBeDefined();
    expect(launcherIcon('javascript')).toBeUndefined();
  });
});

describe('suite icons', () => {
  it('matches the server suiteIcons list exactly', () => {
    const go = readFileSync(new URL('../../internal/api/icon_handlers.go', import.meta.url), 'utf8');
    const block = go.match(/var suiteIcons = map\[string\]bool\{([\s\S]*?)\n\}/);
    if (!block) throw new Error('suiteIcons map not found in icon_handlers.go');
    const server = [...block[1].matchAll(/"([a-z0-9-]+)":\s*true/g)].map((m) => m[1]).sort();
    expect(SUITE_ICONS.map(([app]) => app).sort()).toEqual(server);
  });

  it('resolves only listed names to a bundled file', () => {
    for (const [app] of SUITE_ICONS) {
      expect(suiteIconUrl(`suite:${app}`)).toBe(`/suite-icons/${app}.png`);
      expect(existsSync(new URL(`../public/suite-icons/${app}.png`, import.meta.url))).toBe(true);
    }
    for (const name of ['suite:', 'suite:../x', 'suite:kydrive/../../api', 'suite:KyDrive', 'suite:KyDash', 'suite:kydash/../../api', 'suite:ky-dashboard', 'kydrive', 'favicon', 'globe', 'icon:kydrive']) {
      expect(suiteIconUrl(name)).toBeUndefined();
    }
  });
});
