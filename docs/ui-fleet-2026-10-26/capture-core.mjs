// Shared driver for the 2026-10-26 fleet Appearance captures. A product adapter supplies
// start (a disposable loopback server), signIn (the real login form) and surfaces; this file
// owns the light/dark x 1280x900/390x844 batch and the manifest. Synthetic data only.
// Usage: node capture.mjs <prefix e.g. kyidentity-00-before> [surface,...]
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir, release, platform } from 'node:os';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const git = (repo, ...args) => execFileSync('git', ['-C', repo, ...args], { maxBuffer: 64 << 20 });

// Playwright comes from the product's own dev dependencies, else KY_PLAYWRIGHT (a path to
// an installed @playwright/test) for products whose web/ has no browser harness.
async function playwright(repo) {
  const own = join(repo, 'web/node_modules/@playwright/test/index.mjs');
  const path = existsSync(own) ? own : process.env.KY_PLAYWRIGHT;
  if (!path) throw new Error('set KY_PLAYWRIGHT to an @playwright/test/index.mjs');
  return import(pathToFileURL(path).href);
}

export async function waitReady(url, ms = 60000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try { if ((await fetch(url)).status < 500) return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`server at ${url} not ready`);
}

export async function run(adapter) {
  const [prefix, only] = process.argv.slice(2);
  if (!prefix) throw new Error('usage: node capture.mjs <prefix> [surface,...]');
  const repo = adapter.repo;
  const out = join(repo, 'docs/ui-fleet-2026-10-26/screenshots');
  await mkdir(out, { recursive: true });
  const names = only ? only.split(',') : Object.keys(adapter.surfaces);
  const scratch = await mkdtemp(join(tmpdir(), `ky-fleet-${adapter.product}-`));
  const { chromium } = await playwright(repo);
  const server = await adapter.start(scratch);
  const browser = await chromium.launch();
  const driver = `playwright chromium ${browser.version()} (headless)`;
  const binarySha = server.binary ? sha256(await readFile(server.binary)) : null;
  const files = [];
  try {
    for (const theme of ['light', 'dark']) {
      for (const [device, viewport] of [['desktop', { width: 1280, height: 900 }], ['mobile', { width: 390, height: 844 }]]) {
        // OS-following default: no saved choice, the browser reports the colour scheme.
        const context = await browser.newContext({ baseURL: server.baseURL, viewport, colorScheme: theme, deviceScaleFactor: 1, timezoneId: 'America/Chicago', locale: 'en-US' });
        const page = await context.newPage();
        const step = async (what, fn) => {
          try { await fn(); } catch (err) {
            await page.screenshot({ path: join(scratch, '..', `ky-fleet-${adapter.product}-failed.png`) }).catch(() => {});
            console.error(`${what} failed at ${page.url()}:`, (await page.locator('body').innerText().catch(() => '')).slice(0, 600));
            throw err;
          }
        };
        await step('sign-in', () => adapter.signIn(page, server));
        for (const surface of names) {
          await step(surface, () => adapter.surfaces[surface](page, { device, theme, server }));
          await page.mouse.move(0, 0);
          await page.waitForTimeout(400);
          const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
          const file = `${prefix}-${surface}-${device}-${theme}.png`;
          const png = await page.screenshot({ path: join(out, file) });
          files.push({ file, sha256: sha256(png), surface, viewport: `${viewport.width}x${viewport.height}`, theme: `os-${theme} (no saved choice)`, overflow_px: overflow, full_page: false });
          console.log(file);
        }
        await context.close();
      }
    }
  } finally {
    await browser.close();
    await server.stop();
    await rm(scratch, { recursive: true, force: true });
  }
  // The capture describes HEAD plus any uncommitted source; hash that diff so it can be matched.
  const diff = git(repo, 'diff', 'HEAD', '--', '.', ':(exclude)docs/ui-fleet-2026-10-26');
  const manifest = {
    prefix,
    product: adapter.product,
    branch: git(repo, 'rev-parse', '--abbrev-ref', 'HEAD').toString().trim(),
    head: git(repo, 'rev-parse', 'HEAD').toString().trim(),
    uncommitted_diff_sha256: diff.length ? sha256(diff) : null,
    uncommitted_diff_bytes: diff.length,
    server_binary_sha256: binarySha,
    embedded_index_sha256: adapter.dist && existsSync(adapter.dist) ? sha256(await readFile(adapter.dist)) : null,
    captured: new Date().toISOString(),
    os: `${platform()} ${release()}`,
    driver,
    device_scale_factor: 1,
    timezone: 'America/Chicago',
    locale: 'en-US',
    theme_source: 'context colorScheme emulation with no saved theme choice (OS-following default)',
    fixture: adapter.fixture,
    files,
  };
  await writeFile(join(out, `${prefix}-manifest.json`), JSON.stringify(manifest, null, 2) + '\n');
}

export const here = (url) => dirname(new URL(url).pathname);
