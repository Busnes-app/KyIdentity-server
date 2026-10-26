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

// In-app theme transition check: named light theme with a hovered idle nav row and a
// keyboard-focused card, then Busnes Dark, Busnes Light and Match system. Asserts computed
// colours in the real product CSS, which the shared fixture cannot show.
// Usage: node capture.mjs --verify <prefix>
const luminance = (rgb) => {
  // rgb() is 0-255; color(srgb ...) from color-mix() is 0-1.
  const scale = rgb.startsWith('color(') ? 1 : 255;
  const [r, g, b] = rgb.match(/[\d.]+/g).slice(0, 3).map(Number).map((v) => v / scale).map((v) => v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};

export async function verify(adapter) {
  const prefix = process.argv[3];
  if (!prefix) throw new Error('usage: node capture.mjs --verify <prefix>');
  const repo = adapter.repo;
  const out = join(repo, 'docs/ui-fleet-2026-10-26/screenshots');
  await mkdir(out, { recursive: true });
  const scratch = await mkdtemp(join(tmpdir(), `ky-fleet-${adapter.product}-`));
  const { chromium } = await playwright(repo);
  const server = await adapter.start(scratch);
  const browser = await chromium.launch();
  const results = [];
  const check = (name, ok, detail) => { results.push({ name, ok, detail }); console.log(`${ok ? 'PASS' : 'FAIL'} ${name} ${JSON.stringify(detail)}`); };
  try {
    const context = await browser.newContext({ baseURL: server.baseURL, viewport: { width: 1280, height: 900 }, colorScheme: 'dark', deviceScaleFactor: 1 });
    const page = await context.newPage();
    await adapter.signIn(page, server);
    await adapter.surfaces[adapter.appearanceSurface ?? 'appearance'](page, { device: 'desktop', theme: 'dark', server });
    const radio = (name) => page.getByRole('radio', { name: new RegExp(`^${name}\\b`) }).first();
    const probe = async () => page.evaluate(() => {
      const root = document.documentElement;
      return { inlineBg: root.style.getPropertyValue('--bg'), body: getComputedStyle(document.body).backgroundColor, scheme: getComputedStyle(root).colorScheme };
    });
    for (const [name, light] of [['Sky', true], ['Sun', true], ['Busnes Dark', false], ['Busnes Light', true], ['Match system', false]]) {
      await radio(name).check();
      await page.waitForTimeout(500); // body has a 0.2s colour transition
      const state = await probe();
      check(`${name}: page background`, (luminance(state.body) > 0.4) === light, state);
      const item = adapter.hoverTarget(page);
      await item.hover();
      await page.waitForTimeout(400);
      const hovered = await item.evaluate((el) => ({ bg: getComputedStyle(el).backgroundColor, ink: getComputedStyle(el).color }));
      const bg = hovered.bg === 'rgba(0, 0, 0, 0)' ? state.body : hovered.bg;
      const [hi, lo] = [luminance(bg), luminance(hovered.ink)].sort((a, b) => b - a);
      check(`${name}: hovered nav row contrast`, (hi + 0.05) / (lo + 0.05) >= 4.5, { ...hovered, ratio: ((hi + 0.05) / (lo + 0.05)).toFixed(2) });
      const current = page.locator('[aria-current="page"]').first();
      if (await current.count()) {
        const sel = await current.evaluate((el) => ({ bg: getComputedStyle(el).backgroundColor, ink: getComputedStyle(el).color }));
        const [shi, slo] = [luminance(sel.bg === 'rgba(0, 0, 0, 0)' ? state.body : sel.bg), luminance(sel.ink)].sort((a, b) => b - a);
        check(`${name}: selected nav row contrast`, (shi + 0.05) / (slo + 0.05) >= 4.5, { ...sel, ratio: ((shi + 0.05) / (slo + 0.05)).toFixed(2) });
      }
      if (name === 'Sky') await page.screenshot({ path: join(out, `${prefix}-sky-hover-desktop.png`) });
    }
    await page.mouse.move(0, 0);
    // Keyboard: focus the checked card, arrow to the next one, and see the focus ring.
    await radio('Match system').focus();
    await page.keyboard.press('ArrowRight');
    const keyed = await page.evaluate(() => {
      const el = document.activeElement;
      const card = el?.closest('.ky-appearance-option');
      return { value: el?.value, checked: el?.checked, outline: card ? getComputedStyle(card).outlineStyle : null };
    });
    check('keyboard arrow selects the next card with a visible focus ring', keyed.checked && keyed.value !== 'system' && keyed.outline !== 'none', keyed);
    await page.screenshot({ path: join(out, `${prefix}-keyboard-focus-desktop.png`) });
    await context.close();
  } finally {
    await browser.close();
    await server.stop();
    await rm(scratch, { recursive: true, force: true });
  }
  const head = git(repo, 'rev-parse', 'HEAD').toString().trim();
  const diff = git(repo, 'diff', 'HEAD', '--', '.', ':(exclude)docs/ui-fleet-2026-10-26');
  await writeFile(join(out, `${prefix}-verify.json`), JSON.stringify({ prefix, product: adapter.product, head, uncommitted_diff_sha256: diff.length ? sha256(diff) : null, run: new Date().toISOString(), viewport: '1280x900', colorScheme: 'dark', results }, null, 2) + '\n');
  if (results.some((r) => !r.ok)) process.exitCode = 1;
}

export const main = (adapter) => (process.argv[2] === '--verify' ? verify(adapter) : run(adapter));
