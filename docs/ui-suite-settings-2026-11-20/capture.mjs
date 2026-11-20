// Suite settings captures: admin section, then the sign-in page picking up the default.
// Usage: KY_REDESIGN=<ky-redesign checkout> node capture.mjs <binary> <repo> <port> <out>
// KY_REDESIGN defaults to ~/git/ky-redesign; its captures/drivers/lib.mjs and a Playwright
// install under KyCalendar/web are the shared capture helpers.
import { randomBytes } from 'node:crypto';
import { homedir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { symlinkSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const redesign = resolve(process.env.KY_REDESIGN ?? join(homedir(), 'git/ky-redesign'));
const { secret, tempDir, pw, waitReady, startServer, settle } = await import(pathToFileURL(join(redesign, 'captures/drivers/lib.mjs')).href);

const { chromium } = await pw('KyCalendar/web');
const [binary, REPO, PORT, OUT] = process.argv.slice(2).map((a, i) => (i === 2 ? a : resolve(a)));
const baseURL = `http://127.0.0.1:${PORT}`;
const dir = await tempDir('identity-suite-theme');
const admin = { username: 'admin', password: secret(), replacement: secret() };
const SIGNED_IN = '.ky-icon-button[aria-label="Sign out"]:visible';
const env = {
  PATH: process.env.PATH, HOME: dir,
  KYIDENTITY_DATA_DIR: join(dir, 'data'), KYIDENTITY_LISTEN_HOST: '127.0.0.1', KYIDENTITY_PORT: PORT,
  KYIDENTITY_ISSUER_URL: baseURL, KYIDENTITY_SECRET_KEY: randomBytes(32).toString('hex'),
  KYIDENTITY_ENCRYPTION_KEY: randomBytes(32).toString('hex'), PUSH_RELAY_URL: '', APNS_RELAY_URL: '',
};
let srv;
const log = [];
try {
  for (const asset of ['css', 'fonts']) symlinkSync(join(REPO, asset), join(dir, asset));
  const boot = spawnSync(binary, ['bootstrap-admin', '-username', 'admin'], { cwd: dir, env, input: `${admin.password}\n`, stdio: ['pipe', 'ignore', 'inherit'] });
  if (boot.status !== 0) throw new Error(`bootstrap-admin exited ${boot.status}`);
  srv = startServer(binary, [], { cwd: dir, env, dir });
  await waitReady(`${baseURL}/`);
  await mkdir(OUT, { recursive: true });
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ baseURL, viewport: { width: 1440, height: 900 }, colorScheme: 'light', locale: 'en-US' });
  const page = await ctx.newPage();
  await page.goto('/');
  await shot(page, 'signin-before', 'busnes-light');
  await signIn(page);
  await page.evaluate(() => { location.hash = '#/admin-suite'; });
  await page.getByRole('heading', { name: 'Suite settings', level: 1 }).waitFor();
  await shot(page, 'admin-empty', 'busnes-light');
  // A fresh install shows "No suite default" as the selected choice (PR #277 review).
  const freshChoice = await page.locator('#suite-theme option:checked').innerText();
  if (freshChoice !== 'No suite default (Busnes, follows device)') throw new Error(`fresh install shows ${freshChoice}`);
  // A refused domain shows the server's reason and changes nothing.
  await page.getByLabel('Mail domains').fill('https://example.com');
  await page.getByRole('button', { name: 'Save domains' }).click();
  await stepUp(page);
  await page.getByRole('alert').waitFor();
  log.push(`refusal: ${await page.getByRole('alert').innerText()}`);
  await shot(page, 'admin-refused', 'busnes-light');
  // Saving one form keeps an unsaved edit in the other (PR #277 review).
  await page.getByLabel('Default theme').selectOption('nord');
  await page.getByLabel('Mail domains').fill('example.com\nBücher.example');
  await saved(page, 'Save domains');
  const keptTheme = await page.getByLabel('Default theme').inputValue();
  if (keptTheme !== 'nord') throw new Error(`saving domains reset the unsaved theme to ${keptTheme}`);
  await page.getByLabel('Mail domains').fill('example.com\nBücher.example\ndraft.example');
  await page.getByLabel('Default theme').selectOption('ocean-pair');
  await saved(page, 'Save');
  const keptDomains = await page.getByLabel('Mail domains').inputValue();
  if (!keptDomains.endsWith('draft.example')) throw new Error(`saving the theme reset the unsaved domains to ${JSON.stringify(keptDomains)}`);
  log.push('unsaved edits survive the other form\'s save');
  await page.getByLabel('Mail domains').fill('example.com\nxn--bcher-kva.example');
  await shot(page, 'admin-saved', 'white-cliffs');
  log.push(`domains field: ${JSON.stringify(await page.getByLabel('Mail domains').inputValue())}`);
  log.push(`public: ${await (await fetch(`${baseURL}/api/appearance`)).text()}`.trim());
  log.push(`suite route anonymous: ${(await fetch(`${baseURL}/api/suite/email-domains`)).status}`);
  // Sign out; a fresh browser with nothing stored picks the default up on the sign-in page.
  await page.locator(SIGNED_IN).first().click();
  await page.getByLabel('Username', { exact: true }).waitFor();
  const fresh = await browser.newContext({ baseURL, viewport: { width: 1440, height: 900 }, colorScheme: 'light', locale: 'en-US' });
  const p2 = await fresh.newPage();
  await p2.goto('/');
  await p2.getByLabel('Username', { exact: true }).waitFor();
  await shot(p2, 'signin-default', 'white-cliffs');
  // The user's own choice still wins.
  await p2.evaluate(() => localStorage.setItem('kyidentity-theme', 'busnes-light'));
  await p2.reload();
  await p2.getByLabel('Username', { exact: true }).waitFor();
  await shot(p2, 'signin-user-choice', 'busnes-light');
  // Choosing "No suite default" clears it: the public answer is system again, and a new
  // browser with nothing saved falls back to the built-in Busnes look (PR #277 review).
  await signIn(page);
  await page.evaluate(() => { location.hash = '#/admin-suite'; });
  await page.getByLabel('Default theme').waitFor();
  await page.getByLabel('Default theme').selectOption('system');
  await saved(page, 'Save');
  await shot(page, 'admin-cleared', 'busnes-light');
  const cleared = (await (await fetch(`${baseURL}/api/appearance`)).text()).trim();
  if (cleared !== '{"defaultTheme":"system"}') throw new Error(`after clearing: ${cleared}`);
  log.push(`cleared: ${cleared}`);
  const p3 = await (await browser.newContext({ baseURL, viewport: { width: 1440, height: 900 }, colorScheme: 'light', locale: 'en-US' })).newPage();
  await p3.goto('/');
  await p3.getByLabel('Username', { exact: true }).waitFor();
  await p3.waitForFunction(() => document.documentElement.dataset.theme === 'busnes-light', null, { timeout: 5000 });
  log.push('fresh browser after clearing: busnes-light');
  await browser.close();
} finally {
  await srv?.stop();
}
console.log(log.join('\n'));

async function shot(page, view, expectTheme) {
  await settle(page, 600);
  if (expectTheme) await page.waitForFunction(t => document.documentElement.dataset.theme === t, expectTheme, { timeout: 5000 });
  const path = join(OUT, `kyidentity-suite-settings-${view}-1440-light.png`);
  await page.screenshot({ path });
  const over = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  const theme = await page.evaluate(() => document.documentElement.dataset.theme);
  log.push(`${path} theme=${theme} overflow=${over}`);
}
async function saved(page, button) {
  // A 403 is the stale CSRF token after signing in again, which the app retries (api.ts).
  const put = page.waitForResponse(r => r.request().method() === 'PUT' && r.url().includes('/api/admin/suite-settings/') && r.status() !== 403, { timeout: 90000 });
  await page.getByRole('button', { name: button, exact: true }).click();
  if (button === 'Save domains') await stepUp(page);
  if (!(await put).ok()) throw new Error(`${button}: ${(await put).status()} ${await (await put).text()}`);
  await page.getByRole('status').filter({ hasText: 'Saved.' }).waitFor();
  await settle(page, 200);
}
// Answers the step-up dialog the domains save opens (the wait matches the existing drivers).
async function stepUp(page) {
  const field = page.locator('#admin-stepup-password');
  await field.waitFor({ timeout: 30000 });
  await page.waitForTimeout(5500);
  await field.fill(admin.password);
  await page.getByRole('dialog', { name: /Confirm/ }).getByRole('button', { name: 'Continue' }).click();
  await field.waitFor({ state: 'detached', timeout: 60000 });
}
async function signIn(page) {
  const login = async () => {
    await page.goto('/');
    await page.getByLabel('Username', { exact: true }).fill(admin.username);
    await page.getByLabel('Password', { exact: true }).fill(admin.password);
    await page.getByRole('button', { name: /sign in/i }).first().click();
  };
  await login();
  const change = page.getByRole('button', { name: 'Set new password' });
  await page.locator(SIGNED_IN).or(change).first().waitFor();
  if (await change.isVisible()) {
    const current = page.getByLabel('Current or temporary password');
    if (await current.count()) await current.fill(admin.password);
    await page.getByLabel('New password', { exact: true }).fill(admin.replacement);
    await page.getByLabel('Repeat new password').fill(admin.replacement);
    await change.click();
    await stepUp(page);
    await change.waitFor({ state: 'detached', timeout: 60000 });
    admin.password = admin.replacement;
    const user = page.getByLabel('Username', { exact: true });
    await page.locator(SIGNED_IN).or(user).first().waitFor();
    if (await user.isVisible()) await login();
  }
  await page.locator(SIGNED_IN).first().waitFor();
}
