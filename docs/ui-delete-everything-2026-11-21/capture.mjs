// Delete everything captures (tenancy build plan 8 (c)). Settings > Account, the dialog and
// the export-only view, at 1440x900 and 390x844, Busnes Light and Dark.
// A multi-tenant install is refused at startup in this release, so the server is a real
// single-tenant one with a real sign-in, and the "hosted" views replace only three answers
// with labelled fixtures: GET /api/user/erase, the application list, and (export-only)
// the enrollment field of /api/auth/me. Nothing is submitted.
// Usage: node capture.mjs <kyidentity binary> <repo dir> <port> <before|after> <out dir>
process.env.TZ = 'America/Chicago';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { symlinkSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';

const lib = await import(join(homedir(), 'git/ky-redesign/captures/drivers/lib.mjs'));
const { NOW, busnes, secret, tempDir, pw, waitReady, startServer, settle } = lib;
const { chromium } = await pw('KyCalendar/web');
const [binary, REPO, PORT, TAG, OUT] = process.argv.slice(2).map((a, i) => (i === 2 || i === 3 ? a : resolve(a)));
const baseURL = `http://127.0.0.1:${PORT}`;
const dir = await tempDir(`identity-erase-${TAG}`);
const admin = { username: 'admin', password: secret(), replacement: secret() };
const SIGNED_IN = '.ky-icon-button[aria-label="Sign out"]:visible';
const PLAN = [
  { scheme: 'light', vp: { width: 1440, height: 900 }, dev: '1440' },
  { scheme: 'dark', vp: { width: 1440, height: 900 }, dev: '1440' },
  { scheme: 'light', vp: { width: 390, height: 844 }, dev: '390' },
  { scheme: 'dark', vp: { width: 390, height: 844 }, dev: '390' },
];
const FIXTURE_APPS = { applications: [
  { id: 'kypost', key: 'client:kypost', source: 'client', name: 'KyPost', url: 'https://mail.example.test/', iconName: 'mail' },
  { id: 'kycalendar', key: 'client:kycalendar', source: 'client', name: 'KyCalendar', url: 'https://calendar.example.test/', iconName: 'calendar' },
  { id: 'kydrive', key: 'client:kydrive', source: 'client', name: 'KyDrive', url: 'https://drive.example.test/', iconName: 'folder' },
], preferences: null };

const env = {
  PATH: process.env.PATH, HOME: dir,
  KYIDENTITY_DATA_DIR: join(dir, 'data'), KYIDENTITY_LISTEN_HOST: '127.0.0.1', KYIDENTITY_PORT: PORT,
  KYIDENTITY_ISSUER_URL: baseURL, KYIDENTITY_SECRET_KEY: randomBytes(32).toString('hex'),
  KYIDENTITY_ENCRYPTION_KEY: randomBytes(32).toString('hex'), PUSH_RELAY_URL: '', APNS_RELAY_URL: '',
};

let srv;
const shots = [];
try {
  for (const asset of ['css', 'fonts']) symlinkSync(join(REPO, asset), join(dir, asset));
  const boot = spawnSync(binary, ['bootstrap-admin', '-username', 'admin', '-email', 'alex@example.test'], { cwd: dir, env, input: `${admin.password}\n`, stdio: ['pipe', 'ignore', 'inherit'] });
  if (boot.status !== 0) throw new Error(`bootstrap-admin exited ${boot.status}`);
  srv = startServer(binary, [], { cwd: dir, env, dir });
  await waitReady(`${baseURL}/`);
  await mkdir(OUT, { recursive: true });
  const browser = await chromium.launch();
  for (const { scheme, vp, dev } of PLAN) {
    const ctx = await browser.newContext({ baseURL, viewport: vp, colorScheme: scheme, timezoneId: 'America/Chicago', locale: 'en-US' });
    const page = await ctx.newPage();
    await page.clock.setFixedTime(NOW);
    // The forced password change confirms the given password in the step-up prompt.
    page.addLocatorHandler(page.locator('#admin-stepup-password'), async (field) => {
      await page.waitForTimeout(5500);
      await field.fill(admin.stepUp ?? admin.password);
      await page.getByRole('dialog', { name: /Confirm/ }).getByRole('button', { name: 'Continue' }).click();
      await field.waitFor({ state: 'detached', timeout: 60000 });
    });
    await page.goto('/');
    await page.evaluate((id) => localStorage.setItem('kyidentity-theme', id), busnes(scheme));
    await page.reload();
    await signIn(page);
    await account(page);
    await shot(page, `account-${dev}-${scheme}`);
    if (TAG === 'after') {
      await page.route('**/api/user/erase', (r) => r.request().method() === 'GET'
        ? r.fulfill({ json: { holder: true, otherMembers: 2 }, headers: { 'Cache-Control': 'no-store' } }) : r.abort());
      await page.route('**/api/user/applications', (r) => r.fulfill({ json: FIXTURE_APPS }));
      await account(page);
      await page.getByRole('heading', { name: 'Delete everything' }).waitFor();
      await page.getByRole('heading', { name: 'Delete everything' }).scrollIntoViewIfNeeded();
      await shot(page, `account-hosted-${dev}-${scheme}`, { fixture: true });
      await page.getByRole('button', { name: 'Delete everything…' }).click();
      const dialog = page.getByRole('dialog', { name: 'Delete everything' });
      await dialog.getByText('Export from KyPost').waitFor();
      await dialog.getByLabel(/to confirm/).fill('alex@example.test');
      await shot(page, `dialog-${dev}-${scheme}`, { fixture: true, full: false });
      await dialog.getByRole('button', { name: 'Cancel' }).click();
      await page.route('**/api/auth/me', async (r) => {
        const res = await r.fetch();
        const body = await res.json();
        body.enrollment = { ...(body.enrollment ?? {}), exportOnly: true };
        await r.fulfill({ response: res, json: body });
      });
      await page.goto('/');
      await page.getByRole('heading', { name: 'Your household is being deleted' }).waitFor();
      await shot(page, `export-only-${dev}-${scheme}`, { fixture: true });
      await page.unrouteAll();
    }
    await ctx.close();
  }
  await browser.close();
} finally {
  await srv?.stop();
}
console.log(shots.join('\n'));

async function account(page) {
  await page.evaluate(() => { location.hash = '#/settings/account'; });
  await page.reload();
  await page.getByRole('heading', { name: 'Where you are signed in' }).waitFor();
}
async function shot(page, view, { fixture = false, full = true } = {}) {
  await settle(page, 600);
  const path = join(OUT, `kyidentity-erase-${TAG}-${view}.png`);
  await page.screenshot({ path, fullPage: full });
  const over = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  shots.push(`${path} overflow=${over}${fixture ? ' fixture' : ''}`);
}
async function signIn(page) {
  await page.getByLabel('Username', { exact: true }).waitFor();
  await page.getByLabel('Username', { exact: true }).fill(admin.username);
  await page.getByLabel('Password', { exact: true }).fill(admin.password);
  await page.getByRole('button', { name: /sign in/i }).first().click();
  const change = page.getByRole('button', { name: 'Set new password' });
  await page.locator(SIGNED_IN).or(change).first().waitFor();
  if (admin.replacement && await change.isVisible()) {
    const current = page.getByLabel('Current or temporary password');
    if (await current.count()) await current.fill(admin.password);
    await page.getByLabel('New password', { exact: true }).fill(admin.replacement);
    await page.getByLabel('Repeat new password').fill(admin.replacement);
    admin.stepUp = admin.password;
    await change.click();
    await change.waitFor({ state: 'detached', timeout: 60000 });
    admin.stepUp = null;
    admin.password = admin.replacement;
    admin.replacement = null;
    const user = page.getByLabel('Username', { exact: true });
    await page.locator(SIGNED_IN).or(user).first().waitFor();
    if (await user.isVisible()) return signIn(page);
  }
}
