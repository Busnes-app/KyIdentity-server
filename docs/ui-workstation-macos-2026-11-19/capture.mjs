// Mac sign-in (XCreds). Before/after: Workstation login and its Edit settings dialog.
// After only: the Macs block with Mac sign-in on and its XCreds profile.
// 1440x900 and 390x844, light and dark.
// Usage: node capture.mjs <kyidentity binary> <repo dir> <port> <before|after> <out dir>
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { symlinkSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

const lib = await import(join(homedir(), 'git/ky-redesign/captures/drivers/lib.mjs'));
const { NOW, busnes, secret, tempDir, pw, waitReady, startServer, settle } = lib;
const { chromium } = await pw('KyCalendar/web');
const [binary, REPO, PORT, TAG, OUT] = process.argv.slice(2).map((a, i) => (i === 2 || i === 3 ? a : resolve(a)));
const baseURL = `http://127.0.0.1:${PORT}`;
const dir = await tempDir(`identity-wsmac-${TAG}`);
const admin = { username: 'admin', password: secret(), replacement: secret() };
const SIGNED_IN = '.ky-icon-button[aria-label="Sign out"]:visible';
const env = {
  PATH: process.env.PATH, HOME: dir,
  KYIDENTITY_DATA_DIR: join(dir, 'data'), KYIDENTITY_LISTEN_HOST: '127.0.0.1', KYIDENTITY_PORT: PORT,
  KYIDENTITY_ISSUER_URL: baseURL, KYIDENTITY_SECRET_KEY: randomBytes(32).toString('hex'),
  KYIDENTITY_ENCRYPTION_KEY: randomBytes(32).toString('hex'), PUSH_RELAY_URL: '', APNS_RELAY_URL: '',
};
let srv;
const shots = [];
let clientId = '';
try {
  for (const asset of ['css', 'fonts']) symlinkSync(join(REPO, asset), join(dir, asset));
  const boot = spawnSync(binary, ['bootstrap-admin', '-username', 'admin'], { cwd: dir, env, input: `${admin.password}\n`, stdio: ['pipe', 'ignore', 'inherit'] });
  if (boot.status !== 0) throw new Error(`bootstrap-admin exited ${boot.status}`);
  srv = startServer(binary, [], { cwd: dir, env, dir });
  await waitReady(`${baseURL}/`);
  await mkdir(OUT, { recursive: true });
  const browser = await chromium.launch();
  for (const [scheme, vp, dev] of [['light', { width: 1440, height: 900 }, '1440'], ['dark', { width: 1440, height: 900 }, '1440'],
    ['light', { width: 390, height: 844 }, '390'], ['dark', { width: 390, height: 844 }, '390']]) {
    const ctx = await browser.newContext({ baseURL, viewport: vp, colorScheme: scheme, timezoneId: 'America/Chicago', locale: 'en-US' });
    const page = await ctx.newPage();
    await page.clock.setFixedTime(NOW);
    page.addLocatorHandler(page.locator('#admin-stepup-password'), async (field) => {
      await page.waitForTimeout(5500);
      await field.fill(admin.password);
      await page.getByRole('dialog', { name: /Confirm/ }).getByRole('button', { name: 'Continue' }).click();
      await field.waitFor({ state: 'detached', timeout: 60000 });
    });
    await page.goto('/');
    await page.evaluate((id) => localStorage.setItem('kyidentity-theme', id), busnes(scheme));
    await signIn(page);
    const shot = async (name) => {
      await settle(page, 600);
      const path = join(OUT, `kyidentity-${name}-${TAG}-${dev}-${scheme}.png`);
      await page.screenshot({ path });
      const over = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
      shots.push(`${path} overflow=${over}`);
    };
    const open = async () => {
      await page.evaluate(() => { location.hash = '#/admin-app-registry'; });
      await page.getByRole('heading', { name: 'App connections', exact: true }).waitFor();
      await page.getByRole('button', { name: 'Workstation login' }).click();
      await page.getByRole('heading', { name: 'Workstation login' }).waitFor();
    };
    await open();
    if (!clientId) {
      await page.getByLabel('New workstation app').fill('Office Macs');
      await page.getByRole('button', { name: 'Add', exact: true }).click();
      await page.getByRole('heading', { name: 'Office Macs' }).waitFor({ timeout: 60000 });
      clientId = await page.evaluate(async () => (await (await fetch('/api/admin/workstation-apps')).json()).apps[0].clientId);
      await configure(page);
      await page.reload();
      await open();
    }
    await page.getByRole('heading', { name: 'Office Macs' }).waitFor();
    await shot('workstation-login');
    if (TAG === 'after') {
      await page.getByText('XCreds configuration profile (.mobileconfig)').scrollIntoViewIfNeeded();
      await shot('workstation-mac');
    }
    await page.getByRole('button', { name: 'Edit settings' }).click();
    await page.getByRole('dialog').getByLabel('Offline window (days)').waitFor();
    await shot('workstation-settings');
    await ctx.close();
  }
  await browser.close();
} finally {
  await srv?.stop();
}
console.log(shots.join('\n'));

// Device sign-in on; after: Mac sign-in and require-password on too.
async function configure(page) {
  const call = (method, path, body, grant) => page.evaluate(async ({ method, path, body, grant }) => {
    const csrf = (await (await fetch('/api/auth/csrf')).json()).csrfToken;
    const r = await fetch(path, { method, headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, ...(grant ? { 'X-KyIdentity-StepUp': grant } : {}) }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, body: await r.text() };
  }, { method, path, body, grant });
  const grant = async (op) => JSON.parse((await call('POST', '/api/auth/step-up', { password: admin.password, code: '', method: '', operation: op })).body).stepUpToken;
  const settings = { deviceGrantEnabled: true, deviceCodeTtl: 300, offlineWindow: 604800, ...(TAG === 'after' ? { requirePassword: true, macSignIn: true } : {}) };
  const r = await call('PUT', `/api/admin/workstation-apps/${clientId}`, settings, await grant(`PUT /api/admin/workstation-apps/${clientId}`));
  if (r.status !== 200) throw new Error(`settings ${r.status} ${r.body}`);
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
  if (admin.replacement && await change.isVisible()) {
    const current = page.getByLabel('Current or temporary password');
    if (await current.count()) await current.fill(admin.password);
    await page.getByLabel('New password', { exact: true }).fill(admin.replacement);
    await page.getByLabel('Repeat new password').fill(admin.replacement);
    await change.click();
    await change.waitFor({ state: 'detached', timeout: 60000 });
    admin.password = admin.replacement;
    admin.replacement = null;
    const user = page.getByLabel('Username', { exact: true });
    await page.locator(SIGNED_IN).or(user).first().waitFor();
    if (await user.isVisible()) await login();
  }
  await page.locator(SIGNED_IN).first().waitFor();
}
