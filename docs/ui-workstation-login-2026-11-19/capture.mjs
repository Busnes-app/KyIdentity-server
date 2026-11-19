// Workstation login screens. Before/after: App connections and Settings → Account (sessions).
// After only: Workstation login, its Settings dialog, and /device (code entry, approval).
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
const dir = await tempDir(`identity-ws-${TAG}`);
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
    await page.evaluate(() => { location.hash = '#/admin-app-registry'; });
    await page.getByRole('heading', { name: 'App connections' }).waitFor();
    await shot('app-connections');
    if (TAG === 'after') {
      await page.getByRole('button', { name: 'Workstation login' }).click();
      await page.getByRole('heading', { name: 'Workstation login' }).waitFor();
      if (!clientId) {
        await page.getByLabel('New workstation app').fill('Linux desktops');
        await page.getByRole('button', { name: 'Add', exact: true }).click();
        await page.getByRole('heading', { name: 'Linux desktops' }).waitFor({ timeout: 60000 });
        clientId = await page.evaluate(async () => (await (await fetch('/api/admin/workstation-apps')).json()).apps[0].clientId);
        await enableAndSignInOnce(page);
        await page.reload();
        await page.getByRole('heading', { name: 'Linux desktops' }).waitFor();
      }
      await page.getByRole('heading', { name: 'Linux desktops' }).waitFor();
      await shot('workstation-login');
      await page.getByRole('button', { name: 'Settings', exact: true }).click();
      await page.getByRole('dialog').getByLabel('Offline window (days)').waitFor();
      await shot('workstation-settings');
      await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
      const code = await startDeviceCode(page);
      await page.goto(`/device?user_code=${code}`);
      await page.getByRole('heading', { name: 'Sign in on a computer' }).waitFor();
      await shot('device-enter');
      await page.getByRole('button', { name: 'Continue' }).click();
      await page.getByRole('button', { name: 'Approve' }).waitFor();
      await shot('device-confirm');
      await page.goto('/');
    }
    await page.evaluate(() => { location.hash = '#/settings/account'; });
    await page.getByRole('heading', { name: 'Settings' }).first().waitFor();
    await page.getByText(TAG === 'after' ? 'Workstation login: Linux desktops' : 'Unknown browser').or(page.getByText(/HeadlessChrome|Chrome/).first()).first().waitFor();
    await page.getByText(/Sessions|Signed-in sessions|browser sessions/i).first().scrollIntoViewIfNeeded().catch(() => {});
    await shot('sessions');
    await ctx.close();
  }
  await browser.close();
} finally {
  await srv?.stop();
}
console.log(shots.join('\n'));

async function startDeviceCode(page) {
  return page.evaluate(async (id) => {
    const r = await fetch('/oauth/device_authorization', { method: 'POST', body: new URLSearchParams({ client_id: id, scope: 'openid profile email' }) });
    return (await r.json()).user_code;
  }, clientId);
}

// Turn the grant on, assign the administrator, and complete one device sign-in so a
// workstation session exists for the sessions screen.
async function enableAndSignInOnce(page) {
  const call = (method, path, body, grant) => page.evaluate(async ({ method, path, body, grant }) => {
    const csrf = (await (await fetch('/api/auth/csrf')).json()).csrfToken;
    const r = await fetch(path, { method, headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, ...(grant ? { 'X-KyIdentity-StepUp': grant } : {}) }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, body: await r.text() };
  }, { method, path, body, grant });
  const grant = async (op) => JSON.parse((await call('POST', '/api/auth/step-up', { password: admin.password, code: '', method: '', operation: op })).body).stepUpToken;
  let r = await call('PUT', `/api/admin/workstation-apps/${clientId}`, { deviceGrantEnabled: true, deviceCodeTtl: 300, offlineWindow: 604800 }, await grant(`PUT /api/admin/workstation-apps/${clientId}`));
  if (r.status !== 200) throw new Error(`settings ${r.status} ${r.body}`);
  const apps = JSON.parse((await call('GET', '/api/admin/workstation-apps')).body);
  const me = JSON.parse((await call('GET', '/api/auth/me')).body);
  const path = `/api/admin/app-registry/${apps.apps[0].appId}/assignments/users/${me.id}`;
  r = await call('PUT', path, {}, await grant(`PUT ${path}`));
  if (r.status !== 200) throw new Error(`assign ${r.status} ${r.body}`);
  const device = await page.evaluate(async (id) => (await (await fetch('/oauth/device_authorization', { method: 'POST', body: new URLSearchParams({ client_id: id, scope: 'openid profile email' }) })).json()), clientId);
  r = await call('POST', '/api/device/decision', { userCode: device.user_code, approve: true });
  if (r.status !== 200) throw new Error(`approve ${r.status} ${r.body}`);
  const token = await page.evaluate(async ({ id, code }) => (await fetch('/oauth/token', { method: 'POST', body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: code, client_id: id }) })).status, { id: clientId, code: device.device_code });
  if (token !== 200) throw new Error(`device token ${token}`);
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
