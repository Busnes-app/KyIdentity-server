// Register-client form with client ID "kycalendar": before, the type select is free;
// after, it is locked to Confidential. 1440x900 and 390x844, light and dark.
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
const dir = await tempDir(`identity-clients-${TAG}`);
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
    await page.evaluate(() => { location.hash = '#/admin-clients'; });
    await page.getByRole('button', { name: 'Register client' }).first().click();
    const dialog = page.getByRole('dialog');
    await dialog.locator('label:has-text("Client ID (optional)") + input, label:has-text("Client ID (optional)") ~ input').first().fill('kycalendar');
    await settle(page, 600);
    const path = join(OUT, `kyidentity-clients-${TAG}-${dev}-${scheme}.png`);
    await page.screenshot({ path });
    const over = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
    shots.push(`${path} overflow=${over}`);
    await ctx.close();
  }
  await browser.close();
} finally {
  await srv?.stop();
}
console.log(shots.join('\n'));

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
