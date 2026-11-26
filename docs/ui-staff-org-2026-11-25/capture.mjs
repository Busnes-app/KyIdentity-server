// Staff org selection captures (tenancy build plan 5). The Users page with the org
// picker, a finder result, and the page after choosing a customer org, at 1440x900 and
// 390x844, Busnes Light and Dark. A multi-tenant install is refused at startup in this
// release, so the server is a real single-tenant one with a real sign-in, and only the
// finder's answers (GET /api/admin/orgs) are labelled fixtures. Nothing is submitted.
// Usage: node capture.mjs <kyidentity binary> <repo dir> <port> <out dir> <playwright dir>
process.env.TZ = 'America/Chicago';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { symlinkSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';

const lib = await import(join(homedir(), 'git/ky-redesign/captures/drivers/lib.mjs'));
const { NOW, busnes, secret, tempDir, waitReady, startServer, settle } = lib;
const [binary, REPO, PORT, OUT, PW] = process.argv.slice(2).map((a, i) => (i === 2 ? a : resolve(a)));
const { chromium } = await import(join(PW, 'node_modules/@playwright/test/index.mjs'));
const baseURL = `http://127.0.0.1:${PORT}`;
const dir = await tempDir('identity-staff-org');
const admin = { username: 'admin', password: secret(), replacement: secret() };
const SIGNED_IN = '.ky-icon-button[aria-label="Sign out"]:visible';
const PLAN = [
  { scheme: 'light', vp: { width: 1440, height: 900 }, dev: '1440' },
  { scheme: 'dark', vp: { width: 1440, height: 900 }, dev: '1440' },
  { scheme: 'light', vp: { width: 390, height: 844 }, dev: '390' },
  { scheme: 'dark', vp: { width: 390, height: 844 }, dev: '390' },
];
const STAFF = { id: '7d0c4a52-staff', name: 'Busnes staff', kind: 'staff', status: 'active', homeRegion: 'local', plan: '', billingRef: '', maxSeats: 0, seatsUsed: 4 };
const FAMILY = { id: '3f2b9e10-0c41-4d7a-9a55-2d6f1c7e8b01', name: 'The Rivera family', kind: 'customer', status: 'active', homeRegion: 'us-east-2', plan: 'family', billingRef: 'cus_family_01', maxSeats: 6, seatsUsed: 3 };

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
    page.addLocatorHandler(page.locator('#admin-stepup-password'), async (field) => {
      await page.waitForTimeout(5500);
      await field.fill(admin.stepUp ?? admin.password);
      await page.getByRole('dialog', { name: /Confirm/ }).getByRole('button', { name: 'Continue' }).click();
      await field.waitFor({ state: 'detached', timeout: 60000 });
    });
    const sent = [];
    await page.route('**/api/admin/orgs*', (r) => {
      const q = new URL(r.request().url()).searchParams.get('q') ?? '';
      r.fulfill({ json: { orgs: q ? [FAMILY] : [STAFF] }, headers: { 'Cache-Control': 'no-store' } });
    });
    page.on('request', (r) => { if (r.url().includes('/api/admin/users')) sent.push(r.headers()['x-ky-org'] ?? ''); });
    await page.goto('/');
    await page.evaluate((id) => localStorage.setItem('kyidentity-theme', id), busnes(scheme));
    await page.reload();
    await signIn(page);
    await page.evaluate(() => { location.hash = '#/admin-users'; });
    await page.getByText('Working in').waitFor();
    await page.getByRole('heading', { name: 'Users' }).waitFor();
    await shot(page, `picker-${dev}-${scheme}`);
    await page.getByLabel('Find an organisation').fill('rivera@example.test');
    await page.getByRole('button', { name: 'Find' }).click();
    await page.getByText('The Rivera family').waitFor();
    await shot(page, `found-${dev}-${scheme}`);
    await page.getByRole('button', { name: 'Work in this org' }).click();
    await page.getByText('Working in The Rivera family').waitFor();
    await page.getByRole('heading', { name: 'Users' }).waitFor();
    await shot(page, `selected-${dev}-${scheme}`);
    shots.push(`X-Ky-Org sent on /api/admin/users: ${JSON.stringify([...new Set(sent)])}`);
    await ctx.close();
  }
  await browser.close();
} finally {
  await srv?.stop();
}
console.log(shots.join('\n'));

async function shot(page, view) {
  await settle(page, 600);
  const path = join(OUT, `kyidentity-staff-org-${view}.png`);
  await page.screenshot({ path, fullPage: true });
  const over = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  shots.push(`${path} overflow=${over} fixture`);
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
