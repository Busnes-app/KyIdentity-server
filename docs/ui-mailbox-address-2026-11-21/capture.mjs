// Mailbox address captures: the Users page before and after, in single-tenant mode from a
// real server, and the hosted (multi-tenant) states with the users list fixture-injected.
// Usage: KY_REDESIGN=<ky-redesign checkout> node capture.mjs <before|after> <binary> <repo> <port> <out>
// A multi-tenant server is refused at startup in this release, so for the "hosted" shots
// the browser rewrites only GET /api/admin/users: it adds mailboxDomains and two customer
// rows, as a household org's list answers (TestMailboxAddressRouteInACustomerOrg). Nothing
// is saved in those shots.
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
const [stage, binary, REPO, PORT, OUT] = process.argv.slice(2).map((a, i) => (i === 0 || i === 3 ? a : resolve(a)));
const baseURL = `http://127.0.0.1:${PORT}`;
const dir = await tempDir('identity-mailbox');
const admin = { username: 'admin', password: secret(), replacement: secret() };
const SIGNED_IN = '.ky-icon-button[aria-label="Sign out"]:visible';
const env = {
  PATH: process.env.PATH, HOME: dir,
  KYIDENTITY_DATA_DIR: join(dir, 'data'), KYIDENTITY_LISTEN_HOST: '127.0.0.1', KYIDENTITY_PORT: PORT,
  KYIDENTITY_ISSUER_URL: baseURL, KYIDENTITY_SECRET_KEY: randomBytes(32).toString('hex'),
  KYIDENTITY_ENCRYPTION_KEY: randomBytes(32).toString('hex'), PUSH_RELAY_URL: '', APNS_RELAY_URL: '',
};
const SIZES = [['1440', { width: 1440, height: 900 }], ['390', { width: 390, height: 844 }]];
const SCHEMES = ['light', 'dark'];
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
  const first = await (await browser.newContext({ baseURL, viewport: SIZES[0][1], colorScheme: 'light', locale: 'en-US' })).newPage();
  await signIn(first);
  const state = await first.context().storageState();
  for (const [size, viewport] of SIZES) {
    for (const scheme of SCHEMES) {
      const ctx = await browser.newContext({ baseURL, viewport, colorScheme: scheme, locale: 'en-US', storageState: state });
      const page = await ctx.newPage();
      await openUsers(page);
      const single = await (await page.request.get('/api/admin/users')).text();
      if (single.includes('mailbox')) throw new Error(`single-tenant list names a mailbox: ${single}`);
      await shot(page, `users-${stage}`, size, scheme);
      if (stage === 'after') {
        await ctx.route('**/api/admin/users', async (route) => {
          if (route.request().method() !== 'GET') return route.continue();
          const body = await (await route.fetch()).json();
          body.users = [
            { id: 'fixture-holder', username: 'robin@gmail.example', displayName: 'Robin Holder', email: 'robin@gmail.example', role: 'user', status: 'active', mailboxAddress: 'robin@ky.example' },
            { id: 'fixture-member', username: 'sam@outlook.example', displayName: 'Sam Member', email: 'sam@outlook.example', role: 'user', status: 'disabled', pending: true },
          ];
          body.mailboxDomains = ['ky.example', 'xn--bcher-kva.example'];
          await route.fulfill({ json: body });
        });
        await openUsers(page);
        await page.getByText('Mailbox robin@ky.example').first().waitFor();
        await page.getByRole('button', { name: 'More actions for sam@outlook.example' }).click();
        await page.getByRole('button', { name: 'Mailbox address for sam@outlook.example' }).waitFor();
        await shot(page, 'hosted-menu', size, scheme);
        await page.getByRole('button', { name: 'Mailbox address for sam@outlook.example' }).click();
        await page.getByLabel('Mailbox address').fill('sam@ky.example');
        await shot(page, 'hosted-set', size, scheme);
        await page.getByRole('button', { name: 'Cancel' }).click();
        await page.getByRole('button', { name: 'More actions for robin@gmail.example' }).click();
        await page.getByRole('button', { name: 'Mailbox address for robin@gmail.example' }).click();
        await page.getByLabel('Mailbox address').waitFor();
        if (await page.getByLabel('Mailbox address').inputValue() !== 'robin@ky.example') throw new Error('the current address is not prefilled');
        await shot(page, 'hosted-change', size, scheme);
      }
      await ctx.close();
    }
  }
  await browser.close();
} finally {
  await srv?.stop();
}
console.log(log.join('\n'));

async function openUsers(page) {
  await page.goto('/');
  await page.locator(SIGNED_IN).first().waitFor();
  await page.evaluate(() => { location.hash = '#/admin-users'; });
  await page.getByRole('heading', { name: 'Users', level: 1 }).waitFor();
  await page.locator('.users-table tbody tr').first().waitFor();
}
async function shot(page, view, size, scheme) {
  await settle(page, 600);
  const path = join(OUT, `kyidentity-mailbox-${view}-${size}-${scheme}.png`);
  await page.screenshot({ path });
  const over = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  const theme = await page.evaluate(() => document.documentElement.dataset.theme);
  log.push(`${path} theme=${theme} overflow=${over}`);
}
// Answers the step-up dialog (the wait matches the existing drivers).
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
