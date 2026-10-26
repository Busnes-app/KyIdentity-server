// KyIdentity adapter for capture-core.mjs, review follow-up batch (R1). A fresh loopback server
// on generated keys. The bootstrap administrator creates two ordinary users through the real
// Create User form, then grants "helpdesk" the Helpdesk delegation through the real delegation
// editor (step-up answered in the UI). CAPTURE_AS=delegate signs in as that delegate: real
// server-side delegated access, not a rewritten /api/auth/me.
// Usage: [CAPTURE_AS=delegate] node capture.mjs <prefix> [surface,...] | --verify <prefix>
import { randomBytes } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { appendFileSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { here, main, waitReady } from './capture-core.mjs';

const repo = join(here(import.meta.url), '../..');
const PORT = '5871';
const baseURL = `http://127.0.0.1:${PORT}`;
const secret = () => `Fleet-${randomBytes(18).toString('base64url')}9!`;
// Every given password must be replaced at first sign-in; later contexts use the new one.
const account = (username) => ({ username, password: secret(), replacement: secret() });
const admin = account('admin');
const helpdesk = account('helpdesk');
const member = account('member');
const viewer = process.env.CAPTURE_AS === 'delegate' ? helpdesk : admin;
let seeded = false;
const prefix = process.argv[2] === '--verify' ? process.argv[3] : process.argv[2];

const nav = (name) => async (page) => {
  await page.getByRole('button', { name, exact: true }).click();
  await page.getByRole('heading', { level: 1 }).first().waitFor();
};

async function stepUp(page, acct) {
  const field = page.locator('#admin-stepup-password');
  await field.waitFor();
  await field.fill(acct.password);
  await page.getByRole('dialog', { name: /Confirm/ }).getByRole('button', { name: 'Continue' }).click();
  await field.waitFor({ state: 'detached', timeout: 60000 });
}

async function signInAs(page, acct) {
  const login = async () => {
    await page.goto('/');
    await page.getByLabel('Username', { exact: true }).fill(acct.username);
    await page.getByLabel('Password', { exact: true }).fill(acct.password);
    await page.getByRole('button', { name: /sign in/i }).first().click();
  };
  await login();
  const change = page.getByRole('button', { name: 'Set new password' });
  await Promise.race([page.getByRole('navigation').first().waitFor(), change.waitFor()]);
  if (acct.replacement && await change.isVisible()) {
    await page.getByLabel('Current or temporary password').fill(acct.password);
    await page.getByLabel('New password', { exact: true }).fill(acct.replacement);
    await page.getByLabel('Repeat new password').fill(acct.replacement);
    await change.click();
    await stepUp(page, acct);
    acct.password = acct.replacement;
    acct.replacement = null;
    await change.waitFor({ state: 'detached' });
    if (!(await page.getByRole('navigation').first().isVisible())) await login();
  }
  await page.getByRole('navigation').first().waitFor();
}

// As the administrator: two ordinary users, then the Helpdesk delegation for one of them.
async function seed(page) {
  await nav('Users')(page);
  for (const acct of [helpdesk, member]) {
    await page.getByRole('button', { name: 'Create User' }).click();
    const form = page.getByRole('dialog', { name: 'Create User Account' });
    await form.getByPlaceholder('e.g. bob', { exact: true }).fill(acct.username);
    await form.getByPlaceholder('e.g. Bob Builder').fill(acct.username === 'helpdesk' ? 'Help Desk' : 'Member');
    await form.getByPlaceholder('bob@example.com').fill(`${acct.username}@example.test`);
    await form.getByPlaceholder('Blank: the user chooses one through a link').fill(acct.password);
    await form.locator('button[type=submit]').click();
    await stepUp(page, admin);
    await form.waitFor({ state: 'detached' });
    await page.locator('.users-table tbody tr', { hasText: acct.username }).first().waitFor();
  }
  await page.locator('.users-table tbody tr', { hasText: 'helpdesk' }).locator('details.row-actions > summary').click();
  await page.getByRole('button', { name: 'Delegated administration for helpdesk' }).click();
  const editor = page.getByRole('dialog', { name: 'Delegation for helpdesk' });
  // The editor loads the saved delegations and the app list before it accepts a change.
  await editor.getByText(/No app connections yet|App owner/).last().waitFor();
  await page.waitForTimeout(500);
  await editor.getByRole('checkbox', { name: /Helpdesk:/ }).check();
  await editor.getByRole('button', { name: 'Save', exact: true }).click();
  await stepUp(page, admin);
  await editor.waitFor({ state: 'detached' });
}

// Opens one row's Manage, if that row offers one, and records what each row offers.
const manageRow = (account) => async (page, { device, theme }) => {
  await nav('Users')(page);
  await page.locator('.users-table tbody tr').nth(2).waitFor();
  const row = page.locator('.users-table tbody tr', { has: page.locator('td[data-label="Account"]', { hasText: new RegExp(`^${account}`) }) });
  const manage = row.locator('details.row-actions > summary');
  if (await manage.count()) {
    await manage.click();
    await row.locator('.row-actions-menu').waitFor();
  }
  const rows = await page.locator('.users-table tbody tr').evaluateAll((trs) => trs.map((tr) => ({
    account: tr.querySelector('td[data-label="Account"]')?.textContent.trim(),
    role: tr.querySelector('td[data-label="Role"]')?.textContent.trim(),
    manage: !!tr.querySelector('details.row-actions > summary'),
    open: !!tr.querySelector('details.row-actions')?.open,
    actions: [...tr.querySelectorAll('.row-actions-menu .row-action')].map((b) => b.textContent.trim()),
  })));
  if (prefix) appendFileSync(join(here(import.meta.url), 'screenshots', `${prefix}-rows.jsonl`), JSON.stringify({ viewer: viewer.username, opened: account, device, theme, rows }) + '\n');
};

await main({
  // Saved as the theme name, as the product writes it.
  crossTab: ['kyidentity-theme', 'Sun', 'sun'],
  product: 'kyidentity',
  repo,
  dist: join(repo, 'web/dist/index.html'),
  fixture: `fresh data dir with generated secret/encryption keys; bootstrap-admin "admin" and two users ("helpdesk", "member", role user) created through the Create User form with generated passwords, each replaced at first sign-in; "helpdesk" holds the Helpdesk delegation set through the delegation editor; signed in as "${viewer.username}"; no applications, groups or mail`,
  async start(dir) {
    const binary = join(dir, 'kyidentity');
    const build = spawnSync('go', ['build', '-o', binary, './cmd/kyidentity'], { cwd: repo, stdio: 'inherit' });
    if (build.status !== 0) throw new Error('go build failed');
    const env = {
      PATH: process.env.PATH, HOME: dir,
      KYIDENTITY_DATA_DIR: join(dir, 'data'), KYIDENTITY_LISTEN_HOST: '127.0.0.1', KYIDENTITY_PORT: PORT,
      KYIDENTITY_ISSUER_URL: baseURL, KYIDENTITY_SECRET_KEY: randomBytes(32).toString('hex'),
      KYIDENTITY_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
    };
    // The server serves ./css and ./fonts from its working directory, as the image's WORKDIR / does.
    for (const asset of ['css', 'fonts']) symlinkSync(join(repo, asset), join(dir, asset));
    const boot = spawnSync(binary, ['bootstrap-admin', '-username', 'admin'], { cwd: dir, env, input: `${admin.password}\n`, stdio: ['pipe', 'ignore', 'inherit'] });
    if (boot.status !== 0) throw new Error(`bootstrap-admin exited ${boot.status}`);
    const proc = spawn(binary, [], { cwd: dir, env, stdio: ['ignore', 'ignore', 'inherit'] });
    await waitReady(`${baseURL}/`);
    return { baseURL, binary, pid: proc.pid, stop: async () => { proc.kill('SIGTERM'); await new Promise((r) => proc.once('exit', r)); } };
  },
  async signIn(page) {
    if (!seeded) {
      await signInAs(page, admin);
      await seed(page);
      seeded = true;
      await page.context().clearCookies();
    }
    await signInAs(page, viewer);
  },
  hoverTarget: (page) => page.getByRole('button', { name: 'Users', exact: true }),
  surfaces: {
    users: async (page) => { await nav('Users')(page); await page.locator('.users-table tbody tr').nth(2).waitFor(); },
    'manage-admin-row': manageRow('admin'),
    'manage-member-row': manageRow('member'),
    appearance: nav('Appearance'),
  },
});
