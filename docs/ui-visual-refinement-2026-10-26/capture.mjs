// KyIdentity adapter for capture-core.mjs: a fresh loopback server on generated keys and a
// bootstrap administrator with a generated password. No applications, users or mail.
import { randomBytes } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { here, main, waitReady } from './capture-core.mjs';

const repo = join(here(import.meta.url), '../..');
const PORT = '5871';
const baseURL = `http://127.0.0.1:${PORT}`;
const secret = () => `Fleet-${randomBytes(18).toString('base64url')}9!`;
// The bootstrap password must be replaced at first sign-in; later contexts use the new one.
let password = secret();
let replacement = secret();
const nav = (name) => async (page) => {
  await page.getByRole('button', { name, exact: true }).click();
  await page.getByRole('heading', { level: 1 }).first().waitFor();
};

await main({
  // Saved as the theme name, as the product writes it.
  crossTab: ['kyidentity-theme', 'Sun', 'sun'],
  product: 'kyidentity',
  repo,
  dist: join(repo, 'web/dist/index.html'),
  fixture: 'fresh data dir with generated secret/encryption keys; bootstrap-admin "admin" (generated password on stdin, replaced through the required password-change screen at first sign-in); no applications, groups, users or mail; KYIDENTITY_ISSUER_URL on loopback http',
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
    // The server serves ./css and ./fonts from its working directory, as the image's WORKDIR /
    // provides. The 2026-10-26 fleet captures ran from a bare scratch dir, so the fonts 404ed.
    for (const asset of ['css', 'fonts']) symlinkSync(join(repo, asset), join(dir, asset));
    const boot = spawnSync(binary, ['bootstrap-admin', '-username', 'admin'], { cwd: dir, env, input: `${password}\n`, stdio: ['pipe', 'ignore', 'inherit'] });
    if (boot.status !== 0) throw new Error(`bootstrap-admin exited ${boot.status}`);
    const proc = spawn(binary, [], { cwd: dir, env, stdio: ['ignore', 'ignore', 'inherit'] });
    await waitReady(`${baseURL}/`);
    return { baseURL, binary, pid: proc.pid, stop: async () => { proc.kill('SIGTERM'); await new Promise((r) => proc.once('exit', r)); } };
  },
  async signIn(page) {
    const login = async () => {
      await page.goto('/');
      await page.getByLabel('Username', { exact: true }).fill('admin');
      await page.getByLabel('Password', { exact: true }).fill(password);
      await page.getByRole('button', { name: /sign in/i }).first().click();
    };
    await login();
    const change = page.getByRole('button', { name: 'Set new password' });
    await Promise.race([page.getByRole('navigation').first().waitFor(), change.waitFor()]);
    if (replacement && await change.isVisible()) {
      await page.getByLabel('Current or temporary password').fill(password);
      await page.getByLabel('New password', { exact: true }).fill(replacement);
      await page.getByLabel('Repeat new password').fill(replacement);
      await change.click();
      // The change asks for step-up with the current password first.
      await page.locator('#admin-stepup-password').fill(password);
      await page.locator('#admin-stepup-password').press('Enter');
      password = replacement;
      replacement = null;
      await change.waitFor({ state: 'detached' });
      if (!(await page.getByRole('navigation').first().isVisible())) await login();
    }
    await page.getByRole('navigation').first().waitFor();
  },
  hoverTarget: (page) => page.getByRole('button', { name: 'Users', exact: true }),
  surfaces: {
    applications: nav('Applications'),
    users: nav('Users'),
    appearance: nav('Appearance'),
    // Users with the row's Manage disclosure open (the icon row where there is none).
    'users-manage': async (page) => {
      await nav('Users')(page);
      // The heading renders before the user list loads; wait for a row first.
      await page.locator('.admin-table tbody tr').first().waitFor();
      const manage = page.locator('details.row-actions > summary');
      if (await manage.count()) {
        await manage.first().click();
        await page.locator('.row-actions-menu').first().waitFor();
      }
    },
  },
});
