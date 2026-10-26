// Does a table restyled with display:block/grid keep its table, row, cell and header roles in Chromium?
import { chromium } from '/home/yoshi/git/busnes.app/ky-ui/.claude/worktrees/fleet-appearance/node_modules/playwright/index.mjs';
const css = `.users-table thead { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
.users-table, .users-table tbody, .users-table tr { display: block; width: 100%; }
.users-table td { display: grid; grid-template-columns: 7rem minmax(0, 1fr); }
.users-table td::before { content: attr(data-label); }`;
const html = `<style>${css}</style><table class="users-table"><thead><tr><th>Account</th><th>Email</th></tr></thead><tbody><tr><td data-label="Account">admin</td><td data-label="Email">admin@local</td></tr></tbody></table>`;
const b = await chromium.launch();
const p = await b.newPage({ viewport: { width: 390, height: 844 } });
await p.setContent(html);
const roles = {};
for (const role of ['table', 'row', 'cell', 'columnheader']) roles[role] = await p.getByRole(role).count();
console.log(JSON.stringify(roles));
console.log(await p.locator('table').ariaSnapshot());
await b.close();
