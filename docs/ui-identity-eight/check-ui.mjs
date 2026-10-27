// Real-browser regression on the owned fixture; no accounts or settings are changed.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
const fixture=JSON.parse(await readFile(process.argv[2],'utf8'));
assert.equal(new URL(fixture.base).hostname,'127.0.0.1');
assert.ok(process.env.KY_PLAYWRIGHT,'Set KY_PLAYWRIGHT to an installed @playwright/test/index.mjs');
const {chromium}=await import(pathToFileURL(process.env.KY_PLAYWRIGHT).href);
const browser=await chromium.launch();const results=[];
try{
 for(const theme of ['light','dark'])for(const [device,viewport]of[['desktop',{width:1280,height:900}],['phone',{width:390,height:844}]]){
  const ctx=await browser.newContext({viewport,colorScheme:theme,deviceScaleFactor:1});const page=await ctx.newPage();
  await page.goto(fixture.base);await page.getByLabel('Username',{exact:true}).fill('admin');await page.getByLabel('Password',{exact:true}).fill(fixture.password);await page.getByRole('button',{name:'Sign in',exact:true}).click();
  const nav=async name=>page.getByRole('button',{name,exact:true}).click();await nav('Users');await page.locator('.users-table tbody tr').nth(4).waitFor();
  const first=page.getByRole('button',{name:'Manage admin',exact:true}),second=page.getByRole('button',{name:'Manage alex',exact:true});
  const rects=()=>page.locator('.users-table tbody tr').evaluateAll(rows=>rows.map(r=>{const b=r.getBoundingClientRect();return{x:b.x,y:b.y,width:b.width,height:b.height};}));const before=await rects();
  await first.click();const menu=page.locator('.row-actions-menu:popover-open');await menu.waitFor();assert.deepEqual(await rects(),before,'Open menu must not resize/reflow account rows');assert.equal(await menu.count(),1);
  const bounds=await menu.boundingBox();assert.ok(bounds.x>=0&&bounds.y>=0&&bounds.x+bounds.width<=viewport.width+1&&bounds.y+bounds.height<=viewport.height+1,'Menu stays within viewport');
  await page.keyboard.press('Tab');await page.keyboard.press('Escape');await menu.waitFor({state:'hidden'});assert.equal(await first.evaluate(e=>e===document.activeElement),true,'Escape returns to invoker');
  await first.focus();await page.keyboard.press('Enter');await menu.waitFor();
  // Light-dismiss the first before opening the next invoker, which may sit under the sheet.
  await page.getByRole('heading',{name:'Users',exact:true}).click();assert.equal(await page.locator('.row-actions-menu:popover-open').count(),0);await first.click();await second.focus();await page.keyboard.press('Enter');assert.equal(await page.locator('.row-actions-menu:popover-open').count(),1);await page.getByRole('group',{name:'Actions for alex',exact:true}).waitFor();await page.keyboard.press('Escape');
  await first.click();await page.getByRole('group',{name:'Actions for admin',exact:true}).getByRole('button',{name:'Edit user',exact:true}).click();const dialog=page.getByRole('dialog');await dialog.waitFor();assert.equal(await page.locator('.row-actions-menu:popover-open').count(),0);await page.keyboard.press('Escape');await dialog.waitFor({state:'detached'});assert.equal(await first.evaluate(e=>e===document.activeElement),true,'Task dialog returns to Manage');
  await nav('Groups');await page.getByRole('heading',{name:'No groups yet',exact:true}).waitFor();assert.equal(await page.locator('.admin-table').count(),0);assert.equal(await page.locator('.pagination-bar').count(),0);await page.locator('.policy-note > summary').click();assert.match(await page.locator('.policy-note').innerText(),/cancels that user's OAuth grants/);assert.match(await page.locator('.policy-note').innerText(),/within five minutes/);
  await nav('App connections');await page.getByRole('heading',{name:'No app connections yet',exact:true}).waitFor();assert.equal(await page.locator('.admin-table').count(),0);assert.equal(await page.locator('.pagination-bar').count(),0);await page.getByLabel('Search connection names or IDs').fill('unmatched');await page.getByRole('heading',{name:'No matching app connections',exact:true}).waitFor();
  await nav('Security and devices');await page.getByRole('button',{name:'Pair a phone',exact:true}).waitFor();const controls=await page.locator('.security-page .secondary-btn').evaluateAll(es=>es.filter(e=>e.getBoundingClientRect().width).map(e=>({text:e.textContent,height:e.getBoundingClientRect().height})));assert.ok(controls.every(c=>c.height>=40),'Security actions use shared target size');
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth-innerWidth),0);results.push({device,theme,menu:bounds,stable_rows:true,escape_return:true,dialog_return:true,empty_states:true,retained_policy:true,controls});await ctx.close();
 }
 console.log(JSON.stringify({browser:browser.version(),results},null,2));
}finally{await browser.close();}
