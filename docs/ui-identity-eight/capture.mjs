import {createRequire} from 'node:module';
import {readFile,writeFile,mkdir,open,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
const root=fileURLToPath(new URL('../../',import.meta.url));
const [fixtureFile,stage,phase]=process.argv.slice(2);
if(!fixtureFile || !/^\d\d$/.test(stage??'') || !['before','after'].includes(phase))throw new Error('usage: capture.mjs <private-fixture.json> <nn> before|after');
const fixture=JSON.parse(await readFile(fixtureFile,'utf8'));
const origin=new URL(fixture.base);if(origin.protocol!=='http:' || origin.hostname!=='127.0.0.1')throw new Error('capture requires an owned loopback fixture');
const require=createRequire('/home/yoshi/git/busnes.app/kyrecovery-server/.claude/worktrees/ui-recovery-eight/tests/browser/package.json');
const {chromium}=require('@playwright/test');
const out=fileURLToPath(new URL('.',import.meta.url));await mkdir(join(out,'screenshots'),{recursive:true});
const manifestPath=join(out,`manifest-${stage}-${phase}.json`);
const manifestFile=await open(manifestPath,'wx');let captured=false;
const browser=await chromium.launch();
const login=async page=>{await page.goto(fixture.base);await page.getByLabel('Username',{exact:true}).fill('admin');await page.getByLabel('Password',{exact:true}).fill(fixture.password);await page.getByRole('button',{name:'Sign in',exact:true}).click();
 const change=page.getByRole('button',{name:'Set new password',exact:true});await Promise.race([page.getByRole('navigation',{name:'Your account'}).waitFor(),change.waitFor()]);
 if(fixture.replacement && await change.isVisible()){await page.getByLabel('Current or temporary password').fill(fixture.password);await page.getByLabel('New password',{exact:true}).fill(fixture.replacement);await page.getByLabel('Repeat new password').fill(fixture.replacement);await change.click();await stepup(page);await change.waitFor({state:'detached'});fixture.password=fixture.replacement;delete fixture.replacement;await writeFile(fixtureFile,JSON.stringify(fixture),{mode:0o600});}
 await page.getByRole('navigation',{name:'Your account'}).waitFor();};
const nav=async(page,name)=>{await page.getByRole('button',{name,exact:true}).click();await page.waitForTimeout(200);};
const stepup=async page=>{const field=page.locator('#admin-stepup-password');await field.waitFor();await field.fill(fixture.password);await page.getByRole('dialog',{name:/Confirm/}).getByRole('button',{name:'Continue',exact:true}).click();await field.waitFor({state:'detached'});};
const shots=[];
try{
 const setup=await browser.newContext();const p=await setup.newPage();await login(p);await nav(p,'Users');
 for(const [username,name] of [['alex','Alex Morgan'],['sam','Sam Rivera'],['taylor','Taylor Kim'],['jordan','Jordan Ellis']]){
  await p.locator('.users-table tbody tr').first().waitFor();if(await p.locator('.users-table tbody tr',{hasText:username}).count())continue;
  await p.getByRole('button',{name:'Create User',exact:true}).click();const form=p.getByRole('dialog',{name:'Create User Account'});
  await form.getByPlaceholder('e.g. bob',{exact:true}).fill(username);await form.getByPlaceholder('e.g. Bob Builder').fill(name);await form.getByPlaceholder('bob@example.com').fill(username+'@example.test');await form.getByPlaceholder('Blank: the user chooses one through a link').fill('Council-'+randomBytes(24).toString('base64url')+'9!');
  await form.locator('button[type=submit]').click();await stepup(p);await form.waitFor({state:'detached'});await p.locator('.users-table tbody tr',{hasText:username}).first().waitFor();
 }
 const state=await setup.storageState();await setup.close();
 const surfaces=[
  {name:'applications',cohort:'member-home',nav:'Applications'},
  {name:'users',cohort:'admin-console',nav:'Users'},
  {name:'users-manage',cohort:'admin-console',nav:'Users',open:async page=>{await page.locator('.users-table tbody tr').nth(4).waitFor();await page.getByRole('button',{name:'Manage admin',exact:true}).click();await page.locator('.row-actions-menu:popover-open').waitFor();}},
  {name:'create-user',cohort:'admin-console',nav:'Users',open:async page=>{await page.getByRole('button',{name:'Create User',exact:true}).click();await page.getByRole('dialog',{name:'Create User Account'}).waitFor();}},
  {name:'groups',cohort:'admin-console',nav:'Groups'},
  {name:'app-connections',cohort:'admin-console',nav:'App connections'},
  {name:'security',cohort:'settings',nav:'Security and devices'},
  {name:'appearance',cohort:'settings',nav:'Appearance'},
  {name:'login',cohort:'auth',anonymous:true},
 ];
 for(const theme of ['light','dark'])for(const [device,viewport]of[['desktop',{width:1280,height:900}],['mobile',{width:390,height:844}]])for(const s of surfaces){
  const ctx=await browser.newContext({viewport,colorScheme:theme,deviceScaleFactor:1,locale:'en-US',timezoneId:'America/New_York',...(!s.anonymous&&{storageState:state})});const page=await ctx.newPage();await page.goto(fixture.base);
  if(s.anonymous)await page.getByRole('button',{name:'Sign in',exact:true}).waitFor();else{await page.getByRole('navigation',{name:'Your account'}).waitFor();await nav(page,s.nav);await s.open?.(page);}
  await page.evaluate(()=>document.fonts.ready);await page.waitForTimeout(300);
  const file=`kyidentity-${stage}-${phase}-${s.name}-${device}-${theme}.png`;const b=await page.screenshot({path:join(out,'screenshots',file),fullPage:false});
  const geometry=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth-innerWidth,savedChoice:localStorage.getItem('kyidentity-theme'),fonts:[...document.fonts].filter(f=>f.status==='loaded').map(f=>f.family)}));
  shots.push({file:'screenshots/'+file,sha256:createHash('sha256').update(b).digest('hex'),bytes:b.length,width:viewport.width,height:viewport.height,viewport,device,theme,cohort:s.cohort,surface:s.name,state:s.name.startsWith('users')?'5 synthetic users':s.open?'open unsubmitted form':'empty/unconfigured',...geometry});await ctx.close();
 }
 const pin=async file=>[file,createHash('sha256').update(await readFile(join(root,file))).digest('hex')];
 const manifest={product:'KyIdentity',stage,phase,source_commit:fixture.source_commit,capture_commit:execFileSync('git',['-C',root,'rev-parse','HEAD']).toString().trim(),source_files:Object.fromEntries(await Promise.all(['web/dist/index.html','css/styles.css','web/src/components/AdminUsers.tsx','web/src/components/Sidebar.tsx','web/src/index.css','web/src/components/DeviceSettings.tsx','web/src/components/AdminGroups.tsx','web/src/components/AdminAppRegistry.tsx','web/src/components/UserDashboard.tsx','web/src/App.tsx','web/src/ky-ui/VERSION'].map(pin))),captured_at:new Date().toISOString(),driver:`Playwright ${require('@playwright/test/package.json').version}; Chromium ${browser.version()}; DPR1; normal service workers`,timezone:'America/New_York',locale:'en-US',fixture:'Owned loopback instance; bootstrap administrator changed password through UI and step-up; four ordinary synthetic users created through real UI. No application/group/device/recovery setup. Open forms not submitted.',shots};
 await manifestFile.writeFile(JSON.stringify(manifest,null,2)+'\n');captured=true;console.log(JSON.stringify({out,images:shots.length,overflows:shots.filter(s=>s.overflow)}));
}finally{await browser.close();await manifestFile.close();if(!captured){await rm(manifestPath);for(const shot of shots)await rm(join(out,shot.file));}}
