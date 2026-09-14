import { useEffect, useRef, useState } from 'react';
import { apiRequest, errorMessage } from '../api';
import { parseAppAccessPage, parseAppAccessGroups } from '../parsers';
import type { AppRecord } from '../types';
import { pageSize, Pager, useDirectoryPage } from './DirectoryPage';
import { isCancelled, useStepUp } from './StepUpPrompt';
import { describeInstant, instantFromLocal, localZone } from '../instant';
import { AccessExplanation } from './AccessExplanation';

export function AdminAppAccess({ app, onClose, onChanged }: { app: AppRecord; onClose: () => void; onChanged: () => void }) {
 const [mode,setMode]=useState(app.accessMode);
 const [enabled,setEnabled]=useState(app.enabled);
 const [view,setView]=useState<'users'|'groups'>('users');
 const [query,setQuery]=useState('');
 const [offset,setOffset]=useState(0);
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState<string|null>(null);
 const [until,setUntil]=useState('');
 const [explaining,setExplaining]=useState<{id:string;username:string}|null>(null);
 const untilInstant=instantFromLocal(until);
 const heading=useRef<HTMLHeadingElement|null>(null);
 useEffect(()=>{heading.current?.focus();},[]);
 const {requestGrant,stepUpPrompt}=useStepUp();
 const base=`/api/admin/app-registry/${encodeURIComponent(app.id)}`;
 const params=new URLSearchParams({q:query,limit:String(pageSize),offset:String(offset)});
 const users=useDirectoryPage(`${base}/access-users?${params}&mode=${mode}&enabled=${enabled}`,parseAppAccessPage);
 const groups=useDirectoryPage(`${base}/access-groups?${params}`,parseAppAccessGroups);
 const mutate=async(method:'PUT'|'DELETE',path:string,reason:string,body?:object)=>{
  setBusy(true);setError(null);
  try{const stepUpToken=await requestGrant(reason,`${method} ${path}`);await apiRequest(path,{method,stepUpToken,body:body?JSON.stringify(body):undefined});users.reload();groups.reload();onChanged();}
  catch(err){if(!isCancelled(err))setError(errorMessage(err,'Could not update access'));}
  finally{setBusy(false);}
 };
 const page=view==='users'?users.page:groups.page;
 useEffect(()=>{if(page&&offset>0&&offset>=page.total)setOffset(Math.max(0,offset-pageSize));},[page,offset]);
 const current=users.page?.app;
 const changed=current&&(mode!==current.accessMode||enabled!==current.enabled);
 return <div className="admin-page">
  <div className="page-header"><div><h1 className="page-title" ref={heading} tabIndex={-1}>Access to {app.launcherName||app.clientName||app.systemName}</h1><code style={{overflowWrap:'anywhere'}}>{app.id}</code></div><button className="secondary-btn" disabled={busy} onClick={onClose}>Back to app connections</button></div>
  <p>Direct and group assignments grant access together. Administrators also need app access.</p>
  {!app.clientId&&<p className="text-muted">Without an OAuth client, these assignments control launcher visibility only. Access at the destination website is separate.</p>}
  {app.systemId&&<p className="text-muted">Provisioning follows this policy: users who gain access are created or reactivated at {app.systemName}; users who lose it are deactivated there. Accounts are never deleted.</p>}
  <p className="text-muted">Revocation blocks code exchange and online token use. Offline access tokens may remain valid for up to 15 minutes; an app's own session may last longer.</p>
  {(error||users.error||groups.error)&&<div role="alert" className="alert-box error">{error||users.error||groups.error} <button className="secondary-btn sm" onClick={()=>{users.reload();groups.reload();}}>Refresh</button></div>}
  <section className="settings-section"><div className="section-header"><h2>Access policy</h2></div><div className="modal-body">
   <p>Current policy: {current?`${current.enabled?'Enabled':'Disabled'} · ${current.accessMode==='all_active_users'?'All active users':'Assigned users only'}`:'Loading...'}</p>
   <div className="form-group"><label className="form-label" htmlFor="app-access-mode">Who can access</label><select id="app-access-mode" className="form-input" value={mode} disabled={busy} onChange={e=>{const v=e.target.value;if(v==='all_active_users'||v==='assigned_only')setMode(v);}}><option value="assigned_only">Assigned users only</option><option value="all_active_users">All active users</option></select></div>
   <div className="form-group"><label><input type="checkbox" checked={enabled} disabled={busy} onChange={e=>setEnabled(e.target.checked)}/> App enabled</label></div>
   <div className="form-group"><label><input type="checkbox" checked={current?.requestable??app.requestable} disabled={busy||!current||current.accessMode!=='assigned_only'} onChange={e=>{if(current)void mutate('PUT',`${base}/requestable`,`${e.target.checked?'Open':'Close'} app ${app.id} to access requests from users who lack access.`,{requestable:e.target.checked,revision:current.revision});}}/> Users may request access (assigned-only apps; an owner or administrator approves each request)</label></div>
   <p role="status">{users.page?`${users.page.losingAccess} users would lose access and ${users.page.gainingAccess} would gain it with this policy. Preview reflects current directory membership.`:'Loading access preview...'}</p>
   <button className="primary-btn" disabled={busy||!changed||!users.page} onClick={()=>{if(users.page)void mutate('PUT',`${base}/access-policy`,`Set app ${app.id} to ${enabled?'enabled':'disabled'}, ${mode==='all_active_users'?'all active users':'assigned users only'}. ${users.page.losingAccess} users currently lose access.`,{mode,enabled,revision:users.page.app.revision});}}>Apply policy</button>
  </div></section>
  <div className="action-buttons-wrap"><button className="secondary-btn" aria-pressed={view==='users'} onClick={()=>{setView('users');setOffset(0);setQuery('');}}>Users and access preview</button><button className="secondary-btn" aria-pressed={view==='groups'} onClick={()=>{setView('groups');setOffset(0);setQuery('');}}>Group assignments</button></div>
  {view==='users'&&<div className="form-group"><label className="form-label" htmlFor="access-until">Direct assignments made now expire at (optional, {localZone()})</label><input id="access-until" type="datetime-local" className="form-input" value={until} disabled={busy} onChange={e=>setUntil(e.target.value)}/>{untilInstant&&<p className="text-muted">Exact instant: {describeInstant(untilInstant)}. Access ends then unless another grant still applies.</p>}</div>}
  <div className="form-group"><label className="form-label" htmlFor="access-search">Search {view}</label><input id="access-search" className="form-input" value={query} maxLength={200} disabled={busy} onChange={e=>{setQuery(e.target.value);setOffset(0);}}/></div>
  <div className="table-card"><table className="admin-table" style={{minWidth:'40rem'}}>
   {view==='users'?<><thead><tr><th>User</th><th>Current access</th><th>Policy preview</th><th>Direct assignment</th></tr></thead><tbody>{users.page?.items.map(u=><tr key={u.id}><td>{u.displayName||u.username}<div className="text-muted">{u.username}</div></td><td>{u.effective?'Allowed':'Denied'}<div className="text-muted">{u.reason.replaceAll('_',' ')}</div>{u.groupAssigned&&<div>Group assignment also applies</div>}<button className="secondary-btn sm" disabled={busy} onClick={()=>setExplaining({id:u.id,username:u.username})}>Explain</button></td><td>{u.preview?'Allowed':'Denied'}</td><td>{u.directExpiresAt&&<div className="text-muted">Until {describeInstant(u.directExpiresAt)}</div>}<div className="action-buttons-wrap"><button className="secondary-btn sm" disabled={busy} onClick={()=>mutate(u.direct?'DELETE':'PUT',`${base}/assignments/users/${encodeURIComponent(u.id)}`,`${u.direct?'Remove':'Add'} direct assignment for ${u.username} (${u.id}) on app ${app.id}${!u.direct&&untilInstant?` until ${untilInstant}`:''}. Other assignments still grant access.`,!u.direct&&untilInstant?{expiresAt:untilInstant}:undefined)}>{u.direct?'Remove direct assignment':'Assign user'}</button>{u.direct&&<button className="secondary-btn sm" disabled={busy} onClick={()=>mutate('PUT',`${base}/assignments/users/${encodeURIComponent(u.id)}`,`Set the direct assignment for ${u.username} on app ${app.id} to ${untilInstant?`end at ${untilInstant}`:'never expire'}.`,untilInstant?{expiresAt:untilInstant}:undefined)}>{untilInstant?'Set expiry':'Remove expiry'}</button>}</div></td></tr>)}</tbody></>
   :<><thead><tr><th>Group</th><th>Assignment</th></tr></thead><tbody>{groups.page?.items.map(g=><tr key={g.id}><td style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{g.name}<div className="text-muted"><code>{g.id}</code></div></td><td><button className="secondary-btn sm" disabled={busy} onClick={()=>mutate(g.assigned?'DELETE':'PUT',`${base}/assignments/groups/${encodeURIComponent(g.id)}`,`${g.assigned?'Remove':'Add'} group assignment ${g.name} (${g.id}) on app ${app.id}. Other assignments still grant access.`)}>{g.assigned?'Remove group assignment':'Assign group'}</button></td></tr>)}</tbody></>}
  </table></div>
  {page?.items.length===0&&<p className="empty-box">No matching {view}.</p>}
  <Pager page={page} offset={offset} onChange={setOffset}/>
  {explaining&&<AccessExplanation appId={app.id} userId={explaining.id} username={explaining.username} onClose={()=>setExplaining(null)}/>}
  {stepUpPrompt}
 </div>;
}
