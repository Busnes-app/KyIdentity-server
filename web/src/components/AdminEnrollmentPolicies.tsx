import { useEffect, useState } from 'react';
import { apiJson, apiRequest, errorMessage } from '../api';
import { parseAttestationSettings, parseEnrollmentPolicies, parseEnrollmentPreview } from '../parsers';
import type { DirectoryGroup, EnrollmentPolicy, EnrollmentPreview } from '../types';
import { isCancelled, useStepUp } from './StepUpPrompt';

export function AdminEnrollmentPolicies({group,onBack}: {group?: DirectoryGroup; onBack?: () => void}) {
 const scopeLabel=(scope:string)=>scope==='organization'?'Everyone':scope==='administrators'?'Administrators':group?.name ?? 'Group';
 const listPath='/api/admin/enrollment-policies'+(group?'?'+new URLSearchParams({groupId:group.id}):'');
 const [policies,setPolicies]=useState<EnrollmentPolicy[]>([]);
 const [draft,setDraft]=useState<EnrollmentPolicy|null>(null);
 const [preview,setPreview]=useState<EnrollmentPreview|null>(null);
 const [error,setError]=useState<string|null>(null);
 const [busy,setBusy]=useState(false);
 const {requestGrant,stepUpPrompt}=useStepUp();
 const reload=async()=>{try{setPolicies(await apiJson(listPath,parseEnrollmentPolicies));}catch(err){setError(errorMessage(err,'Could not load policies'));}};
 const [lockedBootloader,setLockedBootloader]=useState<boolean|null>(null);
 useEffect(()=>{void reload();},[]);
 useEffect(()=>{if(group)return;apiJson('/api/admin/attestation/settings',parseAttestationSettings).then(s=>setLockedBootloader(s.requireLockedBootloader)).catch(err=>setError(errorMessage(err,'Could not load device sign-on setting')));},[group]);
 const saveBootloader=async(value:boolean)=>{
  setBusy(true);setError(null);
  try{const path='/api/admin/attestation/settings';const stepUpToken=await requestGrant(value?'Require a locked bootloader for MFA-grade device sign-on.':'Stop requiring a locked bootloader for MFA-grade device sign-on.',`PUT ${path}`);
   setLockedBootloader((await apiJson(path,parseAttestationSettings,{method:'PUT',stepUpToken,body:JSON.stringify({requireLockedBootloader:value})})).requireLockedBootloader);
  }catch(err){if(!isCancelled(err))setError(errorMessage(err,'Could not save device sign-on setting'));}finally{setBusy(false);}
 };
 const change=(p:EnrollmentPolicy)=>{setDraft(p);setPreview(null);setError(null);};
 const inspect=async(event:React.FormEvent)=>{
  event.preventDefault();if(!draft)return;setBusy(true);setError(null);
  try{setPreview(await apiJson('/api/admin/enrollment-policies/preview',parseEnrollmentPreview,{method:'POST',body:JSON.stringify(draft)}));}
  catch(err){setError(errorMessage(err,'Could not preview policy'));}finally{setBusy(false);}
 };
 const apply=async()=>{
  if(!draft||!preview?.canActivate)return;setBusy(true);setError(null);
  try{const path='/api/admin/enrollment-policies';const stepUpToken=await requestGrant(`Apply ${scopeLabel(draft.scope)} MFA policy. Outstanding OAuth sign-ins and registered tokens will be revoked. Existing deadlines are never extended.`,`PUT ${path}`);
   await apiRequest(path,{method:'PUT',stepUpToken,body:JSON.stringify(draft)});setDraft(null);setPreview(null);await reload();
  }catch(err){if(!isCancelled(err))setError(errorMessage(err,'Could not apply policy; reload before retrying.'));}finally{setBusy(false);}
 };
 return <div className="admin-page"><div className="page-header"><h1 className="page-title">{group ? `MFA policy for ${group.name}` : 'MFA enrollment policies'}</h1>{onBack&&<button className="secondary-btn" disabled={busy} onClick={onBack}>Back to groups</button>}<button className="secondary-btn" disabled={busy} onClick={()=>{setDraft(null);setPreview(null);void reload();}}>Reload policies</button></div>
  <p>Organization, administrator and group requirements combine: permitted factors must overlap, and the earliest enrollment deadline applies. App-specific authentication can remain stricter during grace.</p>
  <p>If the resulting policies require MFA for your account, sign in with a permitted administrator factor within the last five minutes before applying them. This verifies a local administrator can still sign in; there is no policy bypass.</p>
  {error&&<div className="alert-box error" role="alert">{error}</div>}
  <div className="table-card"><table className="admin-table"><thead><tr><th>Scope</th><th>Requirement</th><th>Permitted factors</th><th>Grace</th><th>Action</th></tr></thead><tbody>{policies.map(p=><tr key={p.scope}><td>{scopeLabel(p.scope)}</td><td>{p.required?'MFA required':'No additional requirement'}</td><td>{p.allowedMethods.map(m=>m==='webauthn'?'Passkey':m.toUpperCase()).join(', ')}</td><td>{p.graceSeconds/86400} days</td><td><button className="secondary-btn" disabled={busy} onClick={()=>change(p)}>Edit {scopeLabel(p.scope)}</button></td></tr>)}</tbody></table></div>
  {draft&&<form className="settings-section" onSubmit={inspect}><div className="modal-body"><h2>{scopeLabel(draft.scope)} policy</h2>
   <div className="form-group"><label><input type="checkbox" checked={draft.required} disabled={busy} onChange={e=>change({...draft,required:e.target.checked})}/> Require MFA</label></div>
   <fieldset disabled={busy}><legend>Permitted factors</legend>{(['totp','push','webauthn']).map(method=><label key={method} style={{display:'block',marginBottom:'0.5rem'}}><input type="checkbox" checked={draft.allowedMethods.includes(method)} onChange={e=>change({...draft,allowedMethods:e.target.checked?[...draft.allowedMethods,method]:draft.allowedMethods.filter(m=>m!==method)})}/> {method==='webauthn'?'Passkey':method.toUpperCase()}</label>)}</fieldset>
   <div className="form-group"><label className="form-label" htmlFor="enrollment-grace">Grace period for first-time enrollment (days)</label><input id="enrollment-grace" className="form-input" type="number" min="0" max="90" step="1" required disabled={busy} value={draft.graceSeconds/86400} onChange={e=>change({...draft,graceSeconds:e.target.valueAsNumber*86400})}/></div>
   <p>Zero requires enrollment immediately. Existing deadlines only become earlier; sign-in, longer grace settings, policy reactivation and membership removal/re-addition cannot restart grace. Already-enrolled users must sign in with a permitted factor.</p>
   <button className="secondary-btn" disabled={busy||draft.allowedMethods.length===0}>Preview impact</button>
   {preview&&<div role="status"><p>{preview.affected} active users are covered; {preview.missingFactor} lack a permitted factor. {preview.restrictedSessions} live sessions would be restricted to enrollment. {group ? 'These counts include all applicable policies for members of this group.' : 'These counts include all organization, administrator and group policies.'}</p>
    {!preview.canActivate&&<p>Sign out and sign in with a permitted administrator factor, then reopen this policy. Password-only or recovery sign-in cannot activate it.</p>}
    <p>Applying cancels outstanding OAuth sign-ins and revokes registered tokens. Offline access tokens may remain valid for up to 15 minutes, and destination app sessions may last longer.</p>
    <button type="button" className="primary-btn" disabled={busy||!preview.canActivate} onClick={apply}>Apply policy</button>
   </div>}
  </div></form>}
  {!group&&<div className="settings-section"><div className="modal-body"><h2>Device sign-on</h2>
   <div className="form-group"><label><input type="checkbox" checked={lockedBootloader??false} disabled={busy||lockedBootloader===null} onChange={e=>void saveBootloader(e.target.checked)}/> Require a locked bootloader for MFA-grade device sign-on</label></div>
   <p>Off: the bootloader state is recorded but not enforced. On: new pairings and the daily sweep refuse MFA grade for unlocked bootloaders.</p>
  </div></div>}
  {stepUpPrompt}
 </div>;
}
