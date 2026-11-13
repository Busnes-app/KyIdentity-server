import { useEffect, useState } from 'react';
import { apiJson, errorMessage } from '../api';
import { parseRateLimitNetworks } from '../parsers';
import type { RateLimitNetworks } from '../types';
import { isCancelled, useStepUp } from './StepUpPrompt';

// Stored lists are comma-separated; the field shows one network per line.
export const networksToText = (networks: string) => networks.split(',').filter(Boolean).join('\n');
export const textToNetworks = (text: string) => text.split(/[\s,]+/).filter(Boolean).join(',');

// Office networks whose sign-ins skip the per-address rate limit.
export function AdminOfficeNetworks() {
 const [status, setStatus] = useState<RateLimitNetworks | null>(null);
 const [text, setText] = useState('');
 const [busy, setBusy] = useState(false);
 const [error, setError] = useState<string | null>(null);
 const [message, setMessage] = useState<string | null>(null);
 const { requestGrant, stepUpPrompt } = useStepUp();
 const path = '/api/admin/rate-limit-networks';
 const show = (s: RateLimitNetworks) => { setStatus(s); setText(networksToText(s.networks)); };
 useEffect(() => { apiJson(path, parseRateLimitNetworks).then(show).catch(err => setError(errorMessage(err, 'Could not load the networks'))); }, []);
 const save = async (event: React.FormEvent) => {
  event.preventDefault();
  setBusy(true); setError(null); setMessage(null);
  try {
   const stepUpToken = await requestGrant('Change which networks skip the per-address sign-in limit.', `PUT ${path}`);
   const s = await apiJson(path, parseRateLimitNetworks, { method: 'PUT', stepUpToken, body: JSON.stringify({ networks: textToNetworks(text) }) });
   show(s);
   setMessage(s.networks ? 'Saved. These networks now skip the per-address limit.' : 'Saved. No network you listed skips the limit.');
  } catch (err) { if (!isCancelled(err)) setError(errorMessage(err, 'Could not save the networks')); }
  finally { setBusy(false); }
 };
 return <div className="settings-section"><form className="modal-body" onSubmit={save}><h2>Office networks</h2>
  <p>Sign-in is limited per network address. Staff in one office usually share one address and can trip that limit together. Networks listed here skip it; per-account lockouts and the second factor still apply.</p>
  {error && <div className="alert-box error" role="alert">{error}</div>}
  {message && <div className="alert-box success" role="status">{message}</div>}
  <div className="form-group"><label className="form-label" htmlFor="office-networks">Networks that skip the per-address limit, one per line</label>
   <textarea id="office-networks" className="form-input" rows={4} placeholder="203.0.113.0/24" aria-describedby="office-networks-hint" disabled={busy || !status} value={text} onChange={e => setText(e.target.value)}/></div>
  <p id="office-networks-hint">List only networks you control: everyone behind a listed address loses the limit, so never add guest Wi-Fi, a VPN provider or your reverse proxy. The widest range accepted is /16 (IPv4) or /48 (IPv6).</p>
  {status && <dl className="connection-details">
   {status.environment && <><dt>Also set by the server environment</dt><dd className="cell-id">{status.environment.split(',').join(', ')}</dd></>}
   <dt>Requests that skipped the limit</dt><dd>{status.exempted} since the last change or restart</dd>
  </dl>}
  <button className="primary-btn" disabled={busy || !status}>Save networks</button>
 </form>{stepUpPrompt}</div>;
}
