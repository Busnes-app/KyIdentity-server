import React, { useEffect, useRef, useState } from 'react';
import { apiJson, errorMessage } from '../api';
import { parseBranding, setBranding, useBranding } from '../branding';
import { PageHead } from './PageHead';

/** Organisation name and logo for the sign-in page and the shell (issue #145). */
export function AdminBranding() {
  const branding = useBranding();
  const [name, setName] = useState(branding.name);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const picker = useRef<HTMLInputElement>(null);
  useEffect(() => { setName(branding.name); }, [branding.name]);

  const run = async (what: string, done: string, call: () => Promise<unknown>) => {
    setBusy(true); setError(null); setNotice(null);
    try {
      setBranding(parseBranding(await call()));
      setNotice(done);
    } catch (err) { setError(errorMessage(err, what)); } finally { setBusy(false); }
  };

  const saveName = (e: React.FormEvent) => {
    e.preventDefault();
    void run('Could not save the name', 'Saved.', () => apiJson('/api/admin/branding/name', v => v, { method: 'PUT', body: JSON.stringify({ name: name.trim() }) }));
  };
  const upload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    if (file.size > 128 * 1024) { setError('Logo must be 128 KiB or smaller'); return; }
    void run('Upload failed', 'Logo saved.', () => apiJson('/api/admin/branding/logo', v => v, { method: 'PUT', body: file, headers: { 'Content-Type': file.type } }));
  };
  const removeLogo = () => {
    void run('Could not remove the logo', 'Logo removed.', () => apiJson('/api/admin/branding/logo', v => v, { method: 'DELETE' }));
  };

  return (
    <div className="admin-page">
      <PageHead title="Branding" lede="Your organisation's name and logo on the sign-in page and beside the menu." />
      {error && <div className="alert-box error" role="alert">{error}</div>}
      {notice && <div className="alert-box" role="status">{notice}</div>}
      <form className="settings-section inline-form" onSubmit={saveName}>
        <div className="form-row">
          <div className="form-group flex-1">
            <label className="form-label" htmlFor="branding-name">Organisation name</label>
            <input id="branding-name" className="form-input" maxLength={64} placeholder="KyIdentity" value={name} onChange={e => setName(e.target.value)} disabled={busy} />
          </div>
          <button type="submit" className="primary-btn" disabled={busy || name.trim() === branding.name}>Save</button>
        </div>
      </form>
      <section className="settings-section inline-form" aria-labelledby="branding-logo">
        <p className="form-label" id="branding-logo">Logo</p>
        <p className="form-hint">A square PNG or JPEG, up to 512 by 512 pixels and 128 KiB, shown at 28 and 56 pixels. It is re-encoded on upload. Without one, the KyIdentity mark shows.</p>
        <div className="form-row">
          {branding.logoUrl && <img className="brand-logo" src={branding.logoUrl} width={40} height={40} alt="Current logo" />}
          <input ref={picker} type="file" accept="image/png,image/jpeg" hidden onChange={upload} />
          <button type="button" className="secondary-btn" onClick={() => picker.current?.click()} disabled={busy}>{branding.logoUrl ? 'Replace logo' : 'Upload logo'}</button>
          {branding.logoUrl && <button type="button" className="secondary-btn" onClick={removeLogo} disabled={busy}>Remove logo</button>}
        </div>
      </section>
    </div>
  );
}
