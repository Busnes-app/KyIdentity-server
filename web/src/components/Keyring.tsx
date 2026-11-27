import { wipeTransfer } from '../keyringCrypto';
import { useEffect, useRef, useState } from 'react';
import { ApiError, errorMessage } from '../api';
import {
  approveTransfer, formatRecoveryKey, importKeyringSecret, newKeyringSecret, newTransfer,
  openTransfer, parseRecoveryKey, parseTransferCode, transferCode, unwrapRoot, wrapRoot,
} from '../keyringCrypto';
import type { PendingTransfer, RingContext } from '../keyringCrypto';
import { createKeyringDevice, findKeyringDevice, forgetKeyringDevice } from '../keyringDevice';
import { getKeyringPasskey, keyringPRFAvailable, newKeyringPasskey } from '../keyringPRF';
import { claimTransfer, credentialBytes, fetchWrapper, loadRing, readTransfer, ringPaths, writeRing } from '../keyringAPI';
import type { RingStatus, WrapperInfo } from '../keyringAPI';
import { Modal } from './Modal';
import { isCancelled, useStepUp } from './StepUpPrompt';

type Kit = { kind: 'setup' | 'rotate'; code: string };
type LocalDevice = Awaited<ReturnType<typeof findKeyringDevice>>;

function noKeyringItem(err: unknown) {
  return err instanceof ApiError && err.status === 404;
}

function downloadKit(text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'suite-emergency-kit.txt';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function Keyring({ userID, username }: { userID: string; username: string }) {
  const [ring, setRing] = useState<RingStatus>();
  const [local, setLocal] = useState<LocalDevice>();
  const [unlocked, setUnlocked] = useState(false);
  const root = useRef<Uint8Array<ArrayBuffer> | undefined>(undefined);
  const pending = useRef<PendingTransfer | undefined>(undefined);
  const [code, setCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [approvalCode, setApprovalCode] = useState('');
  const [kit, setKit] = useState<Kit>();
  const [confirmation, setConfirmation] = useState('');
  const [revoke, setRevoke] = useState<WrapperInfo>();
  const [prf, setPRF] = useState(false);
  const [busy, setBusy] = useState(false);
  const working = useRef(false);
  const mounted = useRef(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const { requestGrant, stepUpPrompt } = useStepUp();

  async function refresh() {
    const status = await loadRing();
    if (status.user_id !== userID) throw new Error('Your signed-in account changed. Reopen Settings to continue.');
    const device = status.keyring_version && typeof indexedDB !== 'undefined'
      ? await findKeyringDevice(status, status.wrappers.filter(w => w.kind === 'device').map(w => w.id)).catch(() => undefined)
      : undefined;
    if (mounted.current) {
      setLocal(device);
      setRing(status);
    }
  }

  async function run(work: () => Promise<void>) {
    if (working.current) return;
    working.current = true;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await work();
    } catch (err) {
      if (mounted.current && !isCancelled(err)) setError(errorMessage(err, 'The keyring could not complete this action.'));
    } finally {
      working.current = false;
      if (mounted.current) setBusy(false);
    }
  }

  function setRoot(value?: Uint8Array<ArrayBuffer>) {
    root.current?.fill(0);
    if (mounted.current) {
      root.current = value;
      setUnlocked(value !== undefined);
    } else {
      value?.fill(0);
    }
  }

  useEffect(() => {
    mounted.current = true;
    if (globalThis.isSecureContext && globalThis.crypto?.subtle && typeof indexedDB !== 'undefined') {
      void run(refresh);
      void keyringPRFAvailable().then(supported => {
        if (mounted.current) setPRF(supported);
      }).catch(() => undefined);
    } else {
      setError('The keyring requires a secure browser session with WebCrypto and browser storage.');
    }
    return () => {
      mounted.current = false;
      root.current?.fill(0);
      root.current = undefined;
      wipeTransfer(pending.current);
      pending.current = undefined;
    };
  }, [userID]);

  function showKit(kind: Kit['kind']) {
    const secret = newKeyringSecret();
    setKit({ kind, code: formatRecoveryKey(secret) });
    secret.fill(0);
    setConfirmation('');
    setError('');
  }

  function closeKit() {
    setKit(undefined);
    setConfirmation('');
  }

  async function confirmKit(context: RingStatus, draft: Kit) {
    const initial = draft.kind === 'setup';
    const before = context.wrappers.find(w => w.kind === 'recovery');
    if (!initial && (!root.current || !before)) throw new Error('Unlock your keyring before rotating the Emergency Kit.');
    const path = initial ? ringPaths.status : ringPaths.recovery;
    const method = initial ? 'POST' : 'PUT';
    const grant = await requestGrant('Confirm your identity to save the Emergency Kit.', method + ' ' + path);
    const scope = initial ? { ...context, keyring_version: crypto.randomUUID() } : context;
    const active = initial ? newKeyringSecret() : root.current;
    if (!active) throw new Error('Unlock the keyring first.');
    try {
      const recovery = parseRecoveryKey(draft.code);
      const material = await importKeyringSecret(recovery).finally(() => recovery.fill(0));
      const id = crypto.randomUUID();
      const wrapper = { id, kind: 'recovery', sealed: await wrapRoot({ context: scope, id, kind: 'recovery' }, material, active) };
      const keyring_version = scope.keyring_version;
      if (initial) {
        const { wrapper: device } = await createKeyringDevice(scope, active);
        await writeRing(path, method, { keyring_version, org_id: scope.org_id, user_id: scope.user_id, device, recovery: wrapper }, grant);
      } else {
        await writeRing(path, method, { keyring_version, previous_id: before?.id, wrapper }, grant);
      }
      closeKit();
      setNotice(initial ? 'Keyring created. This browser is trusted.' : 'Emergency Kit rotated. Replace all copies of your previous kit.');
      await refresh();
    } finally {
      if (initial) active.fill(0);
    }
  }

  async function unlockDevice(context: RingContext, device: NonNullable<LocalDevice>) {
    const info = { id: device.id, kind: 'device' } as const;
    const sealed = await fetchWrapper(info, device.capability).catch(err => {
      if (noKeyringItem(err)) {
        setLocal(undefined);
        throw new Error('This browser is no longer trusted. Link it again or use your Emergency Kit.');
      }
      throw err;
    });
    setRoot(await unwrapRoot({ context, ...info }, device.secret, sealed).catch(() => {
      throw new Error('This browser could not unlock the keyring. Use your Emergency Kit or a keyring passkey.');
    }));
  }

  async function registerBrowser(context: RingContext, active: Uint8Array<ArrayBuffer>, grant: string) {
    const { wrapper } = await createKeyringDevice(context, active);
    await writeRing(ringPaths.wrappers, 'POST', { keyring_version: context.keyring_version, wrapper }, grant);
    setRecoveryCode('');
    await refresh();
    setRoot(active.slice());
    setNotice('This browser is now trusted.');
  }

  async function recover(context: RingStatus) {
    const info = context.wrappers.find(w => w.kind === 'recovery');
    if (!info) throw new Error('This keyring has no Emergency Kit wrapper.');
    const bytes = parseRecoveryKey(recoveryCode);
    const material = await importKeyringSecret(bytes).finally(() => bytes.fill(0));
    const sealed = await fetchWrapper(info);
    const active = await unwrapRoot({ context, ...info }, material, sealed).catch(() => {
      throw new Error('This Emergency Kit does not unlock the current keyring.');
    });
    try {
      const grant = await requestGrant('Confirm your identity to trust this browser.', 'POST ' + ringPaths.wrappers);
      await registerBrowser(context, active, grant);
    } finally {
      active.fill(0);
    }
  }

  async function addPasskey(context: RingContext) {
    const active = root.current;
    if (!active) return;
    const grant = await requestGrant('Confirm your identity to add a keyring passkey.', 'POST ' + ringPaths.wrappers);
    const { credential_id, secret } = await newKeyringPasskey(context.user_id, username);
    const id = crypto.randomUUID();
    const sealed = await wrapRoot({ context, id, kind: 'prf' }, secret, active);
    await writeRing(ringPaths.wrappers, 'POST', { keyring_version: context.keyring_version, wrapper: { id, kind: 'prf', credential_id, sealed } }, grant);
    await refresh();
    setNotice('Keyring passkey added.');
  }

  async function unlockPasskey(context: RingContext, info: Extract<WrapperInfo, {kind: 'prf'}>) {
    const material = await getKeyringPasskey(credentialBytes(info.credential_id));
    const sealed = await fetchWrapper(info);
    setRoot(await unwrapRoot({ context, ...info }, material, sealed));
  }

  async function revokeWrapper(info: WrapperInfo) {
    const path = ringPaths.wrapper(info.id);
    const grant = await requestGrant('Confirm your identity to revoke this unlock method.', 'DELETE ' + path);
    await writeRing(path, 'DELETE', undefined, grant);
    setRevoke(undefined);
    if (info.id === local?.id) setRoot();
    if (info.kind === 'device') await forgetKeyringDevice(info.id).catch(() => undefined);
    await refresh();
    setNotice('Unlock method revoked.');
  }

  function clearTransfer() {
    wipeTransfer(pending.current);
    pending.current = undefined;
    setCode('');
  }

  async function startTransfer(context: RingContext) {
    const draft = await newTransfer(context);
    try {
      await writeRing(ringPaths.transfers, 'POST', { keyring_version: context.keyring_version, id: draft.id, ...draft.request });
      if (!mounted.current) {
        wipeTransfer(draft);
        return;
      }
      pending.current = draft;
      setCode(transferCode(draft));
    } catch (err) {
      wipeTransfer(draft);
      throw err;
    }
  }

  async function cancelTransfer() {
    const draft = pending.current;
    if (!draft) return;
    await writeRing(ringPaths.transfer(draft.id), 'DELETE').catch(err => {
      if (!noKeyringItem(err)) throw err;
    });
    clearTransfer();
  }

  async function approve(context: RingContext, device: NonNullable<LocalDevice>) {
    const active = root.current;
    if (!active) return;
    const approval = parseTransferCode(approvalCode);
    try {
      const request = await readTransfer(approval.id);
      const response = await approveTransfer(context, approval, request, active);
      const path = ringPaths.transfer(approval.id) + '/approve';
      const grant = await requestGrant('Approve only a browser you are signing in to yourself. Requested by '
        + `${request.user_agent || 'an unknown browser'} at ${request.ip_address || 'an unknown address'}, signed in `
        + `${new Date(request.signed_in_at * 1000).toLocaleString()}.`, 'PUT ' + path);
      await writeRing(path, 'PUT', { ...response, device_id: device.id }, grant, device.capability);
      setApprovalCode('');
      setNotice('Approved. Finish linking on the requesting browser.');
    } finally {
      approval.secret.fill(0);
    }
  }

  async function completeTransfer(context: RingContext) {
    const draft = pending.current;
    if (!draft) return;
    try {
      const response = await claimTransfer(draft.id).catch(err => {
        if (noKeyringItem(err)) throw new Error('Approval is pending or expired. Check the trusted browser or cancel and start again.');
        throw err;
      });
      let active: Uint8Array<ArrayBuffer>;
      try {
        active = await openTransfer(context, draft, response);
      } finally {
        clearTransfer();
      }
      try {
        const grant = await requestGrant('Confirm your identity to trust this browser.', 'POST ' + ringPaths.wrappers);
        await registerBrowser(context, active, grant);
      } finally {
        active.fill(0);
      }
    } catch (err) {
      if (isCancelled(err) && !pending.current) throw new Error('Linking was cancelled after claiming approval. Start a new request or use your Emergency Kit.');
      throw err;
    }
  }

  const feedback = error ? <p role="alert" className="alert-box error">{error}</p> : null;
  const kitText = kit && ring ? [
    'Suite Emergency Kit', ring.issuer, 'Account: ' + username, '', kit.code, '',
    'Keep this somewhere safe. To regain access, sign in to KyIdentity and open Settings → Suite keyring.',
    'Anyone with this kit and access to your account can unlock your suite keys.', '',
  ].join('\n') : '';

  return <div className="settings-page security-page">
    <div className="settings-section">
      <div className="section-header"><div className="section-title-wrap"><h2>Suite keyring</h2></div></div>
      {feedback}
      {notice && <p role="status" className="alert-box">{notice}</p>}
      {!ring && !error && <p role="status">Loading keyring…</p>}
      {!ring && error && globalThis.isSecureContext && globalThis.crypto?.subtle && typeof indexedDB !== 'undefined' &&
        <button type="button" className="secondary-btn" disabled={busy} onClick={() => void run(refresh)}>Try again</button>}
      {ring && !ring.keyring_version &&
        <button type="button" className="primary-btn" disabled={busy} onClick={() => showKit('setup')}>Set up keyring</button>}
      {ring && ring.keyring_version && <>
        <p className="text-muted text-sm" role="status">{unlocked ? 'Unlocked in this tab.' : 'Locked.'}</p>
        <div className="form-row keyring-actions">
          {unlocked && <button type="button" className="secondary-btn" disabled={busy} onClick={() => setRoot()}>Lock keyring</button>}
          {!unlocked && local && <button type="button" className="primary-btn" disabled={busy} onClick={() => void run(() => unlockDevice(ring, local))}>Unlock this browser</button>}
          {unlocked && <button type="button" className="secondary-btn" disabled={busy} onClick={() => showKit('rotate')}>Rotate Emergency Kit</button>}
          {unlocked && prf && <button type="button" className="secondary-btn" disabled={busy} onClick={() => void run(() => addPasskey(ring))}>Add keyring passkey</button>}
          {unlocked && !local && <button type="button" className="primary-btn" disabled={busy} onClick={() => void run(async () => {
            const active = root.current;
            if (!active) return;
            const grant = await requestGrant('Confirm your identity to trust this browser.', 'POST ' + ringPaths.wrappers);
            await registerBrowser(ring, active, grant);
          })}>Trust this browser</button>}
        </div>
      </>}
    </div>

    {ring && ring.keyring_version && <>
      {!unlocked && !local && <div className="settings-section">
        <h3>Link this browser</h3>
        {code ? <>
          <p>Send this code directly to your trusted browser. The request expires after five minutes.</p>
          <code className="keyring-code">{code}</code>
          <div className="form-row keyring-actions">
            <button type="button" className="primary-btn" disabled={busy} onClick={() => void run(() => completeTransfer(ring))}>Finish linking</button>
            <button type="button" className="secondary-btn" disabled={busy} onClick={() => void run(cancelTransfer)}>Cancel request</button>
          </div>
        </> : <>
          <p>Keep this tab open. You’ll enter the approval code on a different browser where your keyring is already unlocked.</p>
          <button type="button" className="secondary-btn" disabled={busy} onClick={() => void run(() => startTransfer(ring))}>Get approval code</button>
        </>}
      </div>}
      {!unlocked && <form className="settings-section" onSubmit={e => { e.preventDefault(); void run(() => recover(ring)); }}>
        <h3>Use an Emergency Kit</h3>
        <div className="form-group">
          <label className="form-label" htmlFor="keyring-recovery">Suite Recovery Key</label>
          <input id="keyring-recovery" type="password" className="form-input" value={recoveryCode} onChange={e => setRecoveryCode(e.target.value)} autoComplete="off" spellCheck={false} maxLength={100} required />
        </div>
        <button type="submit" className="secondary-btn" disabled={busy || !recoveryCode}>Recover and trust this browser</button>
      </form>}
      {unlocked && local && <form className="settings-section" onSubmit={e => { e.preventDefault(); void run(() => approve(ring, local)); }}>
        <h3>Approve a new browser</h3>
        <div className="form-group">
          <label className="form-label" htmlFor="keyring-approval">Code from your new browser</label>
          <input id="keyring-approval" type="password" className="form-input" value={approvalCode} onChange={e => setApprovalCode(e.target.value)} autoComplete="off" spellCheck={false} maxLength={100} required />
        </div>
        <button type="submit" className="secondary-btn" disabled={busy || !approvalCode}>Approve browser</button>
      </form>}
      <div className="settings-section">
        <h3>Trusted browsers and passkeys</h3>
        {ring.wrappers.every(w => w.kind === 'recovery') ? <p>No browsers or passkeys are registered.</p> :
          <ul className="keyring-devices">{ring.wrappers.filter(w => w.kind !== 'recovery').map(w => (
            <li key={w.id}>
              <div><strong>{w.kind === 'prf' ? 'Keyring passkey' : w.id === local?.id ? 'This browser' : 'Trusted browser'}</strong>
                <code className="keyring-code text-muted text-sm">{w.id}</code></div>
              <div className="form-row keyring-actions">
                {!unlocked && prf && w.kind === 'prf' && <button type="button" className="secondary-btn sm" disabled={busy} onClick={() => void run(() => unlockPasskey(ring, w))}>Unlock with passkey</button>}
                <button type="button" className="secondary-btn danger sm" disabled={busy} onClick={() => { setError(''); setRevoke(w); }} aria-label={`Revoke ${w.kind === 'prf' ? 'passkey' : 'browser'} ${w.id.slice(0, 8)}`}>Revoke</button>
              </div>
            </li>
          ))}</ul>}
      </div>
    </>}

    {kit && ring && <Modal title="Suite Emergency Kit" onClose={() => { if (!busy) closeKit(); }}>
      <form className="modal-body" onSubmit={e => { e.preventDefault(); if (confirmation.trim().toUpperCase() === kit.code) void run(() => confirmKit(ring, kit)); }}>
        <p>Save your kit somewhere you can reach if you lose every trusted browser. {kit.kind === 'rotate' && 'After you confirm, the previous kit stops working.'}</p>
        <div className="keyring-print"><pre className="keyring-code">{kitText}</pre></div>
        <div className="form-row keyring-actions">
          <button type="button" className="secondary-btn" onClick={() => downloadKit(kitText)}>Download kit</button>
          <button type="button" className="secondary-btn" onClick={() => window.print()}>Print kit</button>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="keyring-confirm">Re-enter the recovery key you saved</label>
          <input id="keyring-confirm" type="password" className="form-input" value={confirmation} onChange={e => setConfirmation(e.target.value)} autoComplete="off" spellCheck={false} maxLength={100} required />
        </div>
        {feedback}
        <div className="modal-footer"><button type="submit" className="primary-btn" disabled={busy || confirmation.trim().toUpperCase() !== kit.code}>Confirm saved kit</button></div>
      </form>
    </Modal>}
    {revoke && <Modal title={revoke.kind === 'prf' ? 'Revoke keyring passkey' : 'Revoke trusted browser'} onClose={() => { if (!busy) setRevoke(undefined); }}>
      <div className="modal-body">
        <p>KyIdentity will stop delivering this wrapper. Use another trusted browser or your Emergency Kit to regain access.</p>
        {feedback}
        <div className="modal-footer"><button type="button" className="primary-btn danger" disabled={busy} onClick={() => void run(() => revokeWrapper(revoke))}>Revoke access</button></div>
      </div>
    </Modal>}
    {stepUpPrompt}
  </div>;
}
