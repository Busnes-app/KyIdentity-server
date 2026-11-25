import { useEffect, useRef, useState } from 'react';
import { ApiError, errorMessage } from '../api';
import {
  buildHandoffErrorURL, buildHandoffRedirectURL, formatRecoveryKey, importKeyringSecret,
  newKeyringSecret, newTransfer, newWrappedAppKey, openTransfer, parseRecoveryKey,
  sealHandoffKey, transferCode, unwrapAppKey, unwrapRoot, wrapRoot,
} from '../keyringCrypto';
import type { PendingTransfer, RingContext } from '../keyringCrypto';
import { createKeyringDevice, findKeyringDevice, forgetKeyringDevice } from '../keyringDevice';
import { getKeyringPasskey, keyringPRFAvailable } from '../keyringPRF';
import {
  cancelHandoff, claimTransfer, completeHandoff, credentialBytes, fetchWrapper,
  loadHandoff, ringPaths, saveAppKey, writeRing,
} from '../keyringAPI';
import type { KeyringHandoffDetails, WrapperInfo } from '../keyringAPI';
import type { User } from '../types';
import { AuthFrame } from './AuthFrame';
import { isCancelled, useStepUp } from './StepUpPrompt';

type Stage = 'loading' | 'setup_keyring' | 'unlock' | 'provision_app' | 'redirecting' | 'fatal';

function ringContextFrom(details: KeyringHandoffDetails, versionOverride?: string): RingContext {
  return {
    issuer: details.issuer,
    org_id: details.org_id,
    user_id: details.user_id,
    keyring_version: versionOverride ?? details.keyring_version,
  };
}

function downloadKit(text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'suite-emergency-kit.txt';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/**
 * /keyring-handoff: browser-bound step during OIDC authorization with `keyring_pk`.
 * Unlocks the member's zero-knowledge suite keyring (automatically on a trusted
 * browser, or interactively via passkey PRF / transfer / Emergency Kit), seals the
 * target app's subkey to the app's ephemeral P-256 key, binds it to the fresh
 * authorization code, and returns it strictly in the callback URL fragment.
 */
export function KeyringHandoff({ user }: { user: User }) {
  const interaction = useRef(new URLSearchParams(window.location.search).get('interaction') ?? '').current;
  const [stage, setStage] = useState<Stage>(interaction ? 'loading' : 'fatal');
  const [details, setDetails] = useState<KeyringHandoffDetails | null>(null);
  const [prfAvailable, setPrfAvailable] = useState(false);
  const [trustBrowser, setTrustBrowser] = useState(true);
  const [recoveryInput, setRecoveryInput] = useState('');
  const [pendingTransfer, setPendingTransfer] = useState<PendingTransfer | null>(null);
  const [setupCode, setSetupCode] = useState<string | null>(null);
  const [setupConfirm, setSetupConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(
    interaction ? null : 'This sign-in link is missing its handoff token. Return to the application and sign in again.',
  );

  const rootRef = useRef<Uint8Array<ArrayBuffer> | undefined>(undefined);
  const setupRootRef = useRef<Uint8Array<ArrayBuffer> | undefined>(undefined);
  const setupRecoveryRef = useRef<Uint8Array<ArrayBuffer> | undefined>(undefined);
  const transferRef = useRef<PendingTransfer | null>(null);
  transferRef.current = pendingTransfer;
  const stepUp = useStepUp();

  const clearSecrets = () => {
    rootRef.current?.fill(0);
    rootRef.current = undefined;
    setupRootRef.current?.fill(0);
    setupRootRef.current = undefined;
    setupRecoveryRef.current?.fill(0);
    setupRecoveryRef.current = undefined;
    transferRef.current?.secret.fill(0);
  };

  useEffect(() => () => { clearSecrets(); }, []);

  const finishWithSubkey = async (
    current: KeyringHandoffDetails,
    context: RingContext,
    keyVersion: number,
    subkey: Uint8Array<ArrayBuffer>,
  ) => {
    setStage('redirecting');
    try {
      const done = await completeHandoff(interaction);
      const sealed = await sealHandoffKey({
        context,
        client: current.client_id,
        version: keyVersion,
        code: done.code,
        redirect_uri: done.redirect_uri,
        recipient_key: current.keyring_pk,
      }, subkey);
      const target = buildHandoffRedirectURL(done.redirect_uri, done.code, done.state, {
        ...sealed,
        key_version: keyVersion,
        keyring_version: context.keyring_version,
      });
      clearSecrets();
      window.location.replace(target);
    } finally {
      subkey.fill(0);
    }
  };

  const deliverOrProvision = async (current: KeyringHandoffDetails, root: Uint8Array<ArrayBuffer>, context: RingContext) => {
    const appKey = current.app_key;
    if (appKey && appKey.sealed !== '') {
      let subkey: Uint8Array<ArrayBuffer>;
      try {
        subkey = await unwrapAppKey(
          { context, client: current.client_id, version: appKey.key_version },
          root,
          appKey.sealed,
        );
      } finally {
        root.fill(0);
      }
      await finishWithSubkey(current, context, appKey.key_version, subkey);
      return;
    }
    rootRef.current?.fill(0);
    rootRef.current = root;
    setDetails({ ...current, keyring_version: context.keyring_version });
    setStage('provision_app');
  };

  useEffect(() => {
    if (!interaction) return;
    let active = true;
    (async () => {
      try {
        const [loaded, prfOk] = await Promise.all([loadHandoff(interaction), keyringPRFAvailable().catch(() => false)]);
        if (!active) return;
        setDetails(loaded);
        setPrfAvailable(prfOk);

        if (loaded.keyring_version === '') {
          setStage('setup_keyring');
          return;
        }

        const context = ringContextFrom(loaded);
        const deviceWrappers = loaded.wrappers.filter((w): w is Extract<WrapperInfo, { kind: 'device' }> => w.kind === 'device');
        const local = await findKeyringDevice(context, deviceWrappers.map(w => w.id)).catch(() => undefined);
        if (!active) return;

        if (local) {
          const info = deviceWrappers.find(w => w.id === local.id);
          if (info) {
            try {
              const sealed = await fetchWrapper(info, local.capability);
              const root = await unwrapRoot({ context, id: info.id, kind: 'device' }, local.secret, sealed);
              if (!active) { root.fill(0); return; }
              await deliverOrProvision(loaded, root, context);
              return;
            } catch (err) {
              if (err instanceof ApiError && err.status === 404) {
                await forgetKeyringDevice(local.id).catch(() => {});
              }
            }
          }
        }
        if (active) setStage('unlock');
      } catch (err) {
        if (!active) return;
        setError(errorMessage(err, 'This keyring handoff could not be loaded. Return to the application and try again.'));
        setStage('fatal');
      }
    })();
    return () => { active = false; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [interaction]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      if (!isCancelled(err)) setError(errorMessage(err, 'Could not complete keyring handoff.'));
    } finally {
      setBusy(false);
    }
  };

  const maybeTrustThisBrowser = async (context: RingContext, root: Uint8Array<ArrayBuffer>) => {
    if (!trustBrowser) return;
    try {
      const created = await createKeyringDevice(context, root);
      try {
        const token = await stepUp.requestGrant(`Trust this browser for ${user.username}'s suite keyring`, `POST ${ringPaths.wrappers}`);
        await writeRing(ringPaths.wrappers, 'POST', created.wrapper, token);
      } catch (err) {
        await forgetKeyringDevice(created.device.id).catch(() => {});
        if (!isCancelled(err)) throw err;
      }
    } catch (err) {
      if (!isCancelled(err)) throw err;
    }
  };

  const handleUnlockedRoot = async (current: KeyringHandoffDetails, root: Uint8Array<ArrayBuffer>) => {
    const context = ringContextFrom(current);
    try {
      await maybeTrustThisBrowser(context, root);
      await deliverOrProvision(current, root, context);
    } catch (err) {
      if (rootRef.current !== root) root.fill(0);
      throw err;
    }
  };

  const unlockWithPRF = () => {
    if (!details) return;
    const prfWrappers = details.wrappers.filter((w): w is Extract<WrapperInfo, { kind: 'prf' }> => w.kind === 'prf');
    if (prfWrappers.length === 0) return;
    void run(async () => {
      const context = ringContextFrom(details);
      let lastErr: unknown;
      for (const wrapper of prfWrappers) {
        try {
          const material = await getKeyringPasskey(credentialBytes(wrapper.credential_id));
          const sealed = await fetchWrapper(wrapper);
          const root = await unwrapRoot({ context, id: wrapper.id, kind: 'prf' }, material, sealed);
          await handleUnlockedRoot(details, root);
          return;
        } catch (err) {
          lastErr = err;
        }
      }
      throw lastErr instanceof Error ? lastErr : new Error('Could not unlock with passkey.');
    });
  };

  const unlockWithRecovery = (e: React.FormEvent) => {
    e.preventDefault();
    if (!details) return;
    const recovery = details.wrappers.find(w => w.kind === 'recovery');
    if (!recovery) return;
    void run(async () => {
      const context = ringContextFrom(details);
      const secret = parseRecoveryKey(recoveryInput);
      const material = await importKeyringSecret(secret).finally(() => secret.fill(0));
      const sealed = await fetchWrapper(recovery);
      const root = await unwrapRoot({ context, id: recovery.id, kind: 'recovery' }, material, sealed);
      setRecoveryInput('');
      await handleUnlockedRoot(details, root);
    });
  };

  const startTransfer = () => {
    if (!details) return;
    void run(async () => {
      const context = ringContextFrom(details);
      const next = await newTransfer(context);
      try {
        await writeRing(ringPaths.transfers, 'POST', { id: next.id, ...next.request });
      } catch (err) {
        next.secret.fill(0);
        throw err;
      }
      pendingTransfer?.secret.fill(0);
      setPendingTransfer(next);
    });
  };

  const finishTransfer = () => {
    if (!details || !pendingTransfer) return;
    const active = pendingTransfer;
    void run(async () => {
      const context = ringContextFrom(details);
      const response = await claimTransfer(active.id);
      const root = await openTransfer(context, active, response);
      active.secret.fill(0);
      setPendingTransfer(null);
      await handleUnlockedRoot(details, root);
    });
  };

  const cancelPendingTransfer = () => {
    if (!pendingTransfer) return;
    const active = pendingTransfer;
    void run(async () => {
      await writeRing(ringPaths.transfer(active.id), 'DELETE').catch(() => {});
      active.secret.fill(0);
      setPendingTransfer(null);
    });
  };

  const beginKeyringSetup = () => {
    setupRootRef.current?.fill(0);
    setupRecoveryRef.current?.fill(0);
    setupRootRef.current = newKeyringSecret();
    setupRecoveryRef.current = newKeyringSecret();
    setSetupCode(formatRecoveryKey(setupRecoveryRef.current));
    setSetupConfirm('');
    setError(null);
  };

  const completeKeyringSetup = (e: React.FormEvent) => {
    e.preventDefault();
    if (!details || !setupRootRef.current || !setupRecoveryRef.current || !setupCode) return;
    if (setupConfirm.trim().toUpperCase() !== setupCode) {
      setError('Re-enter the exact Emergency Kit key above to confirm you saved it.');
      return;
    }
    const root = setupRootRef.current;
    const recoveryBytes = setupRecoveryRef.current;
    void run(async () => {
      const version = crypto.randomUUID();
      const context = ringContextFrom(details, version);
      const createdDevice = await createKeyringDevice(context, root);
      const recoveryID = crypto.randomUUID();
      const recoveryMaterial = await importKeyringSecret(recoveryBytes);
      const recoverySealed = await wrapRoot({ context, id: recoveryID, kind: 'recovery' }, recoveryMaterial, root);
      try {
        const token = await stepUp.requestGrant('Initialize your suite keyring', `POST ${ringPaths.status}`);
        await writeRing(ringPaths.status, 'POST', {
          keyring_version: version,
          org_id: context.org_id,
          user_id: context.user_id,
          device: createdDevice.wrapper,
          recovery: { id: recoveryID, kind: 'recovery', sealed: recoverySealed },
        }, token);
      } catch (err) {
        await forgetKeyringDevice(createdDevice.device.id).catch(() => {});
        throw err;
      }
      setupRecoveryRef.current?.fill(0);
      setupRecoveryRef.current = undefined;
      setSetupCode(null);
      setSetupConfirm('');

      const updatedDetails: KeyringHandoffDetails = {
        ...details,
        keyring_version: version,
        wrappers: [
          { id: createdDevice.device.id, kind: 'device' },
          { id: recoveryID, kind: 'recovery' },
        ],
        app_key: null,
      };
      setupRootRef.current = undefined;
      rootRef.current = root;
      setDetails(updatedDetails);
      setStage('provision_app');
    });
  };

  const provisionAppKey = () => {
    if (!details || !rootRef.current) return;
    const root = rootRef.current;
    const context = ringContextFrom(details);
    const nextVersion = details.app_key ? details.app_key.key_version + 1 : 1;
    void run(async () => {
      const wrapped = await newWrappedAppKey(
        { context, client: details.client_id, version: nextVersion },
        root,
      );
      try {
        const token = await stepUp.requestGrant(
          `Create an encryption key for ${details.app_name}`,
          `PUT ${ringPaths.app(details.client_id)}`,
        );
        await saveAppKey(details.client_id, { key_version: nextVersion, sealed: wrapped.sealed }, token);
      } catch (err) {
        wrapped.subkey.fill(0);
        throw err;
      }
      await finishWithSubkey(details, context, nextVersion, wrapped.subkey);
    });
  };

  const continueWithoutKey = () => {
    void run(async () => {
      setStage('redirecting');
      const done = await completeHandoff(interaction);
      clearSecrets();
      window.location.replace(buildHandoffRedirectURL(done.redirect_uri, done.code, done.state));
    });
  };

  const handleCancel = () => {
    void run(async () => {
      if (pendingTransfer) {
        await writeRing(ringPaths.transfer(pendingTransfer.id), 'DELETE').catch(() => {});
      }
      const cancelled = await cancelHandoff(interaction);
      clearSecrets();
      window.location.replace(buildHandoffErrorURL(
        cancelled.redirect_uri,
        cancelled.state,
        'access_denied',
        'Keyring handoff was cancelled',
      ));
    });
  };

  const hasPRF = prfAvailable && (details?.wrappers.some(w => w.kind === 'prf') ?? false);
  const hasRecovery = details?.wrappers.some(w => w.kind === 'recovery') ?? false;

  return <AuthFrame>
    {stepUp.stepUpPrompt}
    <h2>{details ? `Continue to ${details.app_name}` : 'Suite keyring'}</h2>

    {error && <div className="alert-box error" role="alert"><p>{error}</p></div>}

    {stage === 'loading' && <p>Unlocking your encryption key…</p>}

    {stage === 'redirecting' && <p>Completing sign-in to <strong>{details?.app_name ?? 'the application'}</strong>…</p>}

    {stage === 'fatal' && (
      <div className="action-row">
        <a className="secondary-btn" href="/">Back to KyIdentity</a>
      </div>
    )}

    {stage === 'provision_app' && details && (
      <>
        <p>
          <strong>{details.app_name}</strong> needs a dedicated encryption key wrapped by your suite keyring.
          Your key is generated in this browser and never readable by the server.
        </p>
        <div className="action-row" style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <button type="button" className="primary-btn" disabled={busy} onClick={provisionAppKey}>
            {busy ? 'Creating key…' : `Enable encryption for ${details.app_name}`}
          </button>
          <button type="button" className="secondary-btn" disabled={busy} onClick={continueWithoutKey}>
            Continue without encryption key
          </button>
          <button type="button" className="secondary-btn" disabled={busy} onClick={handleCancel}>
            Cancel sign-in
          </button>
        </div>
      </>
    )}

    {stage === 'setup_keyring' && details && (
      <>
        {!setupCode ? (
          <>
            <p>
              <strong>{details.app_name}</strong> uses your zero-knowledge suite keyring so one Emergency Kit protects
              all of your encrypted apps.
            </p>
            <div className="action-row" style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <button type="button" className="primary-btn" disabled={busy} onClick={beginKeyringSetup}>
                Set up suite keyring
              </button>
              <button type="button" className="secondary-btn" disabled={busy} onClick={continueWithoutKey}>
                Continue without encryption key
              </button>
              <button type="button" className="secondary-btn" disabled={busy} onClick={handleCancel}>
                Cancel sign-in
              </button>
            </div>
          </>
        ) : (
          <form onSubmit={completeKeyringSetup}>
            <p>
              Save your <strong>Emergency Kit</strong> before continuing. KyIdentity never stores this key and cannot
              recover it if you lose access to all trusted browsers.
            </p>
            <div className="alert-box" style={{ wordBreak: 'break-all' }}>
              <code className="font-mono">{setupCode}</code>
            </div>
            <div className="action-row" style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
              <button type="button" className="secondary-btn" onClick={() => downloadKit(`KyIdentity Suite Emergency Kit\nAccount: ${user.username}\n\n${setupCode}\n`)}>
                Download kit
              </button>
              <button type="button" className="secondary-btn" onClick={() => window.print()}>
                Print
              </button>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="handoff-kit-confirm">Confirm Emergency Kit</label>
              <input
                id="handoff-kit-confirm"
                className="form-input font-mono"
                autoComplete="off"
                spellCheck={false}
                required
                placeholder="KYR1-..."
                value={setupConfirm}
                disabled={busy}
                onChange={e => setSetupConfirm(e.target.value)}
              />
            </div>
            <div className="action-row" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <button type="submit" className="primary-btn" disabled={busy || !setupConfirm.trim()}>
                {busy ? 'Setting up…' : 'Save keyring & continue'}
              </button>
              <button type="button" className="secondary-btn" disabled={busy} onClick={continueWithoutKey}>
                Continue without encryption key
              </button>
            </div>
          </form>
        )}
      </>
    )}

    {stage === 'unlock' && details && (
      <>
        <p>
          Unlock your suite keyring to sign in to <strong>{details.app_name}</strong> as <strong>{user.username}</strong>.
        </p>

        <label className="form-checkbox" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: '0.75rem 0' }}>
          <input type="checkbox" checked={trustBrowser} disabled={busy} onChange={e => setTrustBrowser(e.target.checked)} />
          <span>Trust this browser for future sign-ins</span>
        </label>

        {hasPRF && (
          <div style={{ marginBottom: '1rem' }}>
            <button type="button" className="primary-btn" style={{ width: '100%' }} disabled={busy} onClick={unlockWithPRF}>
              Unlock with passkey
            </button>
          </div>
        )}

        <div style={{ marginBottom: '1rem' }}>
          {!pendingTransfer ? (
            <button type="button" className="secondary-btn" style={{ width: '100%' }} disabled={busy} onClick={startTransfer}>
              Approve from another trusted browser
            </button>
          ) : (
            <div className="alert-box">
              <p>On a trusted browser, open <strong>Settings → Keyring</strong> and approve this code:</p>
              <p style={{ wordBreak: 'break-all' }}><code className="font-mono">{transferCode(pendingTransfer)}</code></p>
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="primary-btn" disabled={busy} onClick={finishTransfer}>
                  Finish unlocking
                </button>
                <button type="button" className="secondary-btn" disabled={busy} onClick={cancelPendingTransfer}>
                  Cancel request
                </button>
              </div>
            </div>
          )}
        </div>

        {hasRecovery && (
          <form onSubmit={unlockWithRecovery} style={{ marginBottom: '1rem' }}>
            <div className="form-group">
              <label className="form-label" htmlFor="handoff-recovery">Or enter your Emergency Kit</label>
              <input
                id="handoff-recovery"
                className="form-input font-mono"
                autoComplete="off"
                spellCheck={false}
                placeholder="KYR1-..."
                value={recoveryInput}
                disabled={busy}
                onChange={e => setRecoveryInput(e.target.value)}
              />
            </div>
            <button type="submit" className={hasPRF ? 'secondary-btn' : 'primary-btn'} style={{ width: '100%' }} disabled={busy || !recoveryInput.trim()}>
              Unlock with Emergency Kit
            </button>
          </form>
        )}

        <div className="action-row" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.75rem' }}>
          <button type="button" className="secondary-btn" disabled={busy} onClick={continueWithoutKey}>
            Continue without encryption key
          </button>
          <button type="button" className="secondary-btn" disabled={busy} onClick={handleCancel}>
            Cancel sign-in
          </button>
        </div>
      </>
    )}
  </AuthFrame>;
}
