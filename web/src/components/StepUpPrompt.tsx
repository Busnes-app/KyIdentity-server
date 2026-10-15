import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Modal } from './Modal';
import { Lock } from 'lucide-react';
import { apiJson, errorMessage } from '../api';
import { cancelStepUp, methodLabels, parseStepUpMethods, verifyStepUp, type StepUpMethod } from '../stepUp';

interface Pending {
  reason: string;
  operation: string;
  // Captured before the caller's own busy state can disable it.
  returnFocus: Element | null;
  resolve: (grant: string) => void;
  reject: (reason: Error) => void;
}

/** One session- and operation-bound grant per protected action. */
export function useStepUp() {
  const [prompt, setPrompt] = useState<Pending | null>(null);
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [methods, setMethods] = useState<StepUpMethod[] | null>(null);
  const [method, setMethod] = useState<StepUpMethod | ''>('');
  const [digits, setDigits] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const pending = useRef<Pending | null>(null);
  const attempt = useRef<AbortController | null>(null);

  const dismiss = useCallback(() => {
    attempt.current?.abort();
    attempt.current = null;
    pending.current?.reject(new Error('cancelled'));
    pending.current = null;
  }, []);
  const cancel = useCallback(() => {
    dismiss();
    setPrompt(null);
    setPassword('');
    setCode('');
  }, [dismiss]);
  useEffect(() => dismiss, [dismiss]);

  const requestGrant = useCallback((reason: string, operation: string): Promise<string> => {
    const returnFocus = pending.current?.returnFocus ?? document.activeElement;
    dismiss();
    setPassword('');
    setCode('');
    setDigits('');
    setError(null);
    setBusy(false);
    setMethods(null);
    setMethod('');
    return new Promise<string>((resolve, reject) => {
      const next = { reason, operation, returnFocus, resolve, reject };
      pending.current = next;
      setPrompt(next);
      void apiJson('/api/auth/step-up/methods?operation=' + encodeURIComponent(operation), parseStepUpMethods)
        .then(available => {
          if (pending.current !== next) return;
          setMethods(available);
          setMethod(available[0] ?? '');
        })
        .catch(err => {
          if (pending.current === next) setError(errorMessage(err, 'Could not load verification methods'));
        });
    });
  }, [dismiss]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const current = pending.current;
    if (!current || !password || methods === null || attempt.current) return;
    const controller = new AbortController();
    attempt.current = controller;
    setBusy(true);
    setError(null);
    setDigits('');
    try {
      const grant = await verifyStepUp({ password, code, method, operation: current.operation }, controller.signal,
        value => { if (pending.current === current) setDigits(value); });
      if (pending.current !== current || controller.signal.aborted) {
        await cancelStepUp(grant).catch(() => {});
        return;
      }
      pending.current = null;
      current.resolve(grant);
      setPrompt(null);
      setPassword('');
      setCode('');
    } catch (err) {
      if (pending.current === current) {
        setError(errorMessage(err, 'Re-authentication failed'));
        setDigits('');
      }
    } finally {
      if (attempt.current === controller) {
        attempt.current = null;
        setBusy(false);
      }
    }
  };

  const stepUpPrompt = prompt ? (
    <Modal title="Confirm It's You" onClose={cancel} className="step-up-card" returnFocus={prompt.returnFocus}>
      <form onSubmit={submit}>
        <div className="modal-body">
          <p className="modal-desc">{prompt.reason}</p>
          <div className="form-group">
            <label className="form-label" htmlFor="admin-stepup-password">Password</label>
            <input id="admin-stepup-password" type="password" className="form-input"
              autoComplete="current-password" autoFocus value={password} required disabled={busy}
              onChange={e => setPassword(e.target.value)} />
          </div>
          {methods === null && !error && <p role="status">Loading verification methods...</p>}
          {methods && methods.length > 0 && (
            <div className="form-group">
              <label className="form-label" htmlFor="step-up-method">Verify with</label>
              <select id="step-up-method" className="form-input" value={method} disabled={busy}
                onChange={e => {
                  const selected = methods.find(value => value === e.target.value);
                  if (selected) { setMethod(selected); setCode(''); }
                }}>
                {methods.map(value => <option key={value} value={value}>{methodLabels[value]}</option>)}
              </select>
            </div>
          )}
          {(method === 'totp' || method === 'recovery') && (
            <div className="form-group">
              <label className="form-label" htmlFor="admin-stepup-code">{methodLabels[method]}</label>
              <input id="admin-stepup-code" className="form-input" type="text"
                autoComplete="one-time-code" value={code} required disabled={busy}
                onChange={e => setCode(e.target.value)} />
            </div>
          )}
          {digits && <p role="status">Approve the request on your phone and select <strong>{digits}</strong>.</p>}
          {error && <div className="alert-box error" role="alert">{error}</div>}
        </div>
        <div className="modal-footer">
          <button type="button" className="secondary-btn" onClick={cancel}>Cancel</button>
          <button type="submit" className="primary-btn" disabled={busy || !password || methods === null}>
            <Lock size={16} /><span>{busy ? 'Verifying...' : 'Continue'}</span>
          </button>
        </div>
      </form>
    </Modal>
  ) : null;

  return { requestGrant, stepUpPrompt };
}

export function isCancelled(err: unknown): boolean {
  return err instanceof Error && err.message === 'cancelled';
}
