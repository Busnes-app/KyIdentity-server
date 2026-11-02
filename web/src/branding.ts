import { useEffect, useState } from 'react';
import { isRecord } from './api';

/** The organisation's name and logo (issue #145): display only, set under Administration › Branding. */
export interface Branding {
  name: string;
  logoUrl: string;
}

export const NO_BRANDING: Branding = { name: '', logoUrl: '' };

// The only image the server serves for branding. Anything else in the field is refused, so
// the response can never point an <img> somewhere else.
const LOGO_URL = /^\/api\/branding\/logo\?v=[0-9a-f]{16}$/;

export function parseBranding(value: unknown): Branding {
  if (!isRecord(value) || typeof value.name !== 'string' || typeof value.logoUrl !== 'string') throw new Error('Branding response is malformed');
  return { name: value.name, logoUrl: LOGO_URL.test(value.logoUrl) ? value.logoUrl : '' };
}

let current: Branding = NO_BRANDING;
let loading: Promise<void> | null = null;
const listeners = new Set<(b: Branding) => void>();

/** Replaces the shown branding, as after an administrator saves it. */
export function setBranding(b: Branding) {
  current = b;
  listeners.forEach(fn => fn(b));
}

function load() {
  loading ??= fetch('/api/branding')
    .then(res => (res.ok ? res.json() : Promise.reject(new Error(String(res.status)))))
    .then(body => setBranding(parseBranding(body)))
    // Branding is decoration: on any failure the KyIdentity defaults stay.
    .catch(() => undefined);
  return loading;
}

/** The current branding; KyIdentity's own until the server answers. */
export function useBranding(): Branding {
  const [b, setB] = useState(current);
  useEffect(() => {
    listeners.add(setB);
    void load();
    setB(current);
    return () => { listeners.delete(setB); };
  }, []);
  return b;
}
