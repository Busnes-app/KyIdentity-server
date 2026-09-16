let csrfTokenCache: string | null = null;

/** A JSON value, which is all a response body is known to be before it is checked. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Narrows a caught value. `catch` binds `unknown`, and not everything thrown is an Error. */
export function errorMessage(err: unknown, fallback = 'Something went wrong'): string {
  if (err instanceof Error && err.message) return err.message;
  if (typeof err === 'string' && err) return err;
  return fallback;
}

function stringField(source: Record<string, unknown>, key: string): string | undefined {
  const value = source[key];
  return typeof value === 'string' && value ? value : undefined;
}

export async function fetchCSRF(forceRefresh = false): Promise<string> {
  if (forceRefresh) csrfTokenCache = null;
  if (csrfTokenCache) return csrfTokenCache;
  const res = await fetch('/api/auth/csrf');
  if (!res.ok) throw new Error('Failed to obtain CSRF token');
  const body: unknown = await res.json();
  const token = isRecord(body) ? stringField(body, 'csrfToken') : undefined;
  if (!token) throw new Error('CSRF endpoint returned no token');
  csrfTokenCache = token;
  return token;
}

export interface ApiOptions extends RequestInit {
  /** Step-up grant authorizing an account-security change. */
  stepUpToken?: string;
}

/**
 * Performs a request and returns the parsed body as `unknown`.
 *
 * The body is whatever the server sent; declaring it to be a caller-chosen `T` is a claim
 * about the wire that nothing has checked. Callers pass the result through a parser
 * (`parseJson` or their own) so a changed or errored response fails at the boundary instead
 * of surfacing as an undefined field somewhere in a login or admin screen.
 */
export async function apiRequest(path: string, options: ApiOptions = {}): Promise<unknown> {
  const { stepUpToken, ...init } = options;
  const method = init.method || 'GET';
  const isMutating = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';

  const send = async (refreshCSRF = false) => {
    const headers = new Headers(init.headers || {});
    if (!headers.has('Content-Type') && init.body && typeof init.body === 'string') {
      headers.set('Content-Type', 'application/json');
    }
    if (isMutating) {
      headers.set('X-CSRF-Token', await fetchCSRF(refreshCSRF));
    }
    if (stepUpToken) {
      headers.set('X-KyIdentity-StepUp', stepUpToken);
    }
    return fetch(path, { ...init, headers, credentials: 'same-origin' });
  };

  let res = await send(false);

  let data = parseBody(await res.text());

  if (isMutating && res.status === 403 && isRecord(data) && data.error === 'invalid_csrf') {
    res = await send(true);
    data = parseBody(await res.text());
  }

  if (res.status === 401 && !path.startsWith('/api/auth/login') &&
      !(path.startsWith('/api/auth/step-up') && isRecord(data) && data.error === 'invalid_credentials')) {
    window.dispatchEvent(new CustomEvent('kyidentity:unauthorized'));
  }

  if (res.status === 403 && isRecord(data) && data.error === 'enrollment_required') { window.dispatchEvent(new CustomEvent('kyidentity:enrollment-required')); }
  if (!res.ok) {
    throw new ApiError(res.status, data);
  }

  return data;
}

function parseBody(text: string): unknown {
  if (!text) return {};
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { raw: text };
  }
}

/** An error carrying the server's status and machine-readable code. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string | undefined;

  constructor(status: number, body: unknown) {
    const record = isRecord(body) ? body : {};
    super(
      stringField(record, 'error_description') ??
        stringField(record, 'error') ??
        `HTTP ${status}`
    );
    this.name = 'ApiError';
    this.status = status;
    this.code = stringField(record, 'error');
  }
}

/** True when the server is asking for a fresh re-authentication before this change. */
export function isStepUpRequired(err: unknown): boolean {
  return err instanceof ApiError && err.code === 'step_up_required';
}

/**
 * Applies a parser to a response, turning a shape mismatch into a clear failure at the call
 * site rather than an undefined field three components away.
 */
export async function apiJson<T>(
  path: string,
  parse: (value: unknown) => T,
  options: ApiOptions = {}
): Promise<T> {
  const body = await apiRequest(path, options);
  try {
    return parse(body);
  } catch (err) {
    throw new Error(`${path}: ${errorMessage(err, 'unexpected response shape')}`);
  }
}
