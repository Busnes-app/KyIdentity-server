/**
 * Expiry instants. The operator types a wall-clock time in their own zone; the server
 * stores and enforces one UTC instant. Both are always shown together so a DST edge or
 * a mistaken zone is visible before it bites.
 */
export const localZone = (): string => Intl.DateTimeFormat().resolvedOptions().timeZone;

/** A datetime-local value in the operator's zone, as the UTC instant the server takes. */
export function instantFromLocal(local: string): string | undefined {
  if (!local) return undefined;
  const at = new Date(local);
  return Number.isNaN(at.getTime()) ? undefined : at.toISOString();
}

/** The datetime-local value that shows a stored instant in the operator's zone. */
export function localInputValue(iso?: string): string {
  if (!iso) return '';
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}T${pad(at.getHours())}:${pad(at.getMinutes())}`;
}

/** Local wall-clock time with its zone, then the exact instant. */
export function describeInstant(iso: string): string {
  const at = new Date(iso);
  return `${at.toLocaleString()} ${localZone()} (${at.toISOString()})`;
}
