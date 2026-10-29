/**
 * sameOriginPath narrows an untrusted `return_to` value to a path on this origin, or null.
 *
 * The value arrives in the query string, so anyone can choose it. Assigning it to
 * `window.location` unchecked is an open redirect that fires immediately after the user
 * types their password on the real sign-on domain, which is exactly the ending a phishing
 * flow wants. `form-action 'self'` in the CSP does not constrain `window.location`.
 *
 * Only a single-slash-prefixed path is accepted. `//evil.tld` and `https://evil.tld` are
 * protocol-relative and absolute URLs respectively, and both leave this origin.
 */
export function sameOriginPath(raw: string | null): string | null {
  if (!raw) return null;

  let value: string;
  try {
    // The server percent-encodes the path once. A value that is still encoded after one
    // pass is a caller trying to smuggle something past this check, so decode at most once
    // and validate the result.
    value = decodeURIComponent(raw);
  } catch {
    return null; // malformed percent-encoding
  }

  if (!value.startsWith('/') || value.startsWith('//')) return null;
  if (value.includes('\\')) return null; // some browsers treat \\ as //

  // Reject control characters and whitespace: browsers strip or normalise them in ways
  // that can change which origin the value ends up pointing at.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0020\u007f]/.test(value)) return null;

  return value;
}
