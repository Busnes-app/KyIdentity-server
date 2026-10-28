/**
 * Base64url encoding helpers shared by the FCM and APNs Workers — both sign
 * JWTs (a Google service-account assertion / an APNs provider token) and need
 * the same unpadded base64url encoding for the JWT header/claims/signature.
 */

export function base64UrlEncode(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const binary = String.fromCharCode(...arr);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlEncodeString(input: string): string {
  return base64UrlEncode(new TextEncoder().encode(input));
}

/**
 * Decode a PEM-encoded PKCS8 private key (RSA or EC) to its raw DER bytes,
 * ready for crypto.subtle.importKey("pkcs8", ...). Shared by the FCM (RSA)
 * and APNs (ECDSA) Workers, which only differ in the importKey algorithm
 * param, not in how the PEM is unwrapped.
 */
export function pemToDer(pem: string): Uint8Array {
  const normalized = pem.replace(/\\n/g, "\n").trim();
  const body = normalized
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
}
