"use strict";

/**
 * Local, offline JWT expiry decoding.
 *
 * Unlike an AWS or vendor API key, a JWT's own payload can carry an `exp`
 * claim, and that claim is inside the signed part of the token: it cannot
 * be altered without invalidating the signature, so decoding it locally is
 * a trustworthy answer to "is this still valid," not a guess, PROVIDED the
 * token is actually validated (signature + expiry) by whatever service
 * accepts it. residoo does not check the signature (it does not know the
 * issuer's key, and would need a network call to ask), so this only ever
 * reports the claimed expiry, never that a token is genuinely live.
 *
 * No network call, no dependency, no vendor to ask: this is the free,
 * zero-risk half of "is this credential still valid" (see verify.js for
 * the opt-in, network-calling AWS half of that same question).
 */

function base64UrlDecode(segment) {
  const padded = segment.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(padded, "base64").toString("utf-8");
}

/**
 * Returns the token's `exp` claim as milliseconds since epoch, or null when
 * the token is not decodable as a JWT or carries no `exp` claim. Only the
 * `exp` field is ever read out of the payload; every other claim (sub,
 * email, scopes, whatever an issuer put in there) is decoded transiently
 * and discarded, never stored or reported, so a JWT's expiry can be shown
 * without also handling the rest of its payload as sensitive data.
 */
function decodeJwtExpiryMs(token) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  let payload;
  try {
    payload = JSON.parse(base64UrlDecode(parts[1]));
  } catch {
    return null;
  }
  const exp = payload && payload.exp;
  if (typeof exp !== "number" || !Number.isFinite(exp)) return null;
  return exp * 1000;
}

module.exports = { decodeJwtExpiryMs };
