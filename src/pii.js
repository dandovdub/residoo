"use strict";

/**
 * Opt-in PII detection (--include-pii). Named directly by this session's
 * own competitive research into funded AI-DLP vendors (Strac, Cyberhaven,
 * Nightfall) as one of the few concrete, buildable things residoo could
 * adopt without becoming a hosted service -- and independently
 * corroborated by two direct competitors' own shipped detector lists
 * (DidILeak, Medusa), both of which cover PII alongside credentials.
 *
 * Kept entirely separate from PATTERNS/NOISY_PATTERNS in patterns.js on
 * purpose: residoo's stated identity elsewhere in this project is
 * "deliberately credentials-only" (see docs/comparison.md's DidILeak
 * section), and this module doesn't change that default -- it's a
 * separate, explicitly opt-in category a user has to ask for, the same
 * relationship NOISY_PATTERNS already has to the default rule set, just
 * for a different reason (a different RISK CATEGORY, not a lower
 * confidence bar).
 *
 * Only three detectors, deliberately: DidILeak's own shipped list also
 * includes bare email addresses and phone numbers, but both are far too
 * common in ordinary, non-sensitive text (a support email in a comment, a
 * phone number in an error message) to meet this project's own
 * "high-confidence only, a security tool that cries wolf gets
 * uninstalled" bar, opt-in or not -- DidILeak itself rates them "low"/
 * "info" severity for the same reason. The three included here all have a
 * REAL mathematical validator, not just a shape match, which is what
 * keeps false-positive risk low enough to ship even as an additive
 * category: Luhn for card numbers, ISO 7064 MOD 97-10 for IBAN, and the
 * Social Security Administration's own published invalid-range rules for
 * SSNs (no checksum exists for SSNs, hence "medium" confidence there, not
 * "high" -- disclosed, not smoothed over).
 */

/** Luhn checksum (ISO/IEC 7812-1): the standard validator for payment card numbers. `digits` must already be digits-only. */
function luhnValid(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/**
 * ISO 7064 MOD 97-10 (the IBAN checksum): move the first 4 characters to
 * the end, map letters to numbers (A=10..Z=35), and the whole numeral must
 * be congruent to 1 mod 97. Computed digit-by-digit since the numeral is
 * far larger than any JS integer.
 *
 * Scope, disclosed rather than assumed complete: this checks the generic
 * ISO 13616 structural rule and the checksum, not each of the ~70
 * IBAN-issuing countries' own exact fixed length (a German IBAN is always
 * 22 characters, a French one always 27) -- a real per-country length
 * table would need to be built and kept current; the checksum alone
 * already rejects the overwhelming majority of non-IBAN digit/letter runs.
 */
function ibanValid(iban) {
  if (iban.length < 15 || iban.length > 34) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let mod = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const value = code >= 65 && code <= 90 ? code - 55 : code - 48; // A-Z -> 10-35, else digit
    if (value < 0 || value > 35) return false;
    const digits = value >= 10 ? String(value) : ch;
    for (const d of digits) mod = (mod * 10 + (d.charCodeAt(0) - 48)) % 97;
  }
  return mod === 1;
}

const PII_PATTERNS = [
  // Dashed format only -- a bare 9-digit run is indistinguishable from
  // countless other numbers in a coding-agent transcript (ports, PIDs,
  // timestamps) and would make this rule pure noise. Invalid-range
  // exclusions are the Social Security Administration's own published
  // rules: area 000, 666, and 900-999 were never issued; group 00 and
  // serial 0000 are never valid within an otherwise-real-shaped number.
  { id: "us_ssn", label: "US Social Security Number", confidence: "medium",
    re: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  // Candidate digit runs (13-19 digits, ISO/IEC 7812's own real-world
  // range, optionally space- or dash-separated the way a human actually
  // types a card number) are Luhn-validated below before ever being
  // reported -- the regex alone is not the detector.
  { id: "credit_card_number", label: "Credit card number (Luhn-validated)", confidence: "high",
    re: /\b\d(?:[ -]?\d){12,18}\b/g,
    validate: (m) => { const d = m.replace(/[ -]/g, ""); return d.length >= 13 && d.length <= 19 && luhnValid(d); } },
  { id: "iban", label: "IBAN (checksum-validated)", confidence: "high",
    re: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g,
    validate: (m) => ibanValid(m) },
];

module.exports = { PII_PATTERNS, luhnValid, ibanValid };
