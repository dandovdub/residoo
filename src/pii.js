"use strict";

const crypto = require("crypto");
const { BIP39_ENGLISH_WORDLIST } = require("./bip39wordlist");

/**
 * Opt-in PII-and-adjacent detection (--include-pii). Named directly by this
 * session's own competitive research into funded AI-DLP vendors (Strac,
 * Cyberhaven, Nightfall) as one of the few concrete, buildable things
 * residoo could adopt without becoming a hosted service -- and
 * independently corroborated by two direct competitors' own shipped
 * detector lists (DidILeak, Medusa), both of which cover PII alongside
 * credentials.
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
 * "PII" is the name of the flag, not a perfectly accurate label for
 * everything in it: a BIP-39 crypto wallet seed phrase (added after a
 * competitive-feature-parity pass found AgentSweep ships seed-phrase
 * detection and residoo didn't) is a CREDENTIAL, not personal data --
 * arguably it belongs in the default, always-on set the way a vendor API
 * key does. It lives here instead for the same architectural reason as
 * the other three: no single-vendor prefix to anchor on (a seed phrase is
 * 12-24 plain English words, structurally unlike every PATTERNS.js rule),
 * and a real, own risk-category case for asking first, the same
 * "different shape, not a lower bar" framing already applied to SSN/card/
 * IBAN. Kept in the same flag rather than a new one to avoid flag
 * proliferation for what is, mechanically, the same "opt in, then
 * checksum-validate before ever reporting" pattern.
 *
 * Four detectors, deliberately not more: DidILeak's own shipped list also
 * includes bare email addresses and phone numbers, but both are far too
 * common in ordinary, non-sensitive text (a support email in a comment, a
 * phone number in an error message) to meet this project's own
 * "high-confidence only, a security tool that cries wolf gets
 * uninstalled" bar, opt-in or not -- DidILeak itself rates them "low"/
 * "info" severity for the same reason. Every detector here instead has a
 * REAL mathematical validator, not just a shape match, which is what
 * keeps false-positive risk low enough to ship even as an additive
 * category: Luhn for card numbers, ISO 7064 MOD 97-10 for IBAN, the BIP-39
 * spec's own SHA-256 checksum for seed phrases, and the Social Security
 * Administration's own published invalid-range rules for SSNs (no
 * checksum exists for SSNs, hence "medium" confidence there, not "high"
 * -- disclosed, not smoothed over).
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

const BIP39_INDEX = new Map(BIP39_ENGLISH_WORDLIST.map((w, i) => [w, i]));
const BIP39_VALID_LENGTHS = new Set([12, 15, 18, 21, 24]);

/**
 * BIP-39 mnemonic checksum (github.com/bitcoin/bips/blob/master/bip-0039.mediawiki,
 * fetched directly, cross-checked against the spec's own canonical all-zero
 * test vector -- "abandon" x11 + "about" -- rather than trusted from memory):
 * a mnemonic of MS words (12/15/18/21/24) encodes ENT bits of entropy plus a
 * CS = ENT/32-bit checksum, each word an 11-bit index into the wordlist. The
 * checksum is the first CS bits of SHA-256(entropy); this recomputes it and
 * compares. English wordlist only -- BIP-39 also defines Japanese, Korean,
 * Spanish, Chinese, French, Italian, Czech, and Portuguese wordlists this
 * does not check, a disclosed scope limit rather than a silent one, the same
 * shape as ibanValid's own per-country-length gap above.
 *
 * BigInt throughout: a 24-word phrase packs 264 bits, far past a safe JS
 * integer, and a mis-sized intermediate here would silently corrupt every
 * checksum it touches rather than throw.
 */
function bip39ChecksumValid(words) {
  if (!Array.isArray(words) || !BIP39_VALID_LENGTHS.has(words.length)) return false;
  const indices = [];
  for (const w of words) {
    const idx = BIP39_INDEX.get(w);
    if (idx === undefined) return false;
    indices.push(idx);
  }
  const csBits = words.length / 3; // MS/3, derived from CS=ENT/32 and MS=(ENT+CS)/11
  const entBits = words.length * 11 - csBits;

  let combined = 0n;
  for (const idx of indices) combined = (combined << 11n) | BigInt(idx);

  const checksumMask = (1n << BigInt(csBits)) - 1n;
  const checksumBits = combined & checksumMask;
  const entropyBits = combined >> BigInt(csBits);

  const entHex = entropyBits.toString(16).padStart(entBits / 8 * 2, "0");
  const hash = crypto.createHash("sha256").update(Buffer.from(entHex, "hex")).digest();
  const hashBits = BigInt("0x" + hash.toString("hex"));
  const expectedChecksum = (hashBits >> BigInt(256 - csBits)) & checksumMask;

  return checksumBits === expectedChecksum;
}

/**
 * A real seed phrase is rarely the WHOLE candidate span: "here's my wallet
 * seed: <12 words> keep it safe" is a plausible, ordinary way to paste one,
 * and the candidate regex below (deliberately wide, to not miss a phrase
 * that isn't sentence-initial) captures the surrounding words too. Slides
 * every valid length (24 down to 12, longest first so a real 15+-word
 * phrase is reported whole rather than as a coincidentally-checksum-valid
 * 12-word prefix of it) across every starting offset in the captured run,
 * returning the first exact substring whose checksum validates, or null.
 * O(words x 5) checksum computations worst case -- cheap, since the regex
 * itself already bounds "words" to at most 100.
 */
function findBip39Phrase(candidateRun) {
  const words = candidateRun.split(" ");
  for (let start = 0; start < words.length; start++) {
    for (const len of [24, 21, 18, 15, 12]) {
      if (start + len > words.length) continue;
      const slice = words.slice(start, start + len);
      if (bip39ChecksumValid(slice)) return slice.join(" ");
    }
  }
  return null;
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
  // Candidate: a run of 12-100 lowercase words, single-space-separated (how
  // a seed phrase actually appears -- pasted as plain text, no punctuation
  // breaking it up). Deliberately wider than the 12-24 a phrase itself can
  // be: a real phrase is rarely the WHOLE sentence ("here's my seed: <12
  // words> keep it safe"), so the candidate must be free to capture
  // leading/trailing prose too -- findBip39Phrase (below) narrows it back
  // down. validate() returns the narrowed substring, not a boolean: common
  // English function words like "the"/"and"/"of"/"is" are NOT in the
  // 2048-word list (confirmed by direct check against the fetched
  // wordlist), so ordinary prose almost never survives even the membership
  // test, let alone the checksum, but the narrowing still matters whenever
  // it does.
  { id: "crypto_seed_phrase", label: "Crypto wallet seed phrase (BIP-39, checksum-validated)", confidence: "high",
    re: /\b[a-z]+(?: [a-z]+){11,99}\b/g,
    validate: (m) => findBip39Phrase(m) },
];

module.exports = { PII_PATTERNS, luhnValid, ibanValid, bip39ChecksumValid, findBip39Phrase };
