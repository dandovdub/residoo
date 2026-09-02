"use strict";

/**
 * "Rare, not random" — a lightweight, offline approximation of betterleaks'
 * BPE-tokenization rarity filter (see their "Rare Not Random" writeup),
 * applied only to NOISY_PATTERNS matches: a bare `password = "..."` or
 * `api_key = "..."` assignment is the hardest class of finding precisely
 * because most matches are placeholders, variable names, or ordinary
 * English ("password = correcthorsebattery", "secret = temporary_value"),
 * not real secrets.
 *
 * A real BPE tokenizer needs an embedded merge-rules vocabulary (GPT-2's is
 * roughly 50,000 entries) — far too heavy for a zero-dependency, small CLI.
 * This approximates the same signal ("does this look like language, or like
 * noise") with a small, hand-picked table of common English letter bigrams
 * (standard digraph-frequency tables — "th", "he", "in", "er"... together
 * cover a large majority of ordinary English text) instead of a learned
 * vocabulary: real secret material is high-entropy machine output and
 * essentially never strings together English digraphs at the rate real
 * words and sentences do, while a placeholder, a variable name, or a
 * pasted sentence almost always does.
 *
 * This is deliberately not a security boundary. It only ever adjusts
 * confidence on the already-opt-in, already low-confidence NOISY_PATTERNS
 * rules (see patterns.js's own header on why those are opt-in) and is never
 * applied to, and never changes the outcome of, any of the default 38
 * high/medium-confidence rules.
 */

// The most frequent English letter bigrams (standard digraph-frequency
// tables, e.g. Konheim's letter-pair frequency study). Not exhaustive by
// design: the point is common, unmistakably-linguistic pairs, not full
// coverage of every English bigram.
const COMMON_BIGRAMS = new Set([
  "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
  "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
  "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
  "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
  "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur",
]);

/**
 * Fraction of the value's consecutive lowercase-letter bigrams that are one
 * of the common English digraphs above. A non-letter character (digit,
 * punctuation, symbol) breaks a bigram pair rather than being skipped over:
 * a real secret's occasional letter run should not accidentally read as
 * language just because two of its letters happen to land next to each
 * other and spell a common pair across what was actually a digit boundary.
 */
function commonBigramFraction(value) {
  const lower = value.toLowerCase();
  let total = 0;
  let common = 0;
  for (let i = 0; i < lower.length - 1; i++) {
    const a = lower[i], b = lower[i + 1];
    if (a >= "a" && a <= "z" && b >= "a" && b <= "z") {
      total++;
      if (COMMON_BIGRAMS.has(a + b)) common++;
    }
  }
  return total === 0 ? 0 : common / total;
}

// Above this fraction, a value reads as language (or a language-shaped
// placeholder) rather than machine-random output. Calibrated against common
// English words and phrases scoring well above it, and random/base64/hex
// strings scoring at or near zero (see tests/smoke.js).
const LANGUAGE_THRESHOLD = 0.20;

/** True when `value` reads as machine-random rather than as language. */
function looksRandom(value) {
  return commonBigramFraction(value) < LANGUAGE_THRESHOLD;
}

module.exports = { looksRandom, commonBigramFraction };
