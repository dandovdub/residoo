"use strict";

/**
 * Feature 3: paired-secret detection.
 *
 * An AWS secret access key is a 40-character base64 value with no
 * vendor-recognizable prefix. Reported alone, it is indistinguishable from
 * a hash, a session id, or any other base64-shaped string, so it is not one
 * of patterns.js's own PATTERNS: a bare rule for it would be exactly the
 * noisy, low-confidence shape that file's own header keeps out of the
 * default set.
 *
 * But an AWS secret key is never leaked alone: every real credential pair
 * ships an access key id alongside it (the id names WHICH key; the secret
 * authenticates it, and one is useless to an attacker without the other),
 * so every AWS SDK config, env file, or credentials file that leaks the
 * secret leaks the id in the same breath. Instead of a standalone rule,
 * this looks for a 40-char base64 run within a tight window of an
 * already-confirmed AKIA/ASIA match: the PAIRING is the vendor-specific
 * signal, not the shape alone. Same idea as betterleaks' `components`
 * mechanism (pairing a low-signal shape to a nearby high-confidence rule to
 * raise combined confidence), built offline and dependency-free like every
 * other mechanism here: no rule is added to the default set, and a bare
 * 40-char base64 string anywhere else on a line, with no access key nearby,
 * is still silently ignored exactly as before this feature existed.
 *
 * findNearbyCandidate below is the same mechanism generalized: PlanetScale
 * (see scan.js) needs an identical pairing step, just with the anchor and
 * candidate roles swapped (the SECRET is the prefixed, independently
 * detected value; the unprefixed id is what gets found nearby).
 */

const WINDOW = 400; // chars searched on each side of the access-key match

// AWS secret keys are exactly 40 base64-alphabet characters (40 is a
// multiple of 4, so real keys carry no "=" padding). \b on both sides so a
// candidate embedded in a longer alnum run (a hash, a dash-free UUID) is
// not mistaken for one — the same boundary discipline every rule in
// patterns.js already applies to its own matches.
const CANDIDATE_RE = /\b[A-Za-z0-9/+]{40}\b/g;

/**
 * A run of 12+ identical characters at either end. This is the same
 * placeholder tell as scan.js's zeroEntropyTail, reimplemented locally (not
 * imported) because it must check BOTH ends here: a candidate window can
 * hold a placeholder abutting real text on either side, where scan.js's own
 * rules only ever see a value anchored at a rule's own prefix, so only the
 * tail end needs checking there.
 */
function looksZeroEntropy(value) {
  const isRun = (s) => {
    for (let i = 1; i < s.length; i++) if (s[i] !== s[0]) return false;
    return true;
  };
  return isRun(value.slice(0, 12)) || isRun(value.slice(-12));
}

/**
 * Find a candidate value paired with an already-matched anchor value on
 * this line, within `window` characters on either side. `anchorValue` and
 * `anchorIndex` locate the anchor so the search can exclude the anchor's
 * own text from matching itself.
 *
 * Returns the candidate string, or null when there is none, or when more
 * than one distinct candidate sits in the window. Ambiguous pairing is
 * reported as nothing at all: for a finding whose whole point is "this is
 * high confidence because of what it's next to," guessing wrong is worse
 * than staying silent.
 *
 * Generic over which value is the anchor and which is the candidate: AWS
 * anchors on the prefixed access key id and searches for the unprefixed
 * secret; PlanetScale (see scan.js) anchors on the prefixed secret and
 * searches for the unprefixed id — same mechanism, opposite roles, so one
 * function serves both rather than two near-identical copies.
 */
function findNearbyCandidate(line, anchorValue, anchorIndex, candidateRe, window) {
  const start = Math.max(0, anchorIndex - window);
  const end = Math.min(line.length, anchorIndex + anchorValue.length + window);
  const around = line.slice(start, end);
  candidateRe.lastIndex = 0;
  let m;
  let found = null;
  while ((m = candidateRe.exec(around)) !== null) {
    const value = m[0];
    if (value !== anchorValue && !looksZeroEntropy(value)) {
      if (found !== null && found !== value) return null;
      found = value;
    }
    if (m.index === candidateRe.lastIndex) candidateRe.lastIndex++;
  }
  return found;
}

/**
 * Find an AWS secret access key candidate paired with an already-matched
 * access key id or session token on this line. See findNearbyCandidate for
 * the shared mechanism this wraps with AWS's own candidate shape and window.
 */
function findPairedSecret(line, akiaValue, akiaIndex) {
  return findNearbyCandidate(line, akiaValue, akiaIndex, CANDIDATE_RE, WINDOW);
}

module.exports = { findPairedSecret, findNearbyCandidate };
