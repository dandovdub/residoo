# residoo guard: scored corpus results

`residoo guard`'s decision logic (`src/guard.js`'s `evaluateToolInput`) is a
pattern-matching blocklist, not a machine-learned model, so it has none of
the recall/precision fuzziness a detector like `scan()` has — the real
open question is whether the pattern list itself is right: does it catch
what it should, and does it wrongly block ordinary work. This is measured
the same way, and held to the same "published while losing rows" standard
as the main `scan()` benchmark ([`bench/RESULTS.md`](../RESULTS.md)).

## Current result (residoo 0.8.1, 2026-09-04)

| metric | result |
|---|---|
| Recall (sensitive reads correctly blocked) | **35/35 (100%)** |
| False-positive rate (safe commands wrongly blocked) | **0/46 (0%)** |

Corpus: [`bench/guard/corpus.js`](corpus.js), 81 cases total. Reproduce:
`node bench/guard/run.js` (or `--md` for this exact table).

## How this corpus was actually built, not cherry-picked after the fact

This is not a perfect score arrived at by writing easy test cases. The
first real run against a realistic-command probe (not this formal corpus
yet, an ad-hoc check) found three genuine bugs on the first try:

- `cat .env.example` was blocked. `.env.example`/`.env.sample`/
  `.env.template` are conventional, git-committed, secret-free template
  files — blocking them is pure friction with no security benefit. Fixed:
  `.env` followed by one of those specific suffixes is now excluded.
- `cat id_rsa.pub` was blocked. A public key is, by definition, meant to
  be shared — it's what gets pasted into GitHub's own SSH keys page.
  Blocking its read protects nothing. Fixed: `*.pub` is excluded from the
  SSH-key patterns and from the whole `.ssh/` directory match, the same
  exclusion later extended to `known_hosts` (host fingerprints, not
  credentials) once the formal corpus surfaced it too.
- `cat public.pem` was blocked. Fixed: a `.pem`/`.key` filename that
  itself says "public" (`public.pem`, `public-key.pem`) is excluded — a
  real private key is never conventionally named that way.

Building the formal 81-case corpus (`bench/guard/corpus.js`) then found two
more, smaller issues on the first scored run:

- `cat gcp-service-account-prod.json` was missed. Company/project-prefixed
  service-account filenames (`<prefix>-service-account-<env>.json`) are a
  real, common convention; the pattern required a strict word boundary
  right before "service" and a hyphen didn't count as one. Fixed with a
  narrowly-scoped pattern for this one case rather than widening the
  shared boundary definition every other pattern uses (which was tried
  first and caused a real regression — see `src/guard.js`'s own comment on
  `SEP` for exactly what broke and why the fix was reverted in favor of a
  narrower one).
- `cp .env.example .env.local` was miscategorized in the corpus itself
  (not a guard.js bug) — the command touches a real, sensitive `.env.local`
  target alongside the safe template, so it should block, and the corpus
  entry said otherwise. Fixed by moving it to the correct list.

Every fix above is disclosed here specifically so this result reads as
"iterated to here," not "started here" — the same standard the main
benchmark holds itself to.

## What this score does and does not mean

This corpus measures pattern-matching accuracy against realistic filenames
and command phrasings. It does **not** mean `residoo guard` catches every
way a secret can leak — its own README section states the real, structural
limit plainly: it can only see a proposed command's INPUT before it runs,
never its OUTPUT, so it cannot catch a secret typed directly into a prompt
or one arriving through an otherwise-unremarkable command's output. This
corpus is honest about the mechanism's accuracy within its actual scope,
not a claim that the scope itself is complete.

81 cases is not exhaustive. New sensitive-file conventions or new near-miss
filename collisions found later should grow this corpus the same way the
main benchmark's corpus grows — a new case, a real fix if it's a real gap,
the before/after kept on the record either way.
