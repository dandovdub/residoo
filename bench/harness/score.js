#!/usr/bin/env node
"use strict";

/**
 * Benchmark scorer: reads bench/results/<tool>.findings.json records
 * produced by run.js plus the fixture's manifest.json, and emits per-tool,
 * PER-CLASS scores. There is deliberately no single blended headline
 * number: a blended figure would hide exactly the class differences this
 * benchmark exists to show.
 *
 * Usage:
 *   node bench/harness/score.js [--fixture <root>] [--mini] [--results <dir>] [--md] [tool ...]
 *
 * MATCHING RULES (stated in full; a hostile reader should find every
 * fairness question answered here, not dodged):
 *
 * A planted instance is credited to a tool through the first tier that
 * applies to a given finding:
 *
 *   tier 1  exact value   the finding carries the matched secret text and it
 *                         equals the planted value. Available only to tools
 *                         that print secrets (gitleaks). Tools that redact
 *                         output by design are never penalized for that:
 *                         they are matched by the location tiers below.
 *   tier 2  file+line     same file and same 1-based line. File comparison
 *                         accepts absolute paths, fixture-relative suffixes,
 *                         or bare basenames (residoo emits basenames by
 *                         design; the corpus keeps planted basename+line
 *                         pairs unique, and this scorer hard-fails if not).
 *   tier 3  file+family   same file and same coarse rule family, for tools
 *                         that report neither value nor line (whatileaked
 *                         reports one representative file per distinct
 *                         credential). When one file holds several planted
 *                         instances of the same family, attribution prefers
 *                         real secrets over suppress instances over chaff.
 *                         That is the PRO-COMPETITOR direction on purpose:
 *                         an ambiguous finding counts as recall before it
 *                         counts as a false positive.
 *
 * Each finding attributes to at most one planted instance. Extra findings
 * on an already-matched instance are neither recall nor false positives
 * (a tool re-reporting the same site is noise, not error).
 *
 * SCORES per tool per class:
 *   kind=secret    site recall  = exposure sites found / planted sites
 *                  value recall = distinct credentials found / planted
 *                                 distinct credentials (a credential counts
 *                                 as found when ANY of its exposure sites
 *                                 matched). The two differ exactly when a
 *                                 tool dedupes re-exposed credentials; both
 *                                 are always shown.
 *   kind=chaff     false positives (credential-shaped non-secrets flagged)
 *   kind=suppress  false positives (vendor-documented example values flagged)
 *
 * Precision per tool counts planted INSTANCES, not raw findings (re-reporting
 * a matched site is neither doubly right nor doubly wrong):
 * matched secret sites / (matched secret sites + chaff instances flagged +
 * suppress instances flagged + findings matching nothing planted).
 *
 * CLAIMED SCOPE: a tool is scored on a class only if its adapter's
 * claimedClasses (taken from the tool's own documentation, quoted in each
 * adapter) covers it. Unclaimed classes are reported as "out of claimed
 * scope", never as zero recall. Chaff/suppress instances carry the surface
 * class they are embedded in (surfaceClass) for the same scoping decision.
 *
 * ggshield is a special case handled by notScoredForRecall: its recall
 * column reads "not scored (requires server account)", never zero, with the
 * citation printed. Its egress verdict and observed behavior are reported
 * like every other tool's.
 *
 * DUAL-MODE TOOLS (optional live verification, e.g. TruffleHog, Kingfisher,
 * detect-secrets): recall is scored ONLY from the tool's documented offline
 * mode (its own flag, e.g. trufflehog --no-verification, kingfisher
 * --no-validate, detect-secrets -n), because scoring recall in a mode that
 * phones out would conflate the recall axis with the egress axis. Egress is
 * then observed in BOTH modes: the offline run's egress record travels with
 * the scored results as usual, and a companion egress-observation run
 * (adapter id <tool>-default-verification, marked egressOnly with forTool
 * naming the scored adapter) executes the tool's default mode against the
 * same corpus
 * under the same monitor. The scorer attaches that record to the tool's row
 * as a second, clearly labeled mode line (egressModes in scoreboard.json)
 * with the observed connection attempts and their CONNECT destinations
 * reported factually, plus the adapter's citation of the vendor's own
 * verification documentation. Companion records are never scored for recall
 * or precision and never appear as separate tools.
 */

const fs = require("fs");
const path = require("path");
const lib = require("./lib");

function parseArgs(argv) {
  const args = {
    fixtureRoot: path.join(lib.BENCH_ROOT, "corpus", "data"),
    resultsDir: lib.RESULTS_DIR,
    md: false,
    tools: [],
  };
  let resultsOverridden = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--fixture") args.fixtureRoot = path.resolve(argv[++i]);
    else if (a === "--mini") {
      args.fixtureRoot = path.join(lib.BENCH_ROOT, "minifix", "data");
      // Fixture-scoped results dir, matching run.js --mini: a smoke score
      // must never overwrite the published full-corpus scoreboard.
      if (!resultsOverridden) args.resultsDir = path.join(lib.BENCH_ROOT, "results-mini");
    }
    else if (a === "--results") { args.resultsDir = path.resolve(argv[++i]); resultsOverridden = true; }
    else if (a === "--md") args.md = true;
    else args.tools.push(a);
  }
  return args;
}

function fileMatches(finding, planted, fixtureRoot) {
  if (!finding.file) return false;
  const plantedAbs = path.resolve(fixtureRoot, planted.file);
  const plantedBase = path.basename(planted.file);
  const f = finding.file;
  if (path.isAbsolute(f)) return path.resolve(f) === plantedAbs;
  if (f.includes(path.sep)) return plantedAbs.endsWith(path.sep + f);
  return f === plantedBase; // basename-only emitters (redacting tools)
}

function attribute(findings, planted, fixtureRoot) {
  const instMatches = planted.map(() => []); // finding indices per instance
  const findingMatched = findings.map(() => null); // instance index per finding

  const claim = (fi, pi) => {
    findingMatched[fi] = pi;
    instMatches[pi].push(fi);
  };

  // tier 1: exact value
  findings.forEach((f, fi) => {
    if (findingMatched[fi] !== null || !f.value) return;
    const candidates = planted
      .map((p, pi) => ({ p, pi }))
      .filter(({ p }) => p.value === f.value);
    if (!candidates.length) return;
    const inFile = candidates.filter(({ p }) => fileMatches(f, p, fixtureRoot));
    const pool = inFile.length ? inFile : candidates;
    const unmatched = pool.filter(({ pi }) => instMatches[pi].length === 0);
    claim(fi, (unmatched[0] || pool[0]).pi);
  });

  // tier 2: file+line
  findings.forEach((f, fi) => {
    if (findingMatched[fi] !== null || f.line === null) return;
    const hit = planted.findIndex((p) => p.line === f.line && fileMatches(f, p, fixtureRoot));
    if (hit >= 0) claim(fi, hit);
  });

  // tier 3: file+family. Candidate order: kind first (secrets before
  // suppress before chaff, the pro-competitor direction: an ambiguous
  // finding counts as recall before it counts as a false positive), then
  // still-unmatched instances before already-matched ones (so a duplicate
  // finding extends recall to another site rather than piling onto one).
  const KIND_ORDER = { secret: 0, suppress: 1, chaff: 2 };
  findings.forEach((f, fi) => {
    if (findingMatched[fi] !== null || !f.ruleFamily) return;
    const candidates = planted
      .map((p, pi) => ({ p, pi }))
      .filter(({ p }) => p.ruleFamily === f.ruleFamily && fileMatches(f, p, fixtureRoot))
      .sort((a, b) => {
        const kind = (KIND_ORDER[a.p.kind] ?? 3) - (KIND_ORDER[b.p.kind] ?? 3);
        if (kind) return kind;
        return (instMatches[b.pi].length === 0) - (instMatches[a.pi].length === 0);
      });
    if (candidates.length) claim(fi, candidates[0].pi);
  });

  return { instMatches, findingMatched };
}

function pct(n, d) {
  if (d === 0) return "n/a";
  return ((100 * n) / d).toFixed(0) + "%";
}

/** Distinct CONNECT destinations from a raw egress observed record. */
function connectTargets(observed) {
  const targets = [];
  const seen = new Set();
  for (const a of (observed && observed.proxyConnectAttempts) || []) {
    const m = a.firstLine && String(a.firstLine).match(/^CONNECT\s+(\S+)/i);
    const t = m ? m[1] : (a.firstLine ? String(a.firstLine).slice(0, 80) : "(connection with no readable request line)");
    if (!seen.has(t)) { seen.add(t); targets.push(t); }
  }
  return targets;
}

/**
 * One labeled egress-mode entry for a tool's egressModes list, built from a
 * raw run record (run.js output). Counts plus the factual CONNECT
 * destinations; verdict wording stays the monitor's own.
 */
function egressModeEntry(record, modeLabel, extra) {
  const eg = record.egress || {};
  const obs = eg.observed || {};
  return {
    mode: modeLabel,
    verdict: eg.verdict || "unknown",
    detail: eg.detail || eg.citation || null,
    proxyConnectAttempts: (obs.proxyConnectAttempts || []).length,
    nonProxySockets: (obs.nonProxySockets || []).length,
    connectTargets: connectTargets(obs),
    wallMs: record.wallMs,
    ...(extra || {}),
  };
}

function scoreTool(record, manifest, fixtureRoot) {
  const planted = manifest.planted;
  const classes = manifest.classes;
  const claimed = record.claimedClasses || [];

  const scopeClassOf = (p) => p.surfaceClass || p.class;
  const inScope = (p) => lib.claimCovers(claimed, scopeClassOf(p));

  const { instMatches, findingMatched } = attribute(record.findings, planted, fixtureRoot);

  const perClass = {};
  for (const [cid, cdef] of Object.entries(classes)) {
    const instances = planted.map((p, pi) => ({ p, pi })).filter(({ p }) => p.class === cid);
    if (!instances.length) continue;
    const scoped = instances.every(({ p }) => inScope(p));
    const row = { class: cid, kind: cdef.kind, claimed: scoped };
    if (!scoped) {
      row.status = "out of claimed scope (not scored)";
      perClass[cid] = row;
      continue;
    }
    if (cdef.kind === "secret") {
      const sites = instances.length;
      const sitesFound = instances.filter(({ pi }) => instMatches[pi].length > 0).length;
      const groups = new Set(instances.map(({ p }) => p.distinctGroup));
      const groupsFound = new Set(
        instances.filter(({ pi }) => instMatches[pi].length > 0).map(({ p }) => p.distinctGroup)
      );
      row.sites = sites;
      row.sitesFound = sitesFound;
      row.siteRecall = pct(sitesFound, sites);
      row.values = groups.size;
      row.valuesFound = groupsFound.size;
      row.valueRecall = pct(groupsFound.size, groups.size);
    } else {
      const flagged = instances.filter(({ pi }) => instMatches[pi].length > 0).length;
      row.instances = instances.length;
      row.falsePositives = flagged;
    }
    perClass[cid] = row;
  }

  // Precision counts INSTANCES, not findings: a tool that reports the same
  // planted site under two rule ids is re-reporting, not doubly right or
  // doubly wrong (see the matching-rules header: extras on an already
  // matched instance are neither recall nor false positives).
  // Scope symmetry: every precision term is filtered to claimed scope, the
  // credit side (matched secret sites) exactly like the charge side (chaff
  // and suppress flags), so a tool can neither gain nor lose precision in a
  // class it is not scored on.
  const matchedInstances = new Set(findingMatched.filter((pi) => pi !== null));
  const matchedSecretSites = [...matchedInstances].filter((pi) => planted[pi].kind === "secret" && inScope(planted[pi])).length;
  const chaffFlags = [...matchedInstances].filter((pi) => planted[pi].kind === "chaff" && inScope(planted[pi])).length;
  const suppressFlags = [...matchedInstances].filter((pi) => planted[pi].kind === "suppress" && inScope(planted[pi])).length;
  const unplanted = record.findings.filter((_, fi) => findingMatched[fi] === null);

  const fpTotal = chaffFlags + suppressFlags + unplanted.length;
  const reExposed = planted.map((p, pi) => ({ p, pi })).filter(({ p }) => p.kind === "secret" && p.exposure === "re-exposed" && inScope(p));

  // Overall distinct-credential recall across ALL claimed classes (the hard
  // classes explicitly included; the headline-classes-only variant is
  // reported alongside). The all-classes line exists so a tool that
  // deliberately reports one representative site per distinct credential
  // (whatileaked) is never undercounted at the value level: a credential
  // found anywhere counts as found, even when its other exposure sites
  // (possibly in other classes) went unreported. The per-class site metrics
  // still show the cost of that dedup honestly.
  const isHardClass = (p) => Boolean((classes[p.class] || {}).hard);
  const secretInstances = planted.map((p, pi) => ({ p, pi })).filter(({ p }) => p.kind === "secret" && inScope(p));
  const allGroups = new Set(secretInstances.map(({ p }) => p.distinctGroup));
  const foundGroups = new Set(secretInstances.filter(({ pi }) => instMatches[pi].length > 0).map(({ p }) => p.distinctGroup));
  const headlineInstances = secretInstances.filter(({ p }) => !isHardClass(p));
  const headlineGroups = new Set(headlineInstances.map(({ p }) => p.distinctGroup));
  const headlineFound = new Set(headlineInstances.filter(({ pi }) => instMatches[pi].length > 0).map(({ p }) => p.distinctGroup));

  // Per-family site recall over claimed secret classes, so any reader can
  // recompute any class or headline with any family subset and separate
  // family-coverage effects from transcript-shape effects.
  const perFamily = {};
  for (const { p, pi } of secretInstances) {
    const fam = p.ruleFamily || "unknown";
    perFamily[fam] = perFamily[fam] || { sites: 0, sitesFound: 0 };
    perFamily[fam].sites++;
    if (instMatches[pi].length > 0) perFamily[fam].sitesFound++;
  }

  return {
    tool: record.tool,
    displayName: record.displayName,
    version: record.version,
    wallMs: record.wallMs,
    egressVerdict: record.egress ? record.egress.verdict : "unknown",
    // detail carries the observed evidence (verdictFor folds observed
    // attempt counts into it); the by-design citation is rendered once via
    // notScoredForRecall, never duplicated here.
    egressDetail: record.egress ? (record.egress.detail || record.egress.citation) : null,
    egressObserved: record.egress && record.egress.observed
      ? {
          proxyConnectAttempts: (record.egress.observed.proxyConnectAttempts || []).length,
          nonProxySockets: (record.egress.observed.nonProxySockets || []).length,
        }
      : null,
    fixtureMutations: record.fixtureMutations || [],
    scratchWrites: record.scratchWrites || [],
    notScoredForRecall: record.notScoredForRecall || null,
    claimedClasses: claimed,
    claimsNote: record.claimsNote,
    perClass,
    precision: {
      matchedSecretSites,
      chaffFlags,
      suppressFlags,
      unplantedFindings: unplanted.length,
      unplantedSamples: unplanted.slice(0, 10).map((f) => ({ file: f.fileBasename, rule: f.rawRule })),
      precision: pct(matchedSecretSites, matchedSecretSites + fpTotal),
      // Whether flagging vendor-documented example values is a false
      // positive is a philosophy reasonable people weigh differently, so
      // precision is also published with suppress flags excluded.
      precisionExclSuppress: pct(matchedSecretSites, matchedSecretSites + chaffFlags + unplanted.length),
    },
    overallDistinctCredentials: {
      note: "ALL claimed classes, hard classes included; a distinct credential counts as found when any of its exposure sites matched, in any claimed class; guards dedup-style reporters against value-level undercounting. headlineOnly excludes the hard classes.",
      total: allGroups.size,
      found: foundGroups.size,
      recall: pct(foundGroups.size, allGroups.size),
      headlineOnly: {
        total: headlineGroups.size,
        found: headlineFound.size,
        recall: pct(headlineFound.size, headlineGroups.size),
      },
    },
    perFamily,
    reExposure: {
      note: "re-exposed sites are additional exposure locations of a credential already planted elsewhere; a tool that dedupes distinct credentials scores full value recall but partial site recall",
      sitesTotal: reExposed.length,
      sitesFound: reExposed.filter(({ pi }) => instMatches[pi].length > 0).length,
    },
    unexpectedExit: record.unexpectedExit || false,
  };
}

function renderText(scores, manifest) {
  const out = [];
  out.push("Benchmark scoreboard (per class; no blended headline by design)");
  out.push("");
  for (const s of scores) {
    out.push(`== ${s.displayName} (${s.version}) ==`);
    if (s.egressModes) {
      // Dual-mode tool: one clearly labeled egress line per mode.
      out.push(`   wall: ${s.wallMs}ms (offline mode)`);
      for (const m of s.egressModes) {
        const targets = m.connectTargets && m.connectTargets.length ? `; CONNECT targets: ${m.connectTargets.join(", ")}` : "";
        out.push(`   egress, ${m.mode}: ${m.verdict} (${m.proxyConnectAttempts} proxy CONNECT attempt(s), ${m.nonProxySockets} non-proxy socket(s)${targets})`);
        if (m.citation) out.push(`     citation: ${m.citation}`);
        if (m.fakeValuesNote) out.push(`     note: ${m.fakeValuesNote}`);
      }
    } else {
      out.push(`   wall: ${s.wallMs}ms   egress: ${s.egressVerdict}`);
      if (s.egressDetail) out.push(`   egress detail: ${s.egressDetail}`);
    }
    if (s.unexpectedExit) out.push("   WARNING: a scan invocation exited outside the tool's documented codes; inspect results/raw/");
    if (s.notScoredForRecall) {
      out.push(`   recall: ${s.notScoredForRecall.reason}`);
      out.push(`   citation: ${s.notScoredForRecall.citation}`);
      out.push("");
      continue;
    }
    for (const row of Object.values(s.perClass)) {
      if (row.status) {
        out.push(`   ${row.class.padEnd(28)} ${row.status}`);
      } else if (row.kind === "secret") {
        out.push(
          `   ${row.class.padEnd(28)} sites ${String(row.sitesFound).padStart(3)}/${String(row.sites).padEnd(3)} (${row.siteRecall})   distinct values ${row.valuesFound}/${row.values} (${row.valueRecall})`
        );
      } else {
        out.push(
          `   ${row.class.padEnd(28)} [${row.kind}] false positives ${row.falsePositives}/${row.instances}`
        );
      }
    }
    const p = s.precision;
    out.push(
      `   precision ${p.precision}  (matched sites ${p.matchedSecretSites}, chaff FP ${p.chaffFlags}, suppress FP ${p.suppressFlags}, unplanted FP ${p.unplantedFindings}); excluding suppress FP ${p.precisionExclSuppress}`
    );
    const o = s.overallDistinctCredentials;
    out.push(
      `   distinct credentials found, all claimed classes (hard classes included) ${o.found}/${o.total} (${o.recall}); headline classes only ${o.headlineOnly.found}/${o.headlineOnly.total} (${o.headlineOnly.recall})`
    );
    out.push(`   re-exposed sites found ${s.reExposure.sitesFound}/${s.reExposure.sitesTotal}`);
    const fams = Object.entries(s.perFamily || {});
    if (fams.length) {
      out.push(
        "   per-family sites: " + fams.map(([f, v]) => `${f} ${v.sitesFound}/${v.sites}`).join("  ")
      );
    }
    if ((s.fixtureMutations || []).length) {
      out.push(`   WARNING: this tool mutated the scanned fixture (${s.fixtureMutations.length} change(s)); see results/raw/`);
    }
    out.push("");
  }
  out.push("Scoring notes:");
  out.push("- classes a tool never claimed (per its own docs, quoted in its adapter) are reported as out of claimed scope, never as zero");
  out.push("- egress verdicts cover SCAN time only; install-time package fetches are expected and unscored");
  out.push("- dual-mode tools (optional live verification) are scored for recall in their documented offline mode only; their default mode's observed egress is the second labeled line, and the corpus contains only pattern-true fake values");
  out.push("- matching tiers and the pro-competitor ambiguity rule are documented at the top of bench/harness/score.js");
  return out.join("\n");
}

/**
 * Compact cross-tool matrix so scoreboard.md stays readable as the field
 * grows: per-tool detail keeps its own section below (columns never widen
 * with the tool count there), and this matrix gives the at-a-glance
 * comparison with one short cell per tool. Cells: sites found for secret
 * classes, FP counts for chaff/suppress, "oos" out of claimed scope, "n/s"
 * not scored for recall (reason in the tool's section).
 */
function renderSummaryMatrix(scores, manifest) {
  const out = [];
  const classIds = Object.keys(manifest.classes).filter((cid) => scores.some((s) => s.perClass[cid]));
  if (!classIds.length || scores.length < 2) return out;
  out.push("## Cross-tool summary");
  out.push("");
  out.push("Site recall per class (sites found / planted sites). Full per-tool detail, value recall, precision, and notes are in the sections below. oos = out of the tool's claimed scope (not scored, never zero); n/s = recall not scored (reason in the tool's section); FP = flagged instances of a non-secret class (false positives).");
  out.push("");
  out.push("| class | " + scores.map((s) => s.tool).join(" | ") + " |");
  out.push("|---|" + scores.map(() => "---").join("|") + "|");
  for (const cid of classIds) {
    const cells = scores.map((s) => {
      if (s.notScoredForRecall) return "n/s";
      const row = s.perClass[cid];
      if (!row) return "";
      if (row.status) return "oos";
      if (row.kind === "secret") return `${row.sitesFound}/${row.sites}`;
      return `${row.falsePositives}/${row.instances} FP`;
    });
    const cdef = manifest.classes[cid];
    const tag = cdef.kind !== "secret" ? ` (${cdef.kind})` : (cdef.hard ? " (hard class)" : "");
    out.push(`| ${cid}${tag} | ${cells.join(" | ")} |`);
  }
  const distinct = scores.map((s) => (s.notScoredForRecall ? "n/s" : `${s.overallDistinctCredentials.found}/${s.overallDistinctCredentials.total}`));
  out.push(`| distinct credentials, all claimed classes | ${distinct.join(" | ")} |`);
  const prec = scores.map((s) => (s.notScoredForRecall ? "n/s" : s.precision.precision));
  out.push(`| precision (suppress FP included) | ${prec.join(" | ")} |`);
  const egress = scores.map((s) => (s.egressModes ? s.egressModes.map((m) => m.verdict).join(" / ") : s.egressVerdict));
  out.push(`| egress verdict (offline / default where dual-mode) | ${egress.join(" | ")} |`);
  out.push("");
  return out;
}

function renderMarkdown(scores, manifest, unattachedEgressObservations) {
  const out = [];
  out.push("# Scoreboard");
  out.push("");
  out.push("Per-class scores. There is no blended headline number by design: a blend would hide the class differences the benchmark exists to show.");
  out.push("");
  out.push(...renderSummaryMatrix(scores, manifest));
  for (const s of scores) {
    out.push(`## ${s.displayName} (${s.version})`);
    out.push("");
    if (s.egressModes) {
      out.push(`- wall time: ${s.wallMs}ms (offline mode)`);
      for (const m of s.egressModes) {
        const targets = m.connectTargets && m.connectTargets.length ? `; CONNECT targets: ${m.connectTargets.join(", ")}` : "";
        out.push(`- egress (scan-time only), ${m.mode}: **${m.verdict}** (${m.proxyConnectAttempts} proxy CONNECT attempt(s), ${m.nonProxySockets} non-proxy socket(s)${targets})`);
        if (m.citation) out.push(`  - citation: ${m.citation}`);
        if (m.fakeValuesNote) out.push(`  - note: ${m.fakeValuesNote}`);
      }
    } else {
      out.push(`- wall time: ${s.wallMs}ms`);
      out.push(`- egress (scan-time only): **${s.egressVerdict}**${s.egressDetail ? " " + s.egressDetail : ""}`);
    }
    if (s.notScoredForRecall) {
      out.push(`- recall: **${s.notScoredForRecall.reason}**`);
      out.push(`- citation: ${s.notScoredForRecall.citation}`);
      out.push("");
      continue;
    }
    out.push("");
    out.push("| class | kind | sites found | site recall | distinct values | value recall | false positives |");
    out.push("|---|---|---|---|---|---|---|");
    for (const row of Object.values(s.perClass)) {
      if (row.status) {
        out.push(`| ${row.class} | | ${row.status} | | | | |`);
      } else if (row.kind === "secret") {
        out.push(`| ${row.class} | secret | ${row.sitesFound}/${row.sites} | ${row.siteRecall} | ${row.valuesFound}/${row.values} | ${row.valueRecall} | |`);
      } else {
        out.push(`| ${row.class} | ${row.kind} | | | | | ${row.falsePositives}/${row.instances} |`);
      }
    }
    const p = s.precision;
    const o = s.overallDistinctCredentials;
    out.push("");
    out.push(`Precision: ${p.precision} (matched sites ${p.matchedSecretSites}, chaff FP ${p.chaffFlags}, suppress FP ${p.suppressFlags}, unplanted FP ${p.unplantedFindings}); ${p.precisionExclSuppress} with suppress flags excluded. Distinct credentials found, all claimed classes (hard classes included): ${o.found}/${o.total}; headline classes only: ${o.headlineOnly.found}/${o.headlineOnly.total}. Re-exposed sites found: ${s.reExposure.sitesFound}/${s.reExposure.sitesTotal}.`);
    const fams = Object.entries(s.perFamily || {});
    if (fams.length) {
      out.push("");
      out.push("Per-family site recall (claimed secret classes):");
      out.push("");
      out.push("| family | sites found |");
      out.push("|---|---|");
      for (const [f, v] of fams) out.push(`| ${f} | ${v.sitesFound}/${v.sites} |`);
    }
    if ((s.fixtureMutations || []).length) {
      out.push("");
      out.push(`WARNING: this tool mutated the scanned fixture (${s.fixtureMutations.length} change(s)); see results/raw/.`);
    }
    out.push("");
  }
  for (const u of unattachedEgressObservations || []) {
    out.push(`## ${u.recordTool} (egress observation, unattached)`);
    out.push("");
    out.push(`This default-mode egress observation names forTool=${u.forTool}, which has no scored results in this scoreboard; rerun the scored (offline-mode) adapter to attach it.`);
    out.push("");
    out.push(`- egress (scan-time only), ${u.mode}: **${u.verdict}** (${u.proxyConnectAttempts} proxy CONNECT attempt(s), ${u.nonProxySockets} non-proxy socket(s)${u.connectTargets && u.connectTargets.length ? "; CONNECT targets: " + u.connectTargets.join(", ") : ""})`);
    if (u.citation) out.push(`  - citation: ${u.citation}`);
    if (u.fakeValuesNote) out.push(`  - note: ${u.fakeValuesNote}`);
    out.push("");
  }
  return out.join("\n") + "\n";
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifest = lib.loadManifest(args.fixtureRoot);

  // Fairness precondition for basename-tier matching: a basename-only
  // emitter is matched at tier 2 (basename+line), so the fatal ambiguity is
  // two planted sites sharing basename AND line across different paths.
  // (Bare duplicate basenames are legitimate: real agent layouts repeat
  // names like settings.local.json; the line disambiguates. Tier 3 never
  // sees basenames: every tool matched there emits full paths.)
  const seenKey = new Map();
  for (const p of manifest.planted) {
    const k = path.basename(p.file) + ":" + p.line;
    const prev = seenKey.get(k);
    if (prev && prev !== p.file) {
      console.error(`manifest error: planted sites share basename+line (${k}) across different paths; basename-tier matching would be ambiguous. Fix the corpus.`);
      process.exit(2);
    }
    seenKey.set(k, p.file);
  }

  let toolFiles;
  if (args.tools.length) {
    toolFiles = args.tools.map((t) => path.join(args.resultsDir, `${t}.findings.json`));
  } else {
    toolFiles = fs.readdirSync(args.resultsDir)
      .filter((f) => f.endsWith(".findings.json"))
      .map((f) => path.join(args.resultsDir, f));
  }
  if (!toolFiles.length) {
    console.error(`no *.findings.json in ${args.resultsDir}; run bench/harness/run.js first`);
    process.exit(2);
  }

  const scores = [];
  const rawRecords = {}; // tool id -> raw run record, for egress-mode assembly
  const companions = []; // egressOnly records (dual-mode default runs)
  for (const f of toolFiles) {
    if (!fs.existsSync(f)) {
      console.error(`missing results file: ${f} (skipped)`);
      continue;
    }
    const record = JSON.parse(fs.readFileSync(f, "utf8"));
    if (path.resolve(record.fixtureRoot) !== path.resolve(args.fixtureRoot)) {
      console.error(`skipping ${record.tool}: its results were produced against ${record.fixtureRoot}, not ${args.fixtureRoot}; rerun run.js against the right fixture`);
      continue;
    }
    if (record.egressOnly && record.egressOnly.forTool) {
      // Dual-mode companion (default-mode egress observation): attached to
      // its tool's row below, never scored as a separate tool.
      companions.push(record);
      continue;
    }
    rawRecords[record.tool] = record;
    scores.push(scoreTool(record, manifest, args.fixtureRoot));
  }
  if (!scores.length) {
    console.error("no scoreable results for this fixture; refusing to write an empty scoreboard over existing files");
    process.exit(2);
  }

  // Attach dual-mode egress lines: the scored (offline) run's egress first,
  // then the default-mode observation, both clearly labeled.
  const unattachedEgressObservations = [];
  for (const rec of companions) {
    const main = scores.find((s) => s.tool === rec.egressOnly.forTool);
    const entry = egressModeEntry(rec, rec.egressOnly.modeLabel || "default mode", {
      citation: rec.egressOnly.citation || null,
      fakeValuesNote: rec.egressOnly.fakeValuesNote || null,
      version: rec.version,
    });
    if (!main) {
      console.error(`egress-only record ${rec.tool} names forTool=${rec.egressOnly.forTool}, which has no scored results here; reported unattached`);
      unattachedEgressObservations.push({ recordTool: rec.tool, forTool: rec.egressOnly.forTool, ...entry });
      continue;
    }
    if (!main.egressModes) {
      const mainRecord = rawRecords[main.tool];
      main.egressModes = [
        egressModeEntry(mainRecord, rec.egressOnly.primaryModeLabel || "offline mode (scored for recall)"),
      ];
    }
    main.egressModes.push(entry);
  }

  console.log(renderText(scores, manifest));
  const jsonPath = path.join(args.resultsDir, "scoreboard.json");
  // Relative to the repo root, never the absolute filesystem path: this file
  // is committed and public, and an absolute path can carry the machine's
  // username (caught in a pre-launch audit: a prior run had leaked
  // /Users/<realname>/... here).
  const board = { generatedAt: new Date().toISOString(), fixtureRoot: path.relative(lib.REPO_ROOT, args.fixtureRoot), manifestSeed: manifest.seed, scores };
  if (unattachedEgressObservations.length) board.unattachedEgressObservations = unattachedEgressObservations;
  fs.writeFileSync(jsonPath, JSON.stringify(board, null, 2) + "\n");
  console.log(`scoreboard.json written to ${jsonPath}`);
  if (args.md) {
    const mdPath = path.join(args.resultsDir, "scoreboard.md");
    fs.writeFileSync(mdPath, renderMarkdown(scores, manifest, unattachedEgressObservations));
    console.log(`scoreboard.md written to ${mdPath}`);
  }
}

if (require.main === module) main();

// Exported for audit tooling (e.g. per-tool miss listings); scoring behavior
// lives entirely above and does not depend on how these are consumed.
module.exports = { attribute, fileMatches, scoreTool };
