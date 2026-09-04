"use strict";

const path = require("path");
const { scan, VERIFIABLE_RULE_IDS } = require("./scan");
const {
  ROTATION_GUIDANCE, guidanceFor, loadAcks, loadDismissed,
  ackFinding, dismissFinding, renderRotation,
} = require("./rotation");
const { sweepOnce } = require("./watch");
const { runWithCredential, parseAllowedCommands } = require("./credRun");
const keychain = require("./keychain");

/**
 * The tool catalog for `residoo mcp` (see src/mcp.js for the protocol
 * engine that calls into this). Every handler here calls the same PURE
 * engine functions the CLI itself uses (`scan`, `renderRotation`,
 * `ackFinding`/`dismissFinding`, `guidanceFor`, `sweepOnce`) -- never
 * `cli.js`'s `runX()` functions or `watch.js`'s `startWatch()`, since
 * those specific functions write to stdout by design (they're the
 * human-facing presenters), and this file's whole job is to never let a
 * byte reach stdout except through mcp.js's own `send()`.
 *
 * `verify` is not exposed as a parameter on residoo_scan/residoo_check, on
 * purpose: a human typing `--verify` at a terminal is a deliberate, legible
 * act; an autonomous model choosing a network-triggering parameter
 * mid-conversation is a different trust boundary, and a generic
 * tool-approval prompt may not surface that a given call also makes a live
 * vendor API request with a real secret. Both hardcode `verify: false`. Live
 * verification instead gets its own narrowly-scoped tool, residoo_verify_finding
 * (one credential per call, gated behind RESIDOO_MCP_ALLOW_VERIFY so it does
 * not exist at all unless an operator deliberately opts in) -- see its own
 * comment below for why that is a materially different, honestly-labeled
 * trust boundary rather than the same one wearing a different name.
 */

const FINGERPRINT_PATTERN = /^rf1-[0-9a-f]{32}$/;

function textResult(obj) {
  return { content: [{ type: "text", text: JSON.stringify(obj) }] };
}
function errorResult(message) {
  return { content: [{ type: "text", text: message }], isError: true };
}

function rejectUnknownKeys(args, allowed) {
  const errs = [];
  for (const k of Object.keys(args)) {
    if (!allowed.has(k)) errs.push(`unexpected property "${k}"`);
  }
  return errs;
}

/**
 * Shared arg shape for residoo_scan/residoo_check: includeNoisy,
 * includeSuppressed, includePii, maxEntries. includePii is exposed here
 * (unlike ocr or verify, see this file's own header comment on verify's
 * exclusion) because it is architecturally identical to includeNoisy --
 * local-only, no network call, no external process, just a different
 * detection category (see pii.js) -- not the network/live-secret trust
 * boundary verify's own exclusion is specifically about.
 */
function validateSweepArgs(args, allowedKeys) {
  const errs = rejectUnknownKeys(args, allowedKeys);
  if (args.includeNoisy !== undefined && typeof args.includeNoisy !== "boolean") errs.push("includeNoisy must be a boolean");
  if (args.includeSuppressed !== undefined && typeof args.includeSuppressed !== "boolean") errs.push("includeSuppressed must be a boolean");
  if (args.includePii !== undefined && typeof args.includePii !== "boolean") errs.push("includePii must be a boolean");
  let maxEntries = 25;
  if (args.maxEntries !== undefined) {
    if (typeof args.maxEntries !== "number" || !Number.isInteger(args.maxEntries) || args.maxEntries < 1 || args.maxEntries > 200) {
      errs.push("maxEntries must be an integer between 1 and 200");
    } else {
      maxEntries = args.maxEntries;
    }
  }
  return {
    errs, includeNoisy: args.includeNoisy === true, includeSuppressed: args.includeSuppressed === true,
    includePii: args.includePii === true, maxEntries,
  };
}

/** Drop the full step-by-step runbook (redundant once per shared rule id across many entries -- call residoo_explain for that) and any null-valued optional field. */
function trimGuidance(g) {
  if (!g) return null;
  const out = { label: g.label };
  if (g.rotateUrl) out.rotateUrl = g.rotateUrl;
  if (g.consolePath) out.consolePath = g.consolePath;
  if (g.revokeNote) out.revokeNote = g.revokeNote;
  if (g.generic) out.generic = true;
  return out;
}

function shapeRotationEntry(e) {
  const out = {
    fingerprint: e.fingerprint, ruleId: e.ruleId, label: e.label, preview: e.preview,
    status: e.status, occurrences: e.occurrences, files: e.files, sources: e.sources,
    guidance: trimGuidance(e.guidance),
  };
  if (e.ackedAt) out.ackedAt = e.ackedAt;
  if (e.ackNote) out.ackNote = e.ackNote;
  if (e.lastSeenMs != null) out.lastSeenAt = new Date(e.lastSeenMs).toISOString();
  if (e.pairedSecretPreview) out.pairedSecretPreview = e.pairedSecretPreview;
  if (e.pairedAccessKeyPreview) out.pairedAccessKeyPreview = e.pairedAccessKeyPreview;
  if (e.pairedOtherPreview) { out.pairedOtherPreview = e.pairedOtherPreview; out.pairedOtherLabel = e.pairedOtherLabel; }
  if (e.jwtExpiresAtMs != null) out.jwtExpiresAtMs = e.jwtExpiresAtMs;
  return out;
}

function buildScanSummary(scope, counts, filesScanned, sourceCount) {
  const scopeText = scope.type === "project" ? `project "${scope.projectDir}"` : `${sourceCount} source(s)`;
  if (counts.distinct === 0) return `Scanned ${scopeText}, ${filesScanned} file(s). No secrets found.`;
  const bits = [];
  if (counts.pending > 0) bits.push(`${counts.pending} pending rotation`);
  if (counts.acked > 0) bits.push(`${counts.acked} already acknowledged`);
  if (counts.dismissed > 0) bits.push(`${counts.dismissed} dismissed`);
  return `Scanned ${scopeText}, ${filesScanned} file(s). ${counts.distinct} distinct secret(s): ${bits.join(", ")}.`;
}

/**
 * `buildTools({sources})` returns a fresh `Map<name, {name, description,
 * inputSchema, handler}>` for one `residoo mcp` server invocation.
 * Session-scoped state (the fingerprint-hallucination guard, and
 * residoo_check's tracked/seen Maps) lives in this function's closure, not
 * at module scope, so each server run gets its own clean state and tests
 * can build independent tool sets without cross-test pollution.
 *
 * `sources` is captured ONCE here (evaluated by the caller before this is
 * called), matching `residoo watch`'s own existing, documented limitation:
 * an agent tool installed mid-session needs a restart to be picked up.
 */
function buildTools({ sources }) {
  const sessionSeenFingerprints = new Set();
  const checkTracked = new Map();
  const checkSeen = new Map();
  let checkStarted = false;

  async function handleScan(args) {
    const SCAN_KEYS = new Set(["projectDir", "includeNoisy", "includeSuppressed", "includePii", "maxEntries"]);
    const { errs, includeNoisy, includeSuppressed, includePii, maxEntries } = validateSweepArgs(args, SCAN_KEYS);
    if (args.projectDir !== undefined && typeof args.projectDir !== "string") errs.push("projectDir must be a string");
    if (errs.length) return errorResult(`Invalid arguments: ${errs.join("; ")}`);

    let scanSources;
    let scope = { type: "machine" };
    if (args.projectDir !== undefined) {
      const projectArtifacts = require("./sources/project-artifacts");
      const resolved = path.resolve(args.projectDir);
      const src = projectArtifacts.withRoot(resolved);
      if (!src.available()) return errorResult(`"${args.projectDir}" is not a readable directory.`);
      scanSources = [src];
      scope = { type: "project", projectDir: resolved };
    } else {
      scanSources = sources;
    }

    const result = await scan({ sources: scanSources, includeNoisy, includeSuppressed, includePii, verify: false, noColor: true });
    const acks = loadAcks();
    const dismissed = loadDismissed();
    const rotation = renderRotation(result.findings, acks, dismissed);
    for (const e of rotation.entries) sessionSeenFingerprints.add(e.fingerprint);

    const total = rotation.entries.length;
    const truncated = total > maxEntries;
    const entries = rotation.entries.slice(0, maxEntries).map(shapeRotationEntry);
    const sourceCount = scope.type === "project" ? 1 : scanSources.length;

    return textResult({
      scannedAt: new Date().toISOString(),
      scope,
      filesScanned: result.filesScanned,
      sourcesScanned: result.sourcesScanned,
      bytesScanned: result.bytesScanned,
      unreadable: { count: result.unreadableFiles.length, sample: result.unreadableFiles.slice(0, 5) },
      counts: rotation.counts,
      entries,
      truncated,
      truncatedCount: truncated ? total - maxEntries : 0,
      summary: buildScanSummary(scope, rotation.counts, result.filesScanned, sourceCount),
    });
  }

  async function handleCheck(args) {
    const CHECK_KEYS = new Set(["includeNoisy", "includeSuppressed", "includePii", "maxEntries"]);
    const { errs, includeNoisy, includeSuppressed, includePii, maxEntries } = validateSweepArgs(args, CHECK_KEYS);
    if (errs.length) return errorResult(`Invalid arguments: ${errs.join("; ")}`);

    const firstCheckThisSession = !checkStarted;
    checkStarted = true;

    const ledger = { acks: loadAcks(), dismissed: loadDismissed() };
    const events = [];
    const emit = (e) => events.push(e);
    const stats = await sweepOnce({
      sources, tracked: checkTracked, seen: checkSeen, ledger,
      options: { includeNoisy, includeSuppressed, includePii, verify: false, noColor: true }, emit,
    });

    const allNew = events.filter((e) => e.type === "finding");
    const allReexposures = events.filter((e) => e.type === "reexposure");
    for (const e of allNew) sessionSeenFingerprints.add(e.fingerprint);

    const newFindings = allNew.slice(0, maxEntries).map((e) => ({
      fingerprint: e.fingerprint, ruleId: e.ruleId, label: e.label, confidence: e.confidence,
      source: e.source, relFile: e.relFile, line: e.line, lineIsAbsolute: e.lineIsAbsolute,
      preview: e.preview, guidance: trimGuidance(e.guidance),
    }));
    const reExposures = allReexposures.slice(0, maxEntries).map((e) => ({ ruleId: e.ruleId, preview: e.preview, count: e.count }));
    const droppedNew = Math.max(0, allNew.length - newFindings.length);
    const droppedReexp = Math.max(0, allReexposures.length - reExposures.length);
    const truncatedCount = droppedNew + droppedReexp;

    let summary;
    if (firstCheckThisSession && stats.loud === 0) {
      summary = "First check this session -- baseline established, watching from now on. This does not mean nothing is on disk; call residoo_scan for that.";
    } else if (stats.loud === 0 && stats.quiet === 0) {
      summary = "Nothing new since the last check.";
    } else {
      const bits = [];
      if (stats.loud > 0) bits.push(`${stats.loud} new finding(s)`);
      if (stats.quiet > 0) bits.push(`${stats.quiet} re-exposure(s) of already-known secrets`);
      summary = bits.join(", ") + " since your last check.";
    }

    return textResult({
      checkedAt: new Date().toISOString(),
      firstCheckThisSession,
      newFindings,
      reExposures,
      counts: { newFindings: stats.loud, reExposures: stats.quiet, suppressedByLedger: stats.suppressedByLedger },
      truncated: truncatedCount > 0,
      truncatedCount,
      summary,
    });
  }

  async function handleExplain(args) {
    const errs = rejectUnknownKeys(args, new Set(["ruleId"]));
    if (args.ruleId !== undefined && typeof args.ruleId !== "string") errs.push("ruleId must be a string");
    if (errs.length) return errorResult(`Invalid arguments: ${errs.join("; ")}`);

    if (args.ruleId === undefined) {
      const ruleIds = Object.keys(ROTATION_GUIDANCE).map((id) => ({ id, label: ROTATION_GUIDANCE[id].label }));
      return textResult({ ruleIds });
    }
    const known = Object.prototype.hasOwnProperty.call(ROTATION_GUIDANCE, args.ruleId);
    const g = guidanceFor(args.ruleId);
    return textResult({
      ruleId: args.ruleId, known, label: g.label,
      rotateUrl: g.rotateUrl || null, consolePath: g.consolePath || null,
      steps: g.steps, revokeNote: g.revokeNote, generic: g.generic === true,
    });
  }

  async function resolveTool(kind, args) {
    const errs = rejectUnknownKeys(args, new Set(["fingerprint", "note"]));
    if (typeof args.fingerprint !== "string") {
      errs.push("fingerprint is required and must be a string");
    } else if (!FINGERPRINT_PATTERN.test(args.fingerprint)) {
      errs.push("fingerprint must match ^rf1-[0-9a-f]{32}$ -- copy it verbatim from a prior residoo_scan/residoo_check result, never construct or guess one");
    }
    if (args.note !== undefined && typeof args.note !== "string") errs.push("note must be a string");
    if (typeof args.note === "string" && args.note.length > 2000) errs.push("note must be 2000 characters or fewer");
    if (errs.length) return errorResult(`Invalid arguments: ${errs.join("; ")}`);

    let entry;
    try {
      entry = kind === "ack" ? ackFinding(args.fingerprint, args.note) : dismissFinding(args.fingerprint, args.note);
    } catch (err) {
      return errorResult(`Failed to ${kind === "ack" ? "acknowledge" : "dismiss"} finding: ${err instanceof Error ? err.message : String(err)}`);
    }

    const warning = sessionSeenFingerprints.has(args.fingerprint)
      ? null
      : "This fingerprint was not returned by a residoo_scan or residoo_check call in this session -- it may not correspond to a real finding. Relay this warning rather than treating the response as proof it matched something real.";

    return textResult({
      fingerprint: entry.fingerprint, at: entry.at, note: entry.note || null,
      status: kind === "ack" ? "acked" : "dismissed", ledgerFile: entry.file, warning,
      summary: `${kind === "ack" ? "Acknowledged" : "Dismissed"} ${entry.fingerprint} at ${entry.at}.`,
    });
  }

  async function handleRunWithCred(args) {
    const errs = rejectUnknownKeys(args, new Set(["credentialName", "command", "args"]));
    if (typeof args.credentialName !== "string" || !args.credentialName) errs.push("credentialName is required and must be a string");
    if (typeof args.command !== "string" || !args.command) errs.push("command is required and must be a string");
    if (args.args !== undefined && (!Array.isArray(args.args) || !args.args.every((a) => typeof a === "string"))) {
      errs.push("args must be an array of strings");
    }
    if (errs.length) return errorResult(`Invalid arguments: ${errs.join("; ")}`);

    const r = runWithCredential({ credentialName: args.credentialName, command: args.command, args: args.args || [] });
    if (!r.ok) return errorResult(r.reason);
    return textResult({
      exitCode: r.exitCode, succeeded: r.succeeded, timedOut: r.timedOut,
      stdoutLineCount: r.stdoutLineCount, stderrLineCount: r.stderrLineCount,
      summary: r.timedOut
        ? "Command timed out and was killed. Command output is never returned, by design."
        : `Exit ${r.exitCode}, ${r.succeeded ? "succeeded" : "failed"}. Command output is never returned, by design.`,
    });
  }

  async function handleVerifyFinding(args) {
    const errs = rejectUnknownKeys(args, new Set(["fingerprint"]));
    if (typeof args.fingerprint !== "string") {
      errs.push("fingerprint is required and must be a string");
    } else if (!FINGERPRINT_PATTERN.test(args.fingerprint)) {
      errs.push("fingerprint must match ^rf1-[0-9a-f]{32}$ -- copy it verbatim from a prior residoo_scan/residoo_check result, never construct or guess one");
    }
    if (errs.length) return errorResult(`Invalid arguments: ${errs.join("; ")}`);

    const findEntry = async () => {
      const result = await scan({ sources, includeNoisy: true, includeSuppressed: true, verify: false, noColor: true });
      const rotation = renderRotation(result.findings, loadAcks(), loadDismissed());
      return rotation.entries.find((e) => e.fingerprint === args.fingerprint) || null;
    };

    const before = await findEntry();
    if (!before) {
      return textResult({
        fingerprint: args.fingerprint, found: false, verifiable: null, verified: null,
        summary: "No finding with this fingerprint is currently on disk. It may have been resolved, the source file may have changed since it was last seen, or you may need to call residoo_scan first to see current fingerprints.",
      });
    }
    if (!VERIFIABLE_RULE_IDS.has(before.ruleId)) {
      return textResult({
        fingerprint: args.fingerprint, found: true, ruleId: before.ruleId, verifiable: false, verified: null,
        summary: `residoo cannot live-verify a ${before.ruleId} credential yet. Paired credentials (AWS, PlanetScale, MongoDB Atlas) and credential types with no vendor whoami-style endpoint (JWTs, private keys, bearer tokens of unknown origin, connection strings) are not supported by this tool. Run "residoo scan --project <dir> --verify" from a terminal for AWS/PlanetScale/MongoDB Atlas pairs.`,
      });
    }

    // The actual network call: scoped so ONLY this one fingerprint's
    // credential is ever queued for verification inside scan() (see
    // verifyOnlyFingerprint in src/scan.js), regardless of how many other
    // verifiable credentials exist on this machine. This is the whole reason
    // this tool takes one fingerprint and not a list.
    const result = await scan({ sources, includeNoisy: true, includeSuppressed: true, verify: true, verifyOnlyFingerprint: args.fingerprint, noColor: true });
    const rotation = renderRotation(result.findings, loadAcks(), loadDismissed());
    const after = rotation.entries.find((e) => e.fingerprint === args.fingerprint);
    const checkedAt = new Date().toISOString();
    if (!after || after.verified == null) {
      return textResult({
        fingerprint: args.fingerprint, found: true, ruleId: before.ruleId, verifiable: true, verified: "unknown",
        checkedAt, summary: "The vendor check could not be completed (network error, timeout, or unexpected response). This does not mean the credential is inactive -- treat it as unverified, not as safe.",
      });
    }
    const verified = after.verified === "active" ? "active" : after.verified === "invalid" ? "invalid" : "unknown";
    const summary = verified === "active"
      ? `ACTIVE: this is a real, working credential. Rotate it. Checked ${checkedAt}.`
      : verified === "invalid"
        ? `Inactive: the vendor rejected it. Checked ${checkedAt}.`
        : `Could not verify${after.verifiedDetail ? `: ${after.verifiedDetail}` : ""}. Treat as unverified, not as safe. Checked ${checkedAt}.`;
    return textResult({
      fingerprint: args.fingerprint, found: true, ruleId: before.ruleId, verifiable: true, verified,
      verifiedDetail: after.verifiedDetail || null, checkedAt, summary,
    });
  }

  const tools = new Map();
  tools.set("residoo_scan", {
    name: "residoo_scan",
    description: "Run a fresh, read-only secret scan across every AI coding agent transcript store residoo knows about on this machine (or, if projectDir is given, across one project's committed agent artifacts -- transcripts, agent configs, .env files -- instead), merged with the local rotation ledger so each distinct finding also shows whether it is pending, already acknowledged as rotated, or dismissed as not a real secret. Performs real local disk reads only (can take a few seconds on a machine with many/large transcripts); makes zero network calls and modifies nothing. Every secret is always returned as a short redacted preview (first/last 4 characters) -- the raw value is never included anywhere in the response. Use this for 'do I have any leaked secrets right now' or 'give me the full current picture.' For 'what is new since I last checked in this conversation', call residoo_check instead -- it is much cheaper and only reports newly-appeared findings, not everything on disk.",
    inputSchema: {
      type: "object",
      properties: {
        projectDir: { type: "string", description: "Absolute path to a project/repo directory to scan instead of the machine-wide transcript stores (same as `residoo scan --project <dir>`). Omit for the default machine-wide scan." },
        includeNoisy: { type: "boolean", default: false, description: "Also run residoo's two low-confidence heuristic rules (generic password/secret assignments) -- catches more, false-positives more. Off by default." },
        includeSuppressed: { type: "boolean", default: false, description: "Include matches normally hidden because they look like vendor-documented example values or placeholder text. Off by default." },
        includePii: { type: "boolean", default: false, description: "Also scan for PII (US Social Security Numbers, Luhn-validated credit card numbers, checksum-validated IBANs) -- a different risk category from a credential, not a lower confidence bar. Off by default; residoo is deliberately credentials-only otherwise." },
        maxEntries: { type: "integer", minimum: 1, maximum: 200, default: 25, description: "Cap on distinct findings returned in full detail, pending-first. Counts in the response are always exact even when the entry list is truncated." },
      },
      required: [],
      additionalProperties: false,
    },
    handler: handleScan,
  });
  tools.set("residoo_check", {
    name: "residoo_check",
    description: "Report only what is NEW since the last time this tool was called in this conversation (or since the server started, on the first call). Backed by the same incremental engine as `residoo watch`, but called once per invocation instead of running continuously -- it tails newly-appended bytes and re-reads only files that changed, never a full disk crawl, so it is much cheaper than residoo_scan for a repeat check later in the same session. On the very FIRST call, it silently establishes a baseline and reports zero new findings by design -- this means 'watch just started,' not 'nothing is wrong'; the response's firstCheckThisSession field tells you which case you are in, and you should say so if it is true rather than implying a clean result. Call residoo_scan for a full picture of everything currently on disk. Never makes network calls, never modifies anything.",
    inputSchema: {
      type: "object",
      properties: {
        includeNoisy: { type: "boolean", default: false, description: "Same meaning as residoo_scan." },
        includeSuppressed: { type: "boolean", default: false, description: "Same meaning as residoo_scan." },
        includePii: { type: "boolean", default: false, description: "Same meaning as residoo_scan." },
        maxEntries: { type: "integer", minimum: 1, maximum: 200, default: 25, description: "Cap on new findings / re-exposures returned in full detail. Counts are always exact even when truncated." },
      },
      required: [],
      additionalProperties: false,
    },
    handler: handleCheck,
  });
  tools.set("residoo_explain", {
    name: "residoo_explain",
    description: "Look up residoo's rotation runbook for one detection rule id (e.g. github_pat, aws_access_key_id) -- what the credential is, where to rotate/revoke it in the vendor's console, and numbered steps. Pure local lookup against residoo's built-in guidance table; no network calls, no prior scan needed. Pass the exact ruleId from a finding returned by residoo_scan or residoo_check -- do not guess one. Omit ruleId to get the full list of every rule id residoo has guidance for with a one-line label each. If a rule id is not recognized, this still returns a response (never errors) -- an honest generic fallback with known: false.",
    inputSchema: {
      type: "object",
      properties: {
        ruleId: { type: "string", description: "A rule id from a prior finding's ruleId field. Omit to list every known rule id instead." },
      },
      required: [],
      additionalProperties: false,
    },
    handler: handleExplain,
  });
  tools.set("residoo_ack", {
    name: "residoo_ack",
    description: "Record that the credential behind one specific finding has been rotated. This ONLY appends an entry to residoo's local rotation ledger (~/.residoo/rotations.json) -- the same additive, non-destructive audit file `residoo ack` writes from a terminal. It never touches, edits, or deletes the transcript file the secret was found in, and it does not rotate or revoke the credential itself -- the human still has to go do that at the vendor; use residoo_explain first if they need the steps. fingerprint MUST be copied verbatim from a fingerprint field returned by a prior residoo_scan or residoo_check call in this conversation -- never construct, guess, or reformat one; it is a hash, not something you can compute. Acknowledging a fingerprint that does not match any real finding silently records a no-op entry rather than erroring, which is why the response includes a warning field when the fingerprint was not seen earlier this session -- relay that warning to the user rather than treating a clean-looking response as proof it matched something real. note is optional free text; it is sanitized and length-capped server-side, but treat it as logged and do not put an actual secret value in it.",
    inputSchema: {
      type: "object",
      properties: {
        fingerprint: { type: "string", pattern: "^rf1-[0-9a-f]{32}$", description: "Exact fingerprint string from a prior scan/check finding. Never invent one." },
        note: { type: "string", maxLength: 2000, description: "Optional note on how/when it was rotated. Server-side sanitization caps this further and redacts any accidental secret-shaped text." },
      },
      required: ["fingerprint"],
      additionalProperties: false,
    },
    handler: (args) => resolveTool("ack", args),
  });
  tools.set("residoo_dismiss", {
    name: "residoo_dismiss",
    description: "Record that one specific finding was reviewed and determined NOT to be a real secret (a test fixture, an already-dead example string, a vendor sample not on residoo's built-in suppression list) -- distinct from residoo_ack, which means a real credential was rotated. Same ledger, same fingerprint-must-come-from-a-prior-scan-or-check rule, same non-destructive guarantee (only appends to ~/.residoo/rotations.json; never touches the scanned file).",
    inputSchema: {
      type: "object",
      properties: {
        fingerprint: { type: "string", pattern: "^rf1-[0-9a-f]{32}$", description: "Exact fingerprint string from a prior scan/check finding. Never invent one." },
        note: { type: "string", maxLength: 2000, description: "Optional note on why it was dismissed. Server-side sanitization caps this further and redacts any accidental secret-shaped text." },
      },
      required: ["fingerprint"],
      additionalProperties: false,
    },
    handler: (args) => resolveTool("dismiss", args),
  });

  // Genuinely different from the 5 tools above: this one executes a real
  // command with a live credential injected as environment variables --
  // the first residoo MCP tool that is not purely detection/read-only. It
  // is dynamically OMITTED from this Map entirely (not merely filtered
  // from a tools/list response) when RESIDOO_CRED_ALLOWED_COMMANDS is
  // unset/empty or the OS keychain isn't available, so an unconfigured
  // server's tools/call on this name correctly 404s via src/mcp.js's
  // already-established -32602 "Unknown tool" path with zero new
  // dispatcher logic. This omission is a discovery/clutter reduction
  // ONLY -- the actual, sole security boundary is the fail-closed
  // allow-list check inside runWithCredential itself (src/credRun.js),
  // which must never be removed on the theory that this omission already
  // covers it. Matches the existing pattern of capturing state once per
  // server invocation (see `sources` above): an operator who changes the
  // allow-list while a server is already running needs to restart it.
  const { map: allowedCommands } = parseAllowedCommands(process.env.RESIDOO_CRED_ALLOWED_COMMANDS);
  if (allowedCommands.size > 0 && keychain.isSupported()) {
    tools.set("residoo_run_with_cred", {
      name: "residoo_run_with_cred",
      description: "Run ONE allow-listed command with ONE stored credential injected as environment variables -- you never see the raw value, before, during, or after. This is unlike every other residoo tool: it executes a real command, and that command (and anything IT spawns) can see the injected credential in its own environment for as long as it runs. `command` is a NAME looked up in an operator-configured allow-list (RESIDOO_CRED_ALLOWED_COMMANDS), never a path -- it can never cause any file other than an operator-pinned one to run, and this tool does not exist at all (you will not see it in the tool list) unless an operator has deliberately configured that allow-list outside this conversation. `credentialName` must be one you already know was set up with `residoo cred set` -- there is no way to list credential names from here. The command's own stdout/stderr content is NEVER returned, only exit status and line counts, because that output is itself a channel the injected secret could leak through. Never ask a human to paste a raw credential value into this conversation to use this tool -- credentials are entered directly into the OS keychain via `residoo cred set`, outside any conversation, specifically so no AI tool call ever sees them.",
      inputSchema: {
        type: "object",
        properties: {
          credentialName: { type: "string", description: "Name of a credential previously stored with `residoo cred set`. Not discoverable from here -- ask the user which name to use." },
          command: { type: "string", description: "A name from the operator's RESIDOO_CRED_ALLOWED_COMMANDS allow-list (e.g. \"aws\"), never a path. Rejected outright if it contains a path separator." },
          args: { type: "array", items: { type: "string" }, default: [], description: "Arguments passed to the command verbatim, as a structured list (never a shell string)." },
        },
        required: ["credentialName", "command"],
        additionalProperties: false,
      },
      handler: handleRunWithCred,
    });
  }

  // Genuinely different from residoo_scan/residoo_check even though it also
  // only reads local disk first: its SECOND step makes a real outbound
  // network request to the credential's own vendor, using the actual secret
  // value, to ask whether it still works. Nothing else in this file ever
  // leaves the machine. Dynamically OMITTED from this Map (same pattern as
  // residoo_run_with_cred above) unless RESIDOO_MCP_ALLOW_VERIFY is set to
  // "1" or "true" -- an operator must deliberately opt in, outside the
  // conversation, before this tool exists at all, so a default `residoo mcp`
  // install stays true to "zero network calls" without qualification. This
  // is a STRICTER gate than residoo_scan/residoo_check need, because giving
  // this its own clearly-named, clearly-described tool (rather than a
  // boolean flag buried on residoo_scan) only solves the discovery/approval-
  // prompt-legibility problem the original MCP design flagged -- it does not
  // by itself decide whether an autonomous model should ever be allowed to
  // trigger a real vendor API call with a real secret. That is the
  // operator's call, made once, outside any conversation.
  const mcpAllowVerify = process.env.RESIDOO_MCP_ALLOW_VERIFY === "1" || process.env.RESIDOO_MCP_ALLOW_VERIFY === "true";
  if (mcpAllowVerify) {
    tools.set("residoo_verify_finding", {
      name: "residoo_verify_finding",
      description: "Ask ONE credential's own vendor, live, whether it is still active -- unlike every other residoo tool, this makes a real outbound network request (e.g. to Slack's auth.test, GitHub's user endpoint) using the actual secret value found on disk. The raw value itself is still never returned to you, only the vendor's answer: active (a real, working credential -- rotate it), invalid (the vendor already rejected it), or unknown (the check failed or timed out -- treat this the same as active, not as reassurance). fingerprint MUST be copied verbatim from a fingerprint field returned by a prior residoo_scan or residoo_check call in this conversation -- never construct or guess one. Only single-token credential types are supported (Slack, GitHub, OpenAI, Anthropic, Stripe, and similar) -- paired credentials (AWS access key + secret, PlanetScale, MongoDB Atlas) return verifiable:false; use `residoo scan --verify` from a terminal for those. This tool only exists because an operator deliberately enabled it outside this conversation (RESIDOO_MCP_ALLOW_VERIFY) -- never ask a human to paste a raw credential value to use it; it already reads the value residoo found on disk.",
      inputSchema: {
        type: "object",
        properties: {
          fingerprint: { type: "string", pattern: "^rf1-[0-9a-f]{32}$", description: "Exact fingerprint string from a prior scan/check finding. Never invent one." },
        },
        required: ["fingerprint"],
        additionalProperties: false,
      },
      handler: handleVerifyFinding,
    });
  }

  return tools;
}

module.exports = { buildTools };
