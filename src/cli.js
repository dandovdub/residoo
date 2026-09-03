"use strict";

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { availableSources, ALL_SOURCES } = require("./sources");
const { scan, emptyResult } = require("./scan");
const { render, renderIntegrity, renderJson, renderSarif, makeProgressReporter, printIntro } = require("./report");
const { checkIntegrity } = require("./integrity");
const {
  ROTATION_GUIDANCE, guidanceFor, loadAcks, loadDismissed, ackFinding, dismissFinding, renderRotation,
} = require("./rotation");
const { startWatch, isTailable } = require("./watch");
const { startMcpServer } = require("./mcp");
const { buildTools } = require("./mcpTools");

/**
 * A source is unavailable for the ordinary reason (not installed — nothing
 * more to say) far more often than for a reason worth surfacing. A handful
 * of sources — the SQLite-backed ones gated on the built-in `node:sqlite`
 * module (cursor.js, crush.js, cody.js, devin-cli.js, hermes.js, kiro-cli.js,
 * llm.js, trae.js, void.js, warp.js, zed.js) — export the optional
 * `unavailableReason()` for the one case worth calling out: the tool IS
 * installed but this Node runtime is too old to read its database. Every
 * other source can safely omit this export entirely; this stays a no-op for
 * those rather than requiring every adapter to implement it.
 */
function sourceStatusLabel(source) {
  const reason = typeof source.unavailableReason === "function" ? source.unavailableReason() : null;
  return reason ? `${source.label()} (${reason})` : source.label();
}
function sourceStatusList() {
  return ALL_SOURCES.map(sourceStatusLabel).join(", ");
}

const HELP = `residoo: find secrets leaking through your AI agent's session history

  Coding agents (Claude Code, Cursor, Copilot, ...) write everything you do
  to a local transcript, including file contents your prompts touch. That
  means real credentials sitting in plaintext on disk, indefinitely, in a
  place nobody thinks to check. residoo scans those transcripts for them.

  A scan also runs integrity checks over agent config locations, the 2026
  supply-chain campaigns planted persistence exactly there: SessionStart
  hooks, dropper scripts, folder-open tasks, zero-width Unicode instructions
  hidden in memory/rules files. Every auto-executing hook found in the
  checked locations is listed for your review; only published campaign IOCs
  and campaign-shaped behaviors escalate to warnings.

  Every finding comes with a rotation hint: the vendor's real revocation
  path, verified against their docs, because a leaked key that is found but
  never rotated is still leaked (64% of leaked secrets stay valid for years).
  "residoo explain <rule-id>" prints the full runbook for one credential
  type; "residoo ack <fingerprint>" records that you rotated one, and
  "residoo dismiss <fingerprint>" records that you determined it was never a
  real secret (a test fixture, a vendor example not already recognized).
  Both are recorded in ~/.residoo/rotations.json, the only file residoo
  ever writes outside an explicit --seal.

  Scanning makes NO network calls by default and changes nothing on disk.
  Findings are redacted in every output format. The one opt-in exception is
  --verify, which asks a credential's own vendor whether it still
  authenticates (35 vendors today, see below). Sealing (--seal) writes NEW
  encrypted files only. It never modifies or deletes anything that already
  exists.

Usage:
  residoo scan [options]
  residoo explain <rule-id>   (or: residoo explain --list)
  residoo ack <fingerprint> [--note <text>]
  residoo dismiss <fingerprint> [--note <text>]
  residoo unseal <vault-dir> [--restore <n> --out <path>]

Scan options:
  --json                  machine-readable output (full detail, still redacted)
  --sarif                 SARIF 2.1.0 output (secret findings only), for
                          GitHub code scanning's Security tab and inline PR
                          annotations. Use --json for the full picture
                          (findings + integrity + rotation) instead.
  --project [dir]         scan a repository checkout instead of this machine
                          (default dir: current directory). Covers committed
                          agent transcripts, agent config/rules files, and
                          root-level .env files inside the checkout, plus
                          integrity checks anchored at that directory. The
                          home-level transcript and config sources are NOT
                          scanned in this mode, deliberately: in CI they
                          would scan the runner's home and say nothing about
                          the repo, and a clean project scan must never be
                          mistaken for a clean machine. Run residoo scan
                          without --project for the machine itself.
  --include-noisy         also run broad, false-positive-prone rules
  --include-suppressed    also show matches that looked like placeholder/example text
  --fail-on-find          exit code 1 if anything is found (for CI): secret
                          findings and integrity WARNINGS count; integrity
                          info-level review items do not
  --allow-acked           with --fail-on-find: findings whose fingerprint was
                          acknowledged via "residoo ack" OR dismissed via
                          "residoo dismiss" no longer fail the run; pending
                          findings and integrity warnings still do. Without
                          this flag, --fail-on-find fails on every finding,
                          acked, dismissed, or not.
  --no-integrity          skip the integrity checks (planted hooks, dropper
                          files, auto-run tasks, hidden Unicode)
  --no-color              disable ANSI colour
  --verify                ask the credential's own vendor whether it still
                          authenticates, using the exact value found in
                          your transcript. THIS MAKES A REAL NETWORK CALL.
                          Off by default. 35 vendors today. Three need a
                          paired id+secret (see Rotation below): AWS,
                          checked via sts:get-caller-identity (needs the
                          aws CLI on PATH, residoo shells out to it rather
                          than reimplementing AWS request signing);
                          PlanetScale and MongoDB Atlas (Service Account
                          credentials only), each checked via a direct API
                          call like every other non-AWS vendor here. The
                          other 32 are each a single credential, one
                          direct, dependency-free API call, no CLI needed:
                          Slack, OpenAI, Anthropic, GitHub, Hugging Face,
                          Replicate, DigitalOcean, Pinecone, SendGrid,
                          Groq, xAI, OpenRouter, Stripe, npm, Notion,
                          GitLab, Supabase (management tokens only),
                          ElevenLabs, CircleCI, Airtable, Cloudflare,
                          Heroku, Netlify, Linear, Telegram, Discord
                          webhooks, Vercel, Cerebras, Render, Fly.io,
                          Neon, and PostHog.
                          A verified-invalid credential is reported as
                          already dead, not as something to rotate; a
                          JWT's own signed exp claim is checked locally
                          with no network call at all, on by default, not
                          part of --verify.

Watch:
  residoo watch            continuous scanning instead of one snapshot:
                          alerts the moment a new secret lands in a
                          transcript, instead of waiting for the next
                          "residoo scan". Covers the same sources as scan;
                          run scan first for anything already on disk,
                          since watch only ever looks at content written
                          AFTER it starts. No other tool in this project's
                          own benchmark (bench/) has anything like it.
  --interval <seconds>   how often to check for new content (default 5,
                          minimum 1)
  --json                  NDJSON events on stdout instead of plain text,
                          one line per finding/re-exposure
  --verify                same opt-in vendor check as scan --verify,
                          applied to each newly found credential once,
                          never to one already seen
  --include-noisy, --include-suppressed, --no-color   same meaning as scan
  Ctrl+C stops cleanly and prints a session summary (skipped with --json,
  where the same information is one final NDJSON event).

MCP:
  residoo mcp              run residoo as an MCP server over stdio, so
                          Claude Code (or any other MCP client) can query
                          findings and manage rotation conversationally
                          instead of a human running the CLI. No network
                          calls, nothing destructive: the 5 exposed tools
                          (residoo_scan, residoo_check, residoo_explain,
                          residoo_ack, residoo_dismiss) mirror scan/watch/
                          explain/ack/dismiss exactly, and every value
                          returned is redacted the same way. Register it
                          with "claude mcp add residoo -- residoo mcp".
                          Zero runtime dependencies: the protocol is hand-
                          rolled, not the official SDK.

Cred:
  residoo cred set <name> --env <ENV_VAR_NAME> [--env <ENV_VAR_NAME_2> ...]
                          store a live credential in the OS keychain
                          (macOS/Linux only), one or more env-var names
                          mapped to hidden-typed values. Interactive TTY
                          only, no scripted entry: a live credential is
                          more sensitive than a vault passphrase and
                          should never be typeable into a script or env
                          var visible elsewhere.
  residoo cred remove <name>   delete a stored credential
  residoo cred run <name> -- <command> [args...]
                          run one ALLOW-LISTED command with that
                          credential injected as environment variables.
                          <command> is a name looked up in
                          RESIDOO_CRED_ALLOWED_COMMANDS
                          ("name=/absolute/path,..."), never a path
                          itself; unset/empty means nothing may run, by
                          design. Command output is never shown, only
                          exit status and line counts, since the
                          command's own output is a channel the injected
                          secret could otherwise leak through. See the
                          README for the full safety rationale, including
                          why some allow-listed tools (anything with a
                          plugin/extension system, e.g. gh) still carry
                          residual risk.
  residoo mcp exposes the same operation as the residoo_run_with_cred
  tool, present only when RESIDOO_CRED_ALLOWED_COMMANDS is configured.

Rotation:
  residoo explain <rule-id>     full rotation runbook for one detection rule
                                (where to revoke, steps, what revocation does)
  residoo explain --list        every rule id with its credential label
  residoo ack <fingerprint>     mark one finding's rotation done; fingerprints
                                appear next to findings in the report and in
                                --json. Optional --note <text> is stored with
                                the acknowledgement (redacted if it matches a
                                secret pattern).
  residoo dismiss <fingerprint> mark one finding as reviewed and NOT a real
                                secret (a test fixture, a vendor example not
                                already recognized, etc.), distinct from ack:
                                nothing was rotated, there was nothing to
                                rotate. Same --note handling as ack.

Seal options (used with scan):
  --seal                  after scanning, encrypt every transcript that carried a
                          finding into a local vault directory (AES-256-GCM,
                          passphrase-derived key; originals are left untouched)
  --keychain              with --seal (or unseal): use a truly random key stored
                          in the OS keychain instead of a typed passphrase.
                          Nothing to remember, and the key's strength no longer
                          depends on passphrase choice. macOS today; Linux when
                          secret-tool (libsecret) is installed. TRADEOFF: a
                          keychain-backed vault lives on THIS machine/account
                          only, unlike a passphrase, it is not portable to
                          another machine.
  --vault-dir <dir>       where to create the vault (default: ./residoo-vault-<stamp>)
  --upload-cloudroam      ALSO upload the sealed vault to CloudRoam. One of two
                          opt-in features that touch the network (--verify
                          above is the other); off unless you pass it, and
                          only ciphertext is sent. Needs CLOUDROAM_API_KEY
                          (env) plus:
  --connector <id>        CloudRoam connector id for the destination
  --bucket <name>         destination bucket
  --prefix <p>            optional key prefix inside the bucket

Unseal:
  residoo unseal <vault-dir>                      list the vault's contents
  residoo unseal <vault-dir> --restore 0001.sealed --out file.jsonl
                                                  restore one entry, verified
                                                  byte-identical via its
                                                  recorded SHA-256
  --keychain              add to either unseal form above: retrieve the vault
                          key from the OS keychain instead of prompting for a
                          passphrase. Only works for a vault that was sealed
                          with --keychain on this same machine/account.

The passphrase is read from RESIDOO_PASSPHRASE, or prompted (hidden) on a TTY.

Sources checked on this machine: ${sourceStatusList()}
`;

function argValue(args, flag) {
  const i = args.indexOf(flag);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : null;
}

/** Every value of a flag that may be repeated (e.g. multiple --env), in order given. */
function argValues(args, flag) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === flag && i + 1 < args.length) out.push(args[i + 1]);
  }
  return out;
}

async function getPassphrase({ confirmNew }) {
  const { promptHidden } = require("./prompt");
  const p1 = await promptHidden("Vault passphrase (input hidden): ");
  if (!p1 || p1.length < 8) throw new Error("Passphrase must be at least 8 characters.");
  if (confirmNew && !process.env.RESIDOO_PASSPHRASE) {
    const p2 = await promptHidden("Repeat passphrase: ");
    if (p1 !== p2) throw new Error("Passphrases did not match.");
  }
  return p1;
}

/**
 * The sealing secret for `scan --seal`: a keychain-generated random key (see
 * keychain.js), or a typed passphrase. `vaultId` is null in passphrase mode;
 * in keychain mode the caller writes it to `.keychain-id` inside the vault
 * once sealFindings has created the directory, so unseal can find it again.
 * The generated secret is passed straight through to the SAME
 * sealFindings/deriveKey path a typed passphrase would use — scrypt on a
 * full 256-bit-entropy input is harmless extra defense, and reusing that
 * already-tested path means no change to sealcrypto.js/sealvault.js at all.
 */
async function resolveSealSecret(args) {
  if (!args.includes("--keychain")) {
    return { passphrase: await getPassphrase({ confirmNew: true }), vaultId: null };
  }
  const keychain = require("./keychain");
  if (!keychain.isSupported()) throw new Error(`--keychain: ${keychain.unsupportedReason()}`);
  const vaultId = crypto.randomUUID();
  const passphrase = crypto.randomBytes(32).toString("base64");
  keychain.store(vaultId, passphrase);
  return { passphrase, vaultId };
}

/** The unsealing secret for `unseal`: a keychain-retrieved key, or a typed passphrase. */
async function resolveUnsealSecret(args, vaultDir) {
  if (!args.includes("--keychain")) return getPassphrase({ confirmNew: false });
  const keychain = require("./keychain");
  if (!keychain.isSupported()) throw new Error(`--keychain: ${keychain.unsupportedReason()}`);
  const idPath = path.join(vaultDir, ".keychain-id");
  if (!fs.existsSync(idPath)) {
    throw new Error(
      `No .keychain-id marker in ${vaultDir}: this vault was not sealed with --keychain, ` +
      `or the marker file was moved separately from the vault. Try unsealing without --keychain.`
    );
  }
  const vaultId = fs.readFileSync(idPath, "utf-8").trim();
  try {
    return keychain.retrieve(vaultId);
  } catch {
    throw new Error(
      "Could not retrieve this vault's key from the OS keychain. It may have been removed, " +
      "or this may be a different machine/account than the one that sealed it: a keychain-backed " +
      "vault is not portable across machines."
    );
  }
}

async function runSeal(result, args) {
  const { sealFindings, uploadVaultToCloudRoam } = require("./sealvault");

  const filesWithFindings = [...new Set(result.findings.map((f) => f.file))];
  if (filesWithFindings.length === 0) {
    process.stdout.write("Nothing to seal: no findings.\n");
    return 0;
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const vaultDir = argValue(args, "--vault-dir") || path.resolve(`residoo-vault-${stamp}`);
  const { passphrase, vaultId } = await resolveSealSecret(args);

  process.stdout.write(`\nSealing ${filesWithFindings.length} file(s) with findings into ${vaultDir}\n`);
  const { entries } = await sealFindings({
    files: filesWithFindings, vaultDir, passphrase,
    log: (s) => process.stdout.write(s + "\n"),
  });
  // Written only after sealFindings has created vaultDir. Plaintext, but
  // holds nothing sensitive: a random id with no meaning outside this
  // keychain lookup, never the key itself and never anything about what the
  // vault contains.
  if (vaultId) fs.writeFileSync(path.join(vaultDir, ".keychain-id"), vaultId, { mode: 0o600 });
  const totalPlain = entries.reduce((s, e) => s + e.plainBytes, 0);
  const totalSealed = entries.reduce((s, e) => s + e.sealedBytes, 0);
  process.stdout.write(
    `\nSealed ${entries.length} file(s): ${(totalPlain / 1024 / 1024).toFixed(1)}MB plain -> ` +
    `${(totalSealed / 1024 / 1024).toFixed(1)}MB encrypted.\n` +
    `Originals were NOT touched. Once you've verified a restore works\n` +
    `(residoo unseal ${path.basename(vaultDir)}${vaultId ? " --keychain" : ""} --restore 0001.sealed --out /tmp/check), removing the\n` +
    `plaintext originals is your call; residoo never deletes anything itself.\n` +
    (vaultId ? `The vault key is stored in the OS keychain, never typed, never written in plaintext to disk.\n` : "")
  );

  if (args.includes("--upload-cloudroam")) {
    const apiKey = process.env.CLOUDROAM_API_KEY;
    const connectorId = argValue(args, "--connector");
    const bucket = argValue(args, "--bucket");
    if (!apiKey || !connectorId || !bucket) {
      process.stderr.write("--upload-cloudroam needs CLOUDROAM_API_KEY (env), --connector and --bucket.\n");
      return 2;
    }
    process.stdout.write(`\nUploading sealed vault to CloudRoam (${bucket}), ciphertext only:\n`);
    const uploaded = await uploadVaultToCloudRoam({
      vaultDir,
      baseUrl: process.env.CLOUDROAM_BASE_URL || "https://cloudroam.io",
      apiKey, connectorId, bucket,
      prefix: argValue(args, "--prefix") || "",
      log: (s) => process.stdout.write(s + "\n"),
    });
    process.stdout.write(`Uploaded ${uploaded.length} object(s). The local vault remains at ${vaultDir}.\n`);
  }
  return 0;
}

async function runUnseal(args) {
  const { openManifest, restoreEntry } = require("./sealvault");
  const vaultDir = args[1];
  if (!vaultDir) { process.stderr.write("usage: residoo unseal <vault-dir> [--restore <n> --out <path>]\n"); return 2; }

  const passphrase = await resolveUnsealSecret(args, vaultDir);
  let manifest;
  try {
    manifest = openManifest(vaultDir, passphrase);
  } catch {
    process.stderr.write("Could not open vault: wrong passphrase, or the vault is corrupted.\n");
    return 1;
  }

  const restoreName = argValue(args, "--restore");
  if (!restoreName) {
    process.stdout.write(`Vault contents (${manifest.entries.length} sealed file(s)):\n`);
    for (const e of manifest.entries) {
      process.stdout.write(`  ${e.n}  ${(e.plainBytes / 1024 / 1024).toFixed(1).padStart(8)}MB  ${e.origPath}\n`);
    }
    return 0;
  }

  const entry = manifest.entries.find((e) => e.n === restoreName);
  if (!entry) { process.stderr.write(`No entry "${restoreName}" in this vault.\n`); return 2; }
  const out = argValue(args, "--out");
  if (!out) { process.stderr.write("--restore needs --out <path>.\n"); return 2; }

  const { ok, plainBytes } = await restoreEntry(vaultDir, entry, out, passphrase);
  if (ok) {
    process.stdout.write(`Restored ${entry.n} -> ${out} (${(plainBytes / 1024 / 1024).toFixed(1)}MB), ` +
      `verified byte-identical to the original (SHA-256 match).\n`);
    return 0;
  }
  process.stderr.write(`Restored, but verification FAILED: content does not match what was sealed. Do not trust this copy.\n`);
  return 1;
}

/**
 * Full rotation runbook for one rule id, or the whole catalogue via --list.
 * Prints for a HUMAN about to revoke a credential, so it stays plain text
 * and never assumes the finding is still on screen.
 */
function runExplain(args) {
  const ids = Object.keys(ROTATION_GUIDANCE);
  const ruleId = args[1] && !args[1].startsWith("--") ? args[1] : null;

  if (args.includes("--list") || ruleId === null) {
    process.stdout.write("Rotation runbooks available (residoo explain <rule-id>):\n");
    const width = Math.max(...ids.map((i) => i.length)) + 2;
    for (const id of ids) {
      process.stdout.write(`  ${id.padEnd(width)}${ROTATION_GUIDANCE[id].label}\n`);
    }
    return 0;
  }

  const known = Object.prototype.hasOwnProperty.call(ROTATION_GUIDANCE, ruleId);
  const g = guidanceFor(ruleId);
  const out = [];
  out.push(`${g.label} (rule: ${ruleId})`);
  if (g.rotateUrl) out.push(`  rotate/revoke docs: ${g.rotateUrl}`);
  if (g.consolePath) out.push(`  where: ${g.consolePath}`);
  out.push("  steps:");
  g.steps.forEach((s, i) => out.push(`    ${i + 1}. ${s}`));
  out.push(`  note: ${g.revokeNote}`);
  if (g.generic) {
    out.push("  (generic guidance: this rule matches a shape, not a single vendor,");
    out.push("   so the issuing service has to be identified from the finding's context)");
  }
  process.stdout.write(out.join("\n") + "\n");
  if (!known) {
    process.stderr.write(`residoo: "${ruleId}" is not a known rule id; the guidance above is the generic fallback. residoo explain --list shows every known id.\n`);
    return 2;
  }
  return 0;
}

/**
 * Record that one finding's credential was rotated. Takes the fingerprint
 * exactly as the report and --json print it; acks change what the report
 * SAYS (pending vs acknowledged) but never what --fail-on-find DOES unless
 * --allow-acked is also passed to the scan, which keeps a CI gate honest by
 * default.
 */
function runAck(args) {
  const fp = args[1] && !args[1].startsWith("--") ? args[1] : null;
  if (!fp) {
    process.stderr.write("usage: residoo ack <fingerprint> [--note <text>]\n" +
      "Fingerprints (rf1-...) are shown next to findings in the scan report and in --json.\n");
    return 2;
  }
  let res;
  try {
    res = ackFinding(fp, argValue(args, "--note"));
  } catch (err) {
    process.stderr.write(`residoo: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }
  process.stdout.write(
    `Acknowledged ${res.fingerprint} at ${res.at}` +
    (res.note ? ` with note: ${res.note}` : "") + "\n" +
    "The next scan reports this finding as acknowledged. It still counts toward\n" +
    "--fail-on-find unless the scan is run with --allow-acked.\n" +
    "(ack is stateless: it cannot check this fingerprint against a scan, so a\n" +
    "mistyped one is recorded too; the intended finding would then still show\n" +
    "as pending on the next scan.)\n"
  );
  return 0;
}

/**
 * Record that one finding was reviewed and determined NOT to be a real
 * secret (a test fixture, a value used to verify residoo's own detection,
 * a vendor example not already on the built-in suppression list, etc.) —
 * distinct from `ack`, which means "I rotated a real credential." Without
 * this, the only way to stop a confirmed-fake finding from reappearing
 * every scan was to `ack` it, which is semantically wrong (nothing was
 * rotated) and reads misleadingly in the rotation ledger.
 */
function runDismiss(args) {
  const fp = args[1] && !args[1].startsWith("--") ? args[1] : null;
  if (!fp) {
    process.stderr.write("usage: residoo dismiss <fingerprint> [--note <text>]\n" +
      "Fingerprints (rf1-...) are shown next to findings in the scan report and in --json.\n");
    return 2;
  }
  let res;
  try {
    res = dismissFinding(fp, argValue(args, "--note"));
  } catch (err) {
    process.stderr.write(`residoo: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }
  process.stdout.write(
    `Dismissed ${res.fingerprint} at ${res.at}` +
    (res.note ? ` with note: ${res.note}` : "") + "\n" +
    "The next scan reports this finding as dismissed instead of pending, and it is\n" +
    "excluded from --fail-on-find the same way an acked finding is with --allow-acked.\n" +
    "(dismiss is stateless, same as ack: it cannot check this fingerprint against a\n" +
    "scan, so a mistyped one is recorded too; the intended finding would then still\n" +
    "show as pending on the next scan.)\n"
  );
  return 0;
}

/**
 * One pass over each source's files() purely to describe what's about to
 * be watched -- how many files will be tailed (byte-offset, only new
 * content ever read) versus polled (whole-file rescan on any change). A
 * separate, cheap enumeration from the watch itself; not wired into
 * startWatch() so a banner-rendering concern never has to live inside the
 * engine.
 */
function printWatchBanner(sources) {
  process.stderr.write("residoo watch: establishing a baseline over each source (this covers NEW content only -- run `residoo scan` first for anything already on disk)...\n");
  for (const source of sources) {
    let tail = 0, rescan = 0;
    try {
      for (const entry of source.files()) {
        if (entry.broken) continue;
        if (isTailable(entry.file)) tail++; else rescan++;
      }
    } catch {
      // A source erroring while just being counted for the banner is not
      // fatal to the watch itself -- sweepOnce has its own try/catch
      // around files() and reports it there instead.
    }
    const parts = [];
    if (tail) parts.push(`${tail} tailed`);
    if (rescan) parts.push(`${rescan} polled (rescanned on change)`);
    process.stderr.write(`  ${source.label()} (${source.id()}): ${parts.join(", ") || "no files yet"}\n`);
  }
  process.stderr.write(
    "fs.watch is not used; every alert comes from polling, so an alert can lag\n" +
    "up to one --interval behind the actual write. SQLite-backed sources are\n" +
    "always polled in full (no incremental read exists for them). Ctrl+C to stop.\n\n"
  );
}

function printWatchSummary(stats) {
  process.stderr.write(
    `\nresidoo watch: stopped. ${stats.sweeps} sweep${stats.sweeps === 1 ? "" : "s"}, ` +
    `${stats.loud} new finding${stats.loud === 1 ? "" : "s"}, ${stats.quiet} re-exposure${stats.quiet === 1 ? "" : "s"}` +
    (stats.suppressedByLedger ? `, ${stats.suppressedByLedger} already acked or dismissed` : "") +
    (stats.errors ? `, ${stats.errors} sweep error${stats.errors === 1 ? "" : "s"}` : "") + ".\n"
  );
}

/**
 * `residoo watch`: continuous scanning instead of one snapshot. See
 * src/watch.js for the engine; this function is only argument parsing,
 * the startup/shutdown banners, and wiring SIGINT/SIGTERM to a clean stop.
 */
async function runWatch(args) {
  const wantsJson = args.includes("--json");
  const includeNoisy = args.includes("--include-noisy");
  const includeSuppressed = args.includes("--include-suppressed");
  const verify = args.includes("--verify");
  const noColor = args.includes("--no-color");

  let intervalSeconds = 5;
  const intervalArg = argValue(args, "--interval");
  if (intervalArg !== null) {
    const n = Number(intervalArg);
    if (!Number.isFinite(n) || n < 1) {
      process.stderr.write(`--interval must be a number of seconds, at least 1; got "${intervalArg}".\n`);
      return 2;
    }
    intervalSeconds = n;
  }

  const sources = availableSources();
  if (sources.length === 0) {
    process.stderr.write(
      "No known transcript sources found on this machine; nothing to watch.\n" +
      `Checked: ${sourceStatusList()}.\n`
    );
    return 0;
  }

  if (!wantsJson) printWatchBanner(sources);

  const { promise, stop } = startWatch({
    sources,
    options: { includeNoisy, includeSuppressed, verify, noColor, json: wantsJson, pollMs: intervalSeconds * 1000 },
  });

  const printFinalSummary = (stats) => {
    if (wantsJson) process.stdout.write(JSON.stringify({ type: "summary", at: new Date(), ...stats }) + "\n");
    else printWatchSummary(stats);
  };

  // A second Ctrl+C must not hang waiting on a graceful stop that already
  // started -- stop() itself is idempotent, but the listener only needs to
  // act once.
  let signalled = false;
  const onSignal = () => {
    if (signalled) return;
    signalled = true;
    printFinalSummary(stop());
  };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);

  const stats = await promise;
  process.removeListener("SIGINT", onSignal);
  process.removeListener("SIGTERM", onSignal);
  // promise can also resolve because something ELSE called stop() (not
  // possible from outside this function today, but the contract allows
  // it) -- print the summary exactly once regardless of which path got here.
  if (!signalled) printFinalSummary(stats);
  return 0;
}

/**
 * `residoo mcp`: run residoo as an MCP server over stdio. See src/mcp.js
 * for the protocol engine and src/mcpTools.js for the tool catalog; this
 * function is only the startup banner (stderr only -- see mcp.js's own
 * doc comment on why stdout must never carry anything but protocol
 * messages) and wiring SIGINT/SIGTERM to a clean stop, mirroring runWatch.
 */
async function runMcp(args) {
  const { version } = require("../package.json");
  const sources = availableSources();
  process.stderr.write(
    sources.length
      ? `residoo mcp: ${sources.length} source(s) available on this machine: ${sources.map((s) => s.label()).join(", ")}\n`
      : `residoo mcp: no known transcript sources found on this machine (residoo_scan will report none until one is installed and residoo mcp is restarted).\n`
  );
  process.stderr.write("residoo mcp: ready. Waiting for a client on stdin...\n");

  const { promise, stop } = startMcpServer({
    tools: buildTools({ sources }),
    serverInfo: { name: "residoo", version },
    instructions: "Find secrets leaking through this machine's AI coding agent session histories. All tool output is redacted; raw secret values are never returned. Nothing here is destructive: scanning is read-only, and ack/dismiss only append to a local audit ledger.",
  });

  let signalled = false;
  const onSignal = () => {
    if (signalled) return;
    signalled = true;
    stop();
  };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);

  await promise;
  process.removeListener("SIGINT", onSignal);
  process.removeListener("SIGTERM", onSignal);
  return 0;
}

/**
 * `residoo cred`: store a live, reusable credential in the OS keychain and
 * run an allow-listed command with it injected as environment variables,
 * without the value ever touching disk, argv, or a scripted env var. See
 * src/credRun.js's own doc comment for the full threat model. Genuinely
 * different from every other residoo command: it is the one place this
 * project stores something meant to be reused, and the one place it
 * executes a command residoo did not itself choose the identity of.
 */
async function runCred(args) {
  const sub = args[1];
  if (sub === "set") return runCredSet(args.slice(2));
  if (sub === "remove") return runCredRemove(args.slice(2));
  if (sub === "run") return runCredRun(args.slice(2));
  process.stderr.write(
    "usage: residoo cred set <name> --env <ENV_VAR_NAME> [--env <ENV_VAR_NAME_2> ...]\n" +
    "       residoo cred remove <name>\n" +
    "       residoo cred run <name> -- <command> [args...]\n"
  );
  return 2;
}

async function runCredSet(args) {
  const name = args[0] && !args[0].startsWith("--") ? args[0] : null;
  if (!name) {
    process.stderr.write("usage: residoo cred set <name> --env <ENV_VAR_NAME> [--env <ENV_VAR_NAME_2> ...]\n");
    return 2;
  }
  const envNames = argValues(args, "--env");
  if (envNames.length === 0) {
    process.stderr.write("residoo cred set: at least one --env <ENV_VAR_NAME> is required.\n");
    return 2;
  }
  const seen = new Set();
  for (const n of envNames) {
    if (seen.has(n)) {
      process.stderr.write(`residoo cred set: --env "${n}" was given more than once.\n`);
      return 2;
    }
    seen.add(n);
  }

  const keychain = require("./keychain");
  if (!keychain.isSupported()) {
    process.stderr.write(`residoo cred: ${keychain.unsupportedReason()}\n`);
    return 2;
  }

  // allowEnvFallback: false is the whole point here -- RESIDOO_PASSPHRASE
  // is for a vault passphrase, a different secret entirely; if it were
  // consulted, every --env prompt below would silently short-circuit to
  // that SAME value for anyone who has it set. This also means, by
  // design, there is no scripted/CI way to enter a credential value: a
  // live, reusable credential is more sensitive than a vault passphrase
  // and should never be typeable into a script or env var visible
  // elsewhere. residoo cred set requires a real interactive TTY.
  const { promptHidden } = require("./prompt");
  const envVars = [];
  for (const envName of envNames) {
    let value;
    try {
      value = await promptHidden(`Value for ${envName} (input hidden): `, { allowEnvFallback: false });
    } catch (err) {
      process.stderr.write(`residoo cred set: ${err instanceof Error ? err.message : String(err)}\n`);
      return 2;
    }
    if (!value) {
      process.stderr.write(`residoo cred set: no value entered for ${envName}.\n`);
      return 2;
    }
    envVars.push({ name: envName, value });
  }

  keychain.store(name, JSON.stringify({ envVars }), null, keychain.CRED_SERVICE);
  process.stdout.write(
    `Stored credential "${name}" (${envVars.length} env var${envVars.length === 1 ? "" : "s"}: ${envNames.join(", ")}).\n` +
    "To use it: set RESIDOO_CRED_ALLOWED_COMMANDS (see \"residoo cred run --help\" or the README),\n" +
    `then run "residoo cred run ${name} -- <allow-listed-command> [args...]".\n`
  );
  return 0;
}

function runCredRemove(args) {
  const name = args[0] && !args[0].startsWith("--") ? args[0] : null;
  if (!name) {
    process.stderr.write("usage: residoo cred remove <name>\n");
    return 2;
  }
  const keychain = require("./keychain");
  if (!keychain.isSupported()) {
    process.stderr.write(`residoo cred: ${keychain.unsupportedReason()}\n`);
    return 2;
  }
  try {
    keychain.remove(name, null, keychain.CRED_SERVICE);
  } catch (err) {
    process.stderr.write(`residoo cred remove: "${name}" ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }
  process.stdout.write(`Removed credential "${name}".\n`);
  return 0;
}

function runCredRun(args) {
  const name = args[0] && !args[0].startsWith("--") ? args[0] : null;
  const sepIdx = args.indexOf("--");
  if (!name || sepIdx < 0 || sepIdx + 1 >= args.length) {
    process.stderr.write(
      "usage: residoo cred run <name> -- <command> [args...]\n" +
      "<command> must be a name from RESIDOO_CRED_ALLOWED_COMMANDS (e.g. \"aws\"),\n" +
      "not a path -- see the README for the allow-list format and its safety rationale.\n"
    );
    return 2;
  }
  const [command, ...cmdArgs] = args.slice(sepIdx + 1);
  const { runWithCredential } = require("./credRun");
  const r = runWithCredential({ credentialName: name, command, args: cmdArgs });
  if (!r.ok) {
    process.stderr.write(`residoo cred run: ${r.reason}\n`);
    return 2;
  }
  process.stdout.write(
    `${r.timedOut ? "TIMED OUT" : `exit ${r.exitCode}`} (${r.succeeded ? "succeeded" : "failed"}). ` +
    `stdout: ${r.stdoutLineCount} line(s), stderr: ${r.stderrLineCount} line(s).\n` +
    "Command output is never shown by design -- see the README for why.\n"
  );
  return r.succeeded ? 0 : 1;
}

async function main(argv) {
  const args = argv.slice(2);
  if (args.includes("-h") || args.includes("--help") || args.length === 0) {
    process.stdout.write(HELP);
    return 0;
  }

  const cmd = args[0];
  if (cmd === "unseal") return runUnseal(args);
  if (cmd === "explain") return runExplain(args);
  if (cmd === "ack") return runAck(args);
  if (cmd === "dismiss") return runDismiss(args);
  if (cmd === "watch") return runWatch(args);
  if (cmd === "mcp") return runMcp(args);
  if (cmd === "cred") return runCred(args);
  if (cmd !== "scan") {
    process.stderr.write(`Unknown command "${cmd}". Try "residoo --help".\n`);
    return 2;
  }

  const wantsJson = args.includes("--json");
  const wantsSarif = args.includes("--sarif");
  const includeNoisy = args.includes("--include-noisy");
  const includeSuppressed = args.includes("--include-suppressed");
  const failOnFind = args.includes("--fail-on-find");
  const allowAcked = args.includes("--allow-acked");
  // The one flag that makes residoo do something other than read local
  // files: --verify asks the credential's own vendor whether it still
  // authenticates, for every vendor residoo knows how to check today (AWS
  // access key + paired secret via the aws CLI, Slack tokens via a direct
  // API call; see verify.js). Off by default; every other flag here only
  // changes what is READ or how it is DISPLAYED.
  const verify = args.includes("--verify");

  // --project [dir]: the dir is optional (CI passes ".", a bare --project
  // means the current directory). null means machine mode.
  let projectRoot = null;
  const projectIdx = args.indexOf("--project");
  if (projectIdx >= 0) {
    const next = args[projectIdx + 1];
    projectRoot = path.resolve(next && !next.startsWith("--") ? next : ".");
  }
  // Passed through explicitly to render() rather than mutating
  // process.env.NO_COLOR — main() is an exported function a host process can
  // legitimately call more than once (a wrapper CLI, a test runner), and a
  // mutated env var would leak past this one invocation and silently kill
  // color for a later call that never asked for that.
  const noColor = args.includes("--no-color");
  printIntro(noColor);

  // Integrity runs by default: a scan that reports "no secrets leaked" while
  // a planted SessionStart hook sits ready to re-leak them next session is
  // an incomplete answer. Only warn-severity findings (verified campaign
  // signatures, unverifiable configs) gate --fail-on-find — info items are
  // the user's own hooks listed for review, and failing CI on those would
  // train people to pass --no-integrity, which is worse than not checking.
  const wantsIntegrity = !args.includes("--no-integrity");
  const integrityWarnCount = (integ) =>
    integ ? integ.findings.filter((f) => f.severity === "warn").length : 0;
  // The integrity checker's inputs are, by its own threat model, attacker-
  // plantable files — a hostile config must not be able to suppress the
  // secrets report by crashing the checker after the scan already ran. A
  // throw degrades to a warn-severity finding: the run stays alive, the
  // failure stays loud (it still gates --fail-on-find), and it is never a
  // silent all-clear.
  // In project mode both anchors point at the project root: the transcript
  // sources are already project-only, and letting the integrity pass read the
  // invoking machine's home would fail a CI/pre-commit run on a developer's
  // own home-level hooks — a verdict about the wrong thing. The root's own
  // .claude/, .gemini/, .cursor/, .vscode/, CLAUDE.md and .cursorrules are
  // exactly the committed plant sites the campaigns used.
  const runIntegrity = () => {
    try {
      // projectMode additionally makes checkIntegrity ignore the machine's
      // GEMINI_CLI_HOME override and suppress the home-anchored hook
      // demotion — both are statements about this machine, and a committed
      // repo config is not this user's standing config (see integrity.js).
      const integ = checkIntegrity(projectRoot ? { home: projectRoot, cwd: projectRoot, projectMode: true } : {});
      // checkIntegrity's stock scope note says "current working directory";
      // in project mode that would misdescribe what was checked.
      if (projectRoot) {
        integ.scopeNote = "Integrity checks cover the --project directory only (paths shown relative to it); this machine's home-level agent configs were not examined on this run.";
      }
      return integ;
    }
    catch (e) {
      const why = String((e && e.message) || e).replace(/[\x00-\x1f\x7f]/g, "").slice(0, 200);
      return {
        findings: [{
          severity: "warn", kind: "integrity-crashed", file: "(integrity checker)",
          detail: `integrity checks crashed (${why}). Config locations are UNVERIFIED, not clean; the secret-scan results are unaffected`,
        }],
        filesChecked: [],
        scopeNote: "Integrity checks did not complete on this run.",
      };
    }
  };

  let sources;
  if (projectRoot) {
    const projectArtifacts = require("./sources/project-artifacts");
    const src = projectArtifacts.withRoot(projectRoot);
    if (!src.available()) {
      process.stderr.write(`--project: "${projectRoot}" is not a readable directory.\n`);
      return 2;
    }
    sources = [src];
  } else {
    sources = availableSources();
  }

  // loadAcks/loadDismissed degrade to {} (loudly, on stderr) if the state
  // file is corrupt, so a broken rotation ledger can never block or distort
  // a scan.
  const acks = loadAcks();
  const dismissed = loadDismissed();

  if (sources.length === 0) {
    const empty = emptyResult();
    const integrity = wantsIntegrity ? runIntegrity() : null;
    if (wantsSarif) {
      // Same contract as --json below: a CI step consuming SARIF must
      // always get a valid SARIF document, even with nothing to scan.
      process.stdout.write(renderSarif(empty) + "\n");
    } else if (wantsJson) {
      // A --json caller (CI, a script piping into jq) must always get valid JSON
      // on stdout, even on the "nothing to scan" path — a plain-text message on
      // stderr with exit 0 silently breaks that contract.
      process.stdout.write(renderJson(empty, integrity, renderRotation([], acks, dismissed)) + "\n");
    } else {
      process.stderr.write(
        "No known transcript sources found on this machine.\n" +
        `Checked: ${sourceStatusList()}.\n`
      );
      // The integrity checks are not gated on transcript sources existing —
      // a planted repo-level hook in the CWD is exactly as dangerous here.
      if (integrity) process.stdout.write(renderIntegrity(integrity, { noColor }) + "\n");
    }
    return failOnFind && integrityWarnCount(integrity) > 0 ? 1 : 0;
  }

  const progress = makeProgressReporter(noColor);
  const result = await scan({
    sources, includeNoisy, includeSuppressed, verify, noColor,
    onProgress: progress.onProgress,
    // Clears the spinner's last frame before --verify's own stderr lines
    // print; without this the last spinner line sits uncleared on screen
    // and the first --verify line gets appended directly onto its end with
    // no separator (a real rendering bug caught live). Safe to call twice:
    // stop() is idempotent, and the normal post-scan progress.stop() below
    // still runs regardless of whether this fired.
    onBeforeVerify: progress.stop,
  });
  progress.stop();
  const integrity = wantsIntegrity ? runIntegrity() : null;
  const rotation = renderRotation(result.findings, acks, dismissed);
  process.stdout.write((wantsSarif
    ? renderSarif(result)
    : wantsJson
      ? renderJson(result, integrity, rotation)
      : render(result, { noColor, integrity, rotation })) + "\n");

  if (args.includes("--seal")) {
    const sealExit = await runSeal(result, args);
    if (sealExit !== 0) return sealExit;
  }

  // --allow-acked narrows the SECRET gate only: an acknowledged rotation says
  // nothing about a planted hook, so integrity warnings always fail. Without
  // the flag, acks change what the report says, never what CI does — a gate
  // that silently honored local ack state would let one developer's ledger
  // green-light everyone's pipeline.
  const secretGate = allowAcked ? rotation.counts.pending > 0 : result.findings.length > 0;
  return failOnFind && (secretGate || integrityWarnCount(integrity) > 0) ? 1 : 0;
}

module.exports = { main };
