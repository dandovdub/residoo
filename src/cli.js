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

  Scanning makes NO network calls and changes nothing on disk. Findings are
  redacted in every output format. Sealing (--seal) writes NEW encrypted
  files only. It never modifies or deletes anything that already exists.

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
  --upload-cloudroam      ALSO upload the sealed vault to CloudRoam. This is the
                          only residoo feature that touches the network, it is
                          off unless you pass it, and only ciphertext is sent.
                          Needs CLOUDROAM_API_KEY (env) plus:
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
  const result = await scan({ sources, includeNoisy, includeSuppressed, onProgress: progress.onProgress });
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
