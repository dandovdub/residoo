"use strict";

const path = require("path");
const { availableSources, ALL_SOURCES } = require("./sources");
const { scan, emptyResult } = require("./scan");
const { render, renderIntegrity, renderJson } = require("./report");
const { checkIntegrity } = require("./integrity");

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

  Scanning makes NO network calls and changes nothing on disk. Findings are
  redacted in every output format. Sealing (--seal) writes NEW encrypted
  files only. It never modifies or deletes anything that already exists.

Usage:
  residoo scan [options]
  residoo unseal <vault-dir> [--restore <n> --out <path>]

Scan options:
  --json                  machine-readable output (full detail, still redacted)
  --include-noisy         also run broad, false-positive-prone rules
  --include-suppressed    also show matches that looked like placeholder/example text
  --fail-on-find          exit code 1 if anything is found (for CI): secret
                          findings and integrity WARNINGS count; integrity
                          info-level review items do not
  --no-integrity          skip the integrity checks (planted hooks, dropper
                          files, auto-run tasks, hidden Unicode)
  --no-color              disable ANSI colour

Seal options (used with scan):
  --seal                  after scanning, encrypt every transcript that carried a
                          finding into a local vault directory (AES-256-GCM,
                          passphrase-derived key; originals are left untouched)
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

async function runSeal(result, args) {
  const { sealFindings, uploadVaultToCloudRoam } = require("./sealvault");

  const filesWithFindings = [...new Set(result.findings.map((f) => f.file))];
  if (filesWithFindings.length === 0) {
    process.stdout.write("Nothing to seal: no findings.\n");
    return 0;
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const vaultDir = argValue(args, "--vault-dir") || path.resolve(`residoo-vault-${stamp}`);
  const passphrase = await getPassphrase({ confirmNew: true });

  process.stdout.write(`\nSealing ${filesWithFindings.length} file(s) with findings into ${vaultDir}\n`);
  const { entries } = await sealFindings({
    files: filesWithFindings, vaultDir, passphrase,
    log: (s) => process.stdout.write(s + "\n"),
  });
  const totalPlain = entries.reduce((s, e) => s + e.plainBytes, 0);
  const totalSealed = entries.reduce((s, e) => s + e.sealedBytes, 0);
  process.stdout.write(
    `\nSealed ${entries.length} file(s): ${(totalPlain / 1024 / 1024).toFixed(1)}MB plain -> ` +
    `${(totalSealed / 1024 / 1024).toFixed(1)}MB encrypted.\n` +
    `Originals were NOT touched. Once you've verified a restore works\n` +
    `(residoo unseal ${path.basename(vaultDir)} --restore 0001.sealed --out /tmp/check), removing the\n` +
    `plaintext originals is your call; residoo never deletes anything itself.\n`
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

  const passphrase = await getPassphrase({ confirmNew: false });
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

async function main(argv) {
  const args = argv.slice(2);
  if (args.includes("-h") || args.includes("--help") || args.length === 0) {
    process.stdout.write(HELP);
    return 0;
  }

  const cmd = args[0];
  if (cmd === "unseal") return runUnseal(args);
  if (cmd !== "scan") {
    process.stderr.write(`Unknown command "${cmd}". Try "residoo --help".\n`);
    return 2;
  }

  const wantsJson = args.includes("--json");
  const includeNoisy = args.includes("--include-noisy");
  const includeSuppressed = args.includes("--include-suppressed");
  const failOnFind = args.includes("--fail-on-find");
  // Passed through explicitly to render() rather than mutating
  // process.env.NO_COLOR — main() is an exported function a host process can
  // legitimately call more than once (a wrapper CLI, a test runner), and a
  // mutated env var would leak past this one invocation and silently kill
  // color for a later call that never asked for that.
  const noColor = args.includes("--no-color");

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
  const runIntegrity = () => {
    try { return checkIntegrity(); }
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

  const sources = availableSources();
  if (sources.length === 0) {
    const empty = emptyResult();
    const integrity = wantsIntegrity ? runIntegrity() : null;
    if (wantsJson) {
      // A --json caller (CI, a script piping into jq) must always get valid JSON
      // on stdout, even on the "nothing to scan" path — a plain-text message on
      // stderr with exit 0 silently breaks that contract.
      process.stdout.write(renderJson(empty, integrity) + "\n");
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

  const result = await scan({ sources, includeNoisy, includeSuppressed });
  const integrity = wantsIntegrity ? runIntegrity() : null;
  process.stdout.write((wantsJson ? renderJson(result, integrity) : render(result, { noColor, integrity })) + "\n");

  if (args.includes("--seal")) {
    const sealExit = await runSeal(result, args);
    if (sealExit !== 0) return sealExit;
  }

  return failOnFind && (result.findings.length > 0 || integrityWarnCount(integrity) > 0) ? 1 : 0;
}

module.exports = { main };
