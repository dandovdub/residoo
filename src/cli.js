"use strict";

const path = require("path");
const { availableSources, ALL_SOURCES } = require("./sources");
const { scan, emptyResult } = require("./scan");
const { render, renderJson } = require("./report");

const HELP = `residoo — find secrets leaking through your AI agent's session history

  Coding agents (Claude Code, Cursor, Copilot, ...) write everything you do
  to a local transcript, including file contents your prompts touch — which
  means real credentials sitting in plaintext on disk, indefinitely, in a
  place nobody thinks to check. residoo scans those transcripts for them.

  Scanning makes NO network calls and changes nothing on disk. Findings are
  redacted in every output format. Sealing (--seal) writes NEW encrypted
  files only — it never modifies or deletes anything that already exists.

Usage:
  residoo scan [options]
  residoo unseal <vault-dir> [--restore <n> --out <path>]

Scan options:
  --json                  machine-readable output (full detail, still redacted)
  --include-noisy         also run broad, false-positive-prone rules
  --include-suppressed    also show matches that looked like placeholder/example text
  --fail-on-find          exit code 1 if anything is found (for CI)
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

Sources checked on this machine: ${ALL_SOURCES.map((s) => s.label()).join(", ")}
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
    process.stdout.write("Nothing to seal — no findings.\n");
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
    `plaintext originals is your call — residoo never deletes anything itself.\n`
  );

  if (args.includes("--upload-cloudroam")) {
    const apiKey = process.env.CLOUDROAM_API_KEY;
    const connectorId = argValue(args, "--connector");
    const bucket = argValue(args, "--bucket");
    if (!apiKey || !connectorId || !bucket) {
      process.stderr.write("--upload-cloudroam needs CLOUDROAM_API_KEY (env), --connector and --bucket.\n");
      return 2;
    }
    process.stdout.write(`\nUploading sealed vault to CloudRoam (${bucket}) — ciphertext only:\n`);
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
    process.stderr.write("Could not open vault — wrong passphrase, or the vault is corrupted.\n");
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
  process.stderr.write(`Restored, but verification FAILED — content does not match what was sealed. Do not trust this copy.\n`);
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

  const sources = availableSources();
  if (sources.length === 0) {
    const empty = emptyResult();
    if (wantsJson) {
      // A --json caller (CI, a script piping into jq) must always get valid JSON
      // on stdout, even on the "nothing to scan" path — a plain-text message on
      // stderr with exit 0 silently breaks that contract.
      process.stdout.write(renderJson(empty) + "\n");
    } else {
      process.stderr.write(
        "No known transcript sources found on this machine.\n" +
        `Checked: ${ALL_SOURCES.map((s) => s.label()).join(", ")}.\n`
      );
    }
    return 0;
  }

  const result = await scan({ sources, includeNoisy, includeSuppressed });
  process.stdout.write((wantsJson ? renderJson(result) : render(result, { noColor })) + "\n");

  if (args.includes("--seal")) {
    const sealExit = await runSeal(result, args);
    if (sealExit !== 0) return sealExit;
  }

  return failOnFind && result.findings.length > 0 ? 1 : 0;
}

module.exports = { main };
