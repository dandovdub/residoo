"use strict";

const fs = require("fs");
const path = require("path");
const { sealFile, sealBuffer, unsealBuffer, unsealFile } = require("./sealcrypto");

/**
 * Seal every file that carried findings into an encrypted vault directory.
 *
 * Principles, in order of importance:
 *   - NEVER touches the originals. Seal creates new files only; deleting the
 *     plaintext afterwards is the user's own, separate, informed decision.
 *     (residoo's core promise is that scanning is read-only — sealing writes
 *     NEW files and nothing else.)
 *   - The vault leaks nothing in plaintext. Sealed blobs are numbered
 *     (0001.sealed…), and the mapping back to real paths + plaintext hashes
 *     lives in manifest.sealed — itself encrypted. A vault that names its
 *     own contents would defeat the point of uploading it anywhere.
 *   - Streaming throughout: transcripts run to 800MB+; nothing here ever
 *     holds a whole file in memory.
 *
 * Vault layout:
 *   residoo-vault-<stamp>/
 *     0001.sealed …      encrypted+gzipped transcript files
 *     manifest.sealed    encrypted JSON: [{n, origPath, plainSha256, plainBytes, sealedBytes}]
 *     README.txt         plaintext instructions (no sensitive content)
 */
async function sealFindings({ files, vaultDir, passphrase, log = () => {} }) {
  fs.mkdirSync(vaultDir, { recursive: true });
  const entries = [];
  let n = 0;
  for (const file of files) {
    n++;
    const name = String(n).padStart(4, "0") + ".sealed";
    const dest = path.join(vaultDir, name);
    log(`  sealing ${path.basename(file)} …`);
    const { plainSha256, plainBytes, sealedBytes } = await sealFile(file, dest, passphrase);
    entries.push({ n: name, origPath: file, plainSha256, plainBytes, sealedBytes });
    log(`    -> ${name}  (${(plainBytes / 1024 / 1024).toFixed(1)}MB plain -> ${(sealedBytes / 1024 / 1024).toFixed(1)}MB sealed)`);
  }

  const manifest = { v: 1, entries };
  fs.writeFileSync(path.join(vaultDir, "manifest.sealed"), sealBuffer(Buffer.from(JSON.stringify(manifest, null, 2), "utf-8"), passphrase));
  fs.writeFileSync(path.join(vaultDir, "README.txt"),
    "residoo sealed vault\n" +
    "====================\n\n" +
    "Files here are AES-256-GCM encrypted (scrypt-derived key). Without the\n" +
    "passphrase they are unreadable, including by residoo's authors.\n\n" +
    "To list contents:   residoo unseal <vault-dir>            (prompts for passphrase)\n" +
    "To restore a file:  residoo unseal <vault-dir> --restore <n> --out <path>\n\n" +
    "manifest.sealed maps the numbered blobs back to their original paths and\n" +
    "records a SHA-256 of each original, so a restore can be verified as\n" +
    "byte-identical. The manifest is encrypted for the same reason the files\n" +
    "are: even the NAMES of what is in here are nobody else's business.\n"
  );
  return { entries, vaultDir };
}

/** Decrypt and return the vault's manifest. Throws on wrong passphrase. */
function openManifest(vaultDir, passphrase) {
  const sealed = fs.readFileSync(path.join(vaultDir, "manifest.sealed"));
  return JSON.parse(unsealBuffer(sealed, passphrase).toString("utf-8"));
}

/** Restore one numbered entry to outPath and verify it against the recorded hash. */
async function restoreEntry(vaultDir, entry, outPath, passphrase) {
  const { plainSha256, plainBytes } = await unsealFile(path.join(vaultDir, entry.n), outPath, passphrase);
  const ok = plainSha256 === entry.plainSha256 && plainBytes === entry.plainBytes;
  return { ok, plainSha256, plainBytes };
}

/**
 * Upload a vault to CloudRoam — the ONLY code path in residoo that touches
 * the network, and it never runs unless the user passed --upload-cloudroam
 * explicitly. Uses CloudRoam's raw-body streaming endpoint
 * (POST /api/files/upload-stream?bucket&key + X-Connector-Id), so this stays
 * zero-dependency. Only ciphertext leaves the machine: the vault's files are
 * already sealed before this function is ever called, and the manifest that
 * names them is sealed too.
 */
async function uploadVaultToCloudRoam({ vaultDir, baseUrl, apiKey, connectorId, bucket, prefix, log = () => {} }) {
  const files = fs.readdirSync(vaultDir).filter((f) => f.endsWith(".sealed") || f === "README.txt");
  const base = baseUrl.replace(/\/+$/, "");
  const uploaded = [];
  for (const f of files) {
    const full = path.join(vaultDir, f);
    const size = fs.statSync(full).size;
    const key = (prefix ? prefix.replace(/\/+$/, "") + "/" : "") + path.basename(vaultDir) + "/" + f;
    const q = new URLSearchParams({ bucket, key });
    log(`  uploading ${f} (${(size / 1024 / 1024).toFixed(1)}MB) …`);
    const res = await fetch(`${base}/api/files/upload-stream?${q}`, {
      method: "POST",
      headers: {
        Authorization: "Bearer " + apiKey,
        "X-Connector-Id": connectorId,
        "Content-Type": "application/octet-stream",
        "Content-Length": String(size),
      },
      body: fs.createReadStream(full),
      duplex: "half", // required by Node's fetch for a streaming request body
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`upload of ${f} failed: HTTP ${res.status} ${text.slice(0, 200)}`);
    }
    uploaded.push(key);
  }
  return uploaded;
}

module.exports = { sealFindings, openManifest, restoreEntry, uploadVaultToCloudRoam };
