"use strict";

const fs = require("fs");
const crypto = require("crypto");
const zlib = require("zlib");
const { pipeline } = require("stream/promises");
const { Transform } = require("stream");

/**
 * Streaming seal/unseal for transcript files.
 *
 * AES-256-GCM + scrypt — the same primitives validated in the memvault spike,
 * with both of that spike's hard-won lessons applied from the start:
 *   - everything is Buffers end to end (a .toString("utf-8") round-trip on
 *     binary silently corrupts it — verified, not theoretical);
 *   - scrypt at N=2^15/r=8 needs ~32MB, exactly Node's DEFAULT maxmem, so
 *     maxmem must be raised explicitly or the very first real run throws
 *     ERR_CRYPTO_INVALID_SCRYPT_PARAMS (also verified the hard way).
 *
 * And one lesson from residoo itself: transcripts run to 800MB+, past V8's
 * ~512M-char single-string ceiling, so seal/unseal are stream pipelines —
 * no step ever materializes the whole file.
 *
 * Container format (one sealed file):
 *   [4-byte BE header length][JSON header][ciphertext...][16-byte GCM tag]
 * The header is PLAINTEXT and deliberately minimal — salt, iv, version.
 * Anything sensitive (original path, plaintext hash) lives in the vault's
 * separate manifest, which is itself sealed: a sealed blob that leaks its
 * own origin path in cleartext would undermine the point of sealing it.
 */

const MAGIC = 1;
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function deriveKey(passphrase, salt) {
  return crypto.scryptSync(passphrase, salt, 32, SCRYPT);
}

/**
 * Seal srcPath -> destPath, streaming (read -> gzip -> encrypt -> write).
 * Returns { plainSha256, plainBytes, sealedBytes } — the plaintext hash is
 * computed on the fly from the same bytes that get sealed, so the caller can
 * later prove an unsealed copy is byte-identical to what went in.
 */
async function sealFile(srcPath, destPath, passphrase) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(passphrase, salt);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const hash = crypto.createHash("sha256");
  let plainBytes = 0;

  const header = Buffer.from(JSON.stringify({
    v: MAGIC, salt: salt.toString("base64"), iv: iv.toString("base64"), gzip: true,
  }), "utf-8");
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(header.length);

  const out = fs.createWriteStream(destPath);
  out.write(lenBuf);
  out.write(header);

  const tap = new Transform({
    transform(chunk, _enc, cb) { plainBytes += chunk.length; hash.update(chunk); cb(null, chunk); },
  });

  await pipeline(fs.createReadStream(srcPath), tap, zlib.createGzip(), cipher, out, { end: false });
  // GCM's auth tag only exists after the cipher finishes — appended last, read
  // back first by unsealFile below.
  const tag = cipher.getAuthTag();
  await new Promise((resolve, reject) => out.end(tag, (err) => (err ? reject(err) : resolve())));

  const sealedBytes = fs.statSync(destPath).size;
  return { plainSha256: hash.digest("hex"), plainBytes, sealedBytes };
}

/** Unseal sealedPath -> destPath, streaming. Throws on wrong passphrase or any tampering (GCM tag). */
async function unsealFile(sealedPath, destPath, passphrase) {
  const fd = fs.openSync(sealedPath, "r");
  let headerLen, header, dataStart, dataEnd, tag;
  try {
    const size = fs.fstatSync(fd).size;
    const lenBuf = Buffer.alloc(4);
    fs.readSync(fd, lenBuf, 0, 4, 0);
    headerLen = lenBuf.readUInt32BE(0);
    if (headerLen <= 0 || headerLen > 4096) throw new Error("not a residoo sealed file (bad header)");
    const headerBuf = Buffer.alloc(headerLen);
    fs.readSync(fd, headerBuf, 0, headerLen, 4);
    header = JSON.parse(headerBuf.toString("utf-8"));
    dataStart = 4 + headerLen;
    dataEnd = size - 16; // GCM tag
    if (dataEnd < dataStart) throw new Error("sealed file truncated");
    tag = Buffer.alloc(16);
    fs.readSync(fd, tag, 0, 16, dataEnd);
  } finally {
    fs.closeSync(fd);
  }

  const key = deriveKey(passphrase, Buffer.from(header.salt, "base64"));
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(header.iv, "base64"));
  decipher.setAuthTag(tag);

  const hash = crypto.createHash("sha256");
  let plainBytes = 0;
  const tap = new Transform({
    transform(chunk, _enc, cb) { plainBytes += chunk.length; hash.update(chunk); cb(null, chunk); },
  });

  await pipeline(
    fs.createReadStream(sealedPath, { start: dataStart, end: dataEnd - 1 }),
    decipher,
    zlib.createGunzip(),
    tap,
    fs.createWriteStream(destPath)
  );
  return { plainSha256: hash.digest("hex"), plainBytes };
}

/** Seal a small in-memory Buffer (the vault manifest) into the same container format. */
function sealBuffer(buf, passphrase) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(passphrase, salt);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const gz = zlib.gzipSync(buf);
  const ct = Buffer.concat([cipher.update(gz), cipher.final()]);
  const tag = cipher.getAuthTag();
  const header = Buffer.from(JSON.stringify({
    v: MAGIC, salt: salt.toString("base64"), iv: iv.toString("base64"), gzip: true,
  }), "utf-8");
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(header.length);
  return Buffer.concat([lenBuf, header, ct, tag]);
}

/** Inverse of sealBuffer. Returns the plaintext Buffer; throws on wrong passphrase/tampering. */
function unsealBuffer(sealed, passphrase) {
  const headerLen = sealed.readUInt32BE(0);
  const header = JSON.parse(sealed.slice(4, 4 + headerLen).toString("utf-8"));
  const tag = sealed.slice(sealed.length - 16);
  const ct = sealed.slice(4 + headerLen, sealed.length - 16);
  const key = deriveKey(passphrase, Buffer.from(header.salt, "base64"));
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(header.iv, "base64"));
  decipher.setAuthTag(tag);
  const gz = Buffer.concat([decipher.update(ct), decipher.final()]);
  return zlib.gunzipSync(gz);
}

module.exports = { sealFile, unsealFile, sealBuffer, unsealBuffer };
