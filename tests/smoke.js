"use strict";

/**
 * Smoke tests — self-contained, zero dependencies, synthetic data only.
 * Run with `npm test`. Every fixture below is deliberately fake: the one
 * key-shaped string is AWS's officially documented example key id.
 *
 * These are the automated floor under the deeper manual passes recorded in
 * SECURITY.md, not a replacement for them.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

let passed = 0, failed = 0;
function check(name, cond) {
  if (cond) { passed++; console.log("  ok    " + name); }
  else { failed++; console.log("  FAIL  " + name); }
}

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "residoo-smoke-"));

  // ── patterns: detection + mutual exclusivity + redaction ──────────────────
  const { PATTERNS, redact } = require("../src/patterns");
  const docExampleKey = "AKIA" + "IOSFODNN7EXAMPLE"; // AWS's documented example id
  const aws = PATTERNS.find((p) => p.id === "aws_access_key_id");
  aws.re.lastIndex = 0;
  check("AWS key shape detected", aws.re.test("x " + docExampleKey + " y"));

  const anthKey = "sk-ant-api03-" + "a".repeat(60);
  const openai = PATTERNS.find((p) => p.id === "openai_key");
  const anthropic = PATTERNS.find((p) => p.id === "anthropic_key");
  openai.re.lastIndex = 0; anthropic.re.lastIndex = 0;
  check("anthropic key not double-matched by openai rule", !openai.re.test(anthKey) && (anthropic.re.lastIndex = 0, anthropic.re.test(anthKey)));

  const red = redact(docExampleKey);
  check("redact hides the middle", !red.includes("IOSFODNN") && red.includes("AKIA"));
  check("redact strips control chars", !redact("\x1b[2Jabcdefghijklmnop\x1b[0m").includes("\x1b"));

  // ── sealcrypto: round-trip, wrong passphrase, tamper ──────────────────────
  const { sealFile, unsealFile, sealBuffer, unsealBuffer } = require("../src/sealcrypto");
  const src = path.join(tmp, "orig.bin");
  // Random bytes plus deliberately invalid UTF-8 — binary-safety was a real
  // past bug class in this codebase's history.
  const data = Buffer.concat([crypto.randomBytes(2 * 1024 * 1024), Buffer.from([0xff, 0xfe, 0x00]), Buffer.from(docExampleKey)]);
  fs.writeFileSync(src, data);
  const sealed = path.join(tmp, "x.sealed");
  const s = await sealFile(src, sealed, "smoke-pass-123");
  check("seal reports correct plain byte count", s.plainBytes === data.length);

  const out = path.join(tmp, "restored.bin");
  const u = await unsealFile(sealed, out, "smoke-pass-123");
  check("unseal round-trips byte-identical", fs.readFileSync(out).equals(data));
  check("unseal hash matches seal hash", u.plainSha256 === s.plainSha256);

  let wrongThrew = false;
  try { await unsealFile(sealed, path.join(tmp, "w.bin"), "not-the-pass"); } catch { wrongThrew = true; }
  check("wrong passphrase rejected", wrongThrew);

  const tampered = fs.readFileSync(sealed);
  tampered[Math.floor(tampered.length / 2)] ^= 0xff;
  fs.writeFileSync(path.join(tmp, "t.sealed"), tampered);
  let tamperThrew = false;
  try { await unsealFile(path.join(tmp, "t.sealed"), path.join(tmp, "t.bin"), "smoke-pass-123"); } catch { tamperThrew = true; }
  check("tampered ciphertext rejected", tamperThrew);

  const mbuf = Buffer.from(JSON.stringify({ entries: [{ n: "0001.sealed" }] }));
  check("manifest buffer round-trips", unsealBuffer(sealBuffer(mbuf, "pw-8chars"), "pw-8chars").equals(mbuf));

  // ── scan: end to end on a synthetic transcript ────────────────────────────
  const { scan } = require("../src/scan");
  const fakeSourceDir = path.join(tmp, "transcripts");
  fs.mkdirSync(fakeSourceDir);
  fs.writeFileSync(path.join(fakeSourceDir, "a.jsonl"),
    JSON.stringify({ message: { content: "found " + docExampleKey + " in output" } }) + "\n" +
    JSON.stringify({ message: { content: "nothing here" } }) + "\n");
  const fakeSource = {
    id: () => "smoke", label: () => "Smoke", available: () => true,
    *files() {
      for (const f of fs.readdirSync(fakeSourceDir)) {
        const file = path.join(fakeSourceDir, f);
        const st = fs.statSync(file);
        yield { file, mtimeMs: st.mtimeMs, sizeBytes: st.size, broken: false };
      }
    },
    async readLines(file) {
      return { lines: fs.readFileSync(file, "utf-8").split("\n"), status: "complete", bytesRead: fs.statSync(file).size };
    },
  };
  const result = await scan({ sources: [fakeSource] });
  check("scan finds the planted key", result.findings.some((f) => f.ruleId === "aws_access_key_id"));
  check("scan output is redacted", !JSON.stringify(result.findings).includes("IOSFODNN7EXAMPLE"));
  check("filesScanned counted", result.filesScanned === 1);

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error("smoke crashed:", e); process.exit(1); });
