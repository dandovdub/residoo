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

  // ── new vendor patterns: shape match + no cross-rule collision ────────────
  // Fixtures are synthetic ("a" repeated to the vendor's documented length),
  // never anything that could pass for a real credential. Each regex body
  // was checked against a production detector (trufflehog) or, where no
  // detector exists, multiple independent vendor-docs sources — see the
  // comments in src/patterns.js for what backs each one.
  function matchesOnly(id, value) {
    const matched = PATTERNS.filter((p) => { p.re.lastIndex = 0; return p.re.test(value); }).map((p) => p.id);
    return matched.length === 1 && matched[0] === id;
  }
  check("Groq key matched, only by groq_key", matchesOnly("groq_key", "gsk_" + "a".repeat(52)));
  check("xAI key matched, only by xai_key", matchesOnly("xai_key", "xai-" + "a".repeat(80)));
  check("OpenRouter key matched, only by openrouter_key (not openai_key)",
    matchesOnly("openrouter_key", "sk-or-v1-" + "a".repeat(64)));
  check("Hugging Face token matched, only by huggingface_token", matchesOnly("huggingface_token", "hf_" + "a".repeat(34)));
  check("DigitalOcean token matched, only by digitalocean_token", matchesOnly("digitalocean_token", "dop_v1_" + "a".repeat(64)));
  check("Supabase token matched, only by supabase_token", matchesOnly("supabase_token", "sbp_" + "a".repeat(40)));
  check("Vault service token matched, only by vault_token", matchesOnly("vault_token", "hvs." + "a".repeat(95)));
  check("1Password service token matched, only by onepassword_service_token (not jwt)",
    matchesOnly("onepassword_service_token", "ops_eyJ" + "a".repeat(45)));
  check("Discord webhook URL matched, only by discord_webhook",
    matchesOnly("discord_webhook", "https://discord.com/api/webhooks/" + "1".repeat(18) + "/" + "a".repeat(68)));
  check("Telegram bot token matched, only by telegram_bot_token", matchesOnly("telegram_bot_token", "123456789:" + "a".repeat(35)));
  check("Mailgun key matched, only by mailgun_key", matchesOnly("mailgun_key", "key-" + "a".repeat(32)));
  check("Notion token matched, only by notion_token", matchesOnly("notion_token", "secret_" + "a".repeat(43)));
  check("Linear key matched, only by linear_key", matchesOnly("linear_key", "lin_api_" + "a".repeat(40)));
  check("Sentry token matched, only by sentry_token", matchesOnly("sentry_token", "sntryu_" + "a".repeat(64)));

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

  // ── cursor source: synthetic sqlite fixture ────────────────────────────
  // node:sqlite only exists on Node 22.5+ — CI runs this file on 18/20/22
  // (see CONTRIBUTING.md), so this whole block is feature-detected exactly
  // the way src/sources/cursor.js itself is, not assumed to be present.
  {
    let DatabaseSync = null;
    try { ({ DatabaseSync } = require("node:sqlite")); } catch { /* expected on Node < 22.5 */ }
    const cursorSource = require("../src/sources/cursor");

    check(
      "cursor source exports the standard contract plus the optional unavailableReason",
      typeof cursorSource.id === "function" && typeof cursorSource.label === "function" &&
      typeof cursorSource.available === "function" && typeof cursorSource.files === "function" &&
      typeof cursorSource.readLines === "function" && typeof cursorSource.unavailableReason === "function"
    );
    // Exercises the real path-construction/walk logic against whatever's
    // actually on THIS machine — on a machine without Cursor installed this
    // correctly yields nothing rather than throwing, which is itself the
    // thing being checked here (not "finds real data," just "doesn't crash
    // when Cursor isn't there").
    let filesThrew = false;
    try { for (const _ of cursorSource.files()) { /* just drain it */ } }
    catch { filesThrew = true; }
    check("cursor files() does not throw when walked", !filesThrew);

    if (!DatabaseSync) {
      check("cursor source reports unavailable on Node < 22.5 (no node:sqlite)", cursorSource.available() === false);
    } else {
      // Build a throwaway state.vscdb whose shape matches what this source's
      // research verified real Cursor data looks like: two tables,
      // ItemTable and cursorDiskKV, both `key TEXT UNIQUE, value BLOB`, with
      // chat content living in cursorDiskKV under a `bubbleId:<composerId>:<bubbleId>`
      // key, value a JSON-encoded string. The planted secret is AWS's
      // documented example key id — synthetic, never a real credential.
      const dbPath = path.join(tmp, "cursor-state.vscdb");
      const seed = new DatabaseSync(dbPath);
      seed.exec("CREATE TABLE ItemTable (key TEXT UNIQUE, value BLOB)");
      seed.exec("CREATE TABLE cursorDiskKV (key TEXT UNIQUE, value BLOB)");
      seed.prepare("INSERT INTO ItemTable VALUES (?, ?)")
        .run("composer.composerData", JSON.stringify({ allComposers: [{ composerId: "c1" }] }));
      seed.prepare("INSERT INTO cursorDiskKV VALUES (?, ?)")
        .run("composerData:c1", JSON.stringify({ name: "test session", createdAt: Date.now() }));
      seed.prepare("INSERT INTO cursorDiskKV VALUES (?, ?)")
        .run("bubbleId:c1:b1", JSON.stringify({
          type: 1, text: "here's my key: " + docExampleKey, tokenCount: 12,
        }));
      seed.close();

      // readLines(file) is path-parameterized — it doesn't depend on the
      // module's own computed USER_DIR, so it can be exercised directly
      // against this synthetic file without needing to fake Cursor's real
      // install location or touch this machine's actual home directory.
      const cursorResult = await cursorSource.readLines(dbPath);
      check("cursor readLines reads the synthetic db as complete", cursorResult.status === "complete");
      check("cursor readLines surfaces the planted key's row as a line",
        cursorResult.lines.some((l) => l.includes(docExampleKey)));

      // End-to-end: real cursor.js readLines() feeding real scan.js against
      // the synthetic db, exactly the integration path a live `residoo scan`
      // would run — files() is a tiny inline stand-in here only because the
      // real files() looks at this machine's actual Cursor directory (empty,
      // since Cursor isn't installed on the machine this was built on), not
      // because readLines() itself is faked.
      const cursorFakeSource = {
        id: () => "cursor", label: () => "Cursor", available: () => true,
        *files() {
          const st = fs.statSync(dbPath);
          yield { file: dbPath, mtimeMs: st.mtimeMs, sizeBytes: st.size, broken: false };
        },
        readLines: cursorSource.readLines,
      };
      const cursorScanResult = await scan({ sources: [cursorFakeSource] });
      check("scan finds the planted key via the real cursor.js readLines",
        cursorScanResult.findings.some((f) => f.ruleId === "aws_access_key_id"));
      check("cursor scan output is redacted", !JSON.stringify(cursorScanResult.findings).includes("IOSFODNN7EXAMPLE"));
    }
  }

  // ── all registered sources: contract shape + doesn't throw on this machine ─
  // Breadth check across every source in the registry (42 as of this pass,
  // most added multi-source-corroborated-but-unverified — see each file's
  // own header and src/sources/index.js's trust-tier note). This doesn't
  // prove any one adapter's path/schema is right — only a real install can
  // do that — but it does prove every adapter honours the shape scan.js
  // depends on and doesn't crash when actually walked on a real, ordinary
  // machine (this one), which is exactly the class of bug ("throws instead
  // of reporting broken/failed") CONTRIBUTING.md rule 5 exists to catch.
  {
    const { ALL_SOURCES } = require("../src/sources");
    let shapeOk = true, walkOk = true;
    for (const s of ALL_SOURCES) {
      const shape = ["id", "label", "available", "files", "readLines"].every((k) => typeof s[k] === "function");
      if (!shape) { shapeOk = false; console.log("  FAIL  (contract shape) " + (s.id ? s.id() : "<unknown>")); continue; }
      try { s.available(); } catch { walkOk = false; console.log("  FAIL  (available threw) " + s.id()); }
      try { for (const _ of s.files()) { /* drain */ } } catch { walkOk = false; console.log("  FAIL  (files threw) " + s.id()); }
    }
    check(`all ${ALL_SOURCES.length} registered sources export the standard contract`, shapeOk);
    check("all registered sources' available()/files() run clean on this machine", walkOk);
    check("no duplicate source ids in the registry", new Set(ALL_SOURCES.map((s) => s.id())).size === ALL_SOURCES.length);
  }

  // ── warp source: synthetic sqlite fixture (generic multi-table scan) ──────
  // Representative of this project's other SQLite-based sources (cursor.js,
  // crush.js, cody.js, devin-cli.js, hermes.js, kiro-cli.js, llm.js, trae.js,
  // void.js, warp.js, zed.js) — all share the same node:sqlite-feature-
  // detected, discover-tables-at-scan-time shape. node:sqlite only exists on
  // Node 22.5+ (CI runs this file on 18/20/22 too — see CONTRIBUTING.md), so
  // this block is feature-detected the same way the source itself is.
  {
    let DatabaseSync = null;
    try { ({ DatabaseSync } = require("node:sqlite")); } catch { /* expected on Node < 22.5 */ }
    const warpSource = require("../src/sources/warp");

    let filesThrew = false;
    try { for (const _ of warpSource.files()) { /* drain */ } } catch { filesThrew = true; }
    check("warp files() does not throw when walked", !filesThrew);

    if (DatabaseSync) {
      // warp.js deliberately discovers tables via sqlite_master rather than
      // hardcoding names (its own schema is only partially, unofficially
      // documented — see its header) — this fixture uses a real table name
      // reported by a real user (agent_conversations/conversation_data) to
      // exercise that discovery path, not because the adapter requires it.
      const dbPath = path.join(tmp, "warp.sqlite");
      const seed = new DatabaseSync(dbPath);
      seed.exec("CREATE TABLE agent_conversations (id TEXT, conversation_id TEXT, conversation_data TEXT)");
      seed.prepare("INSERT INTO agent_conversations VALUES (?, ?, ?)")
        .run("1", "c1", JSON.stringify({ text: "ran with " + docExampleKey }));
      seed.close();

      const warpResult = await warpSource.readLines(dbPath);
      check("warp readLines reads the synthetic db as complete", warpResult.status === "complete");
      check("warp readLines surfaces the planted key via generic table discovery",
        warpResult.lines.some((l) => l.includes(docExampleKey)));
    }
  }

  // ── amazon-q source: synthetic flat-JSON fixture ──────────────────────────
  // Representative of this project's plain-JSON-file sources (amazon-q.js,
  // continue.js's session files, codebuff.js, mentat.js's reconstructed
  // transcript, pearai.js) — no database, no line-delimited format, the
  // whole file is scanned as one document via the same streaming reader
  // claude-code.js uses.
  {
    const amazonQSource = require("../src/sources/amazon-q");
    const historyFile = path.join(tmp, "chat-history-no-workspace.json");
    fs.writeFileSync(historyFile, JSON.stringify({
      collections: [{ name: "tabs", data: [{ history: [{ body: "leaked " + docExampleKey }] }] }],
    }));

    const aqResult = await amazonQSource.readLines(historyFile);
    check("amazon-q readLines reads the synthetic history file as complete", aqResult.status === "complete");
    check("amazon-q readLines surfaces the planted key", aqResult.lines.some((l) => l.includes(docExampleKey)));

    let filesThrew = false;
    try { for (const _ of amazonQSource.files()) { /* drain */ } } catch { filesThrew = true; }
    check("amazon-q files() does not throw when walked", !filesThrew);
  }

  // ── aider source: synthetic plain-text fixture (chat log + input history) ─
  // Representative of this project's plain-line-delimited-text sources
  // beyond claude-code.js itself (aider.js, codex-cli.js, gemini-cli.js,
  // qwen-code.js, cline.js/roo-code.js's JSON-per-task files, jetbrains-*,
  // openclaw.js, factory-droid.js, kimi-code.js, and more) — including the
  // input-history format's `+`-prefixed lines, which matter because
  // patterns.js matches on `\b` word boundaries rather than a `^` line
  // anchor, so a secret must still be found even when it isn't the first
  // character on the line.
  {
    const aiderSource = require("../src/sources/aider");
    const chatHistoryFile = path.join(tmp, ".aider.chat.history.md");
    fs.writeFileSync(chatHistoryFile,
      "# aider chat started at 2026-09-02\n\n#### put this in .env\n\n> " + docExampleKey + "\n");
    const inputHistoryFile = path.join(tmp, ".aider.input.history");
    fs.writeFileSync(inputHistoryFile, "# 2026-09-02 10:00:00\n+use " + docExampleKey + " for now\n");

    const chatResult = await aiderSource.readLines(chatHistoryFile);
    check("aider readLines reads the synthetic chat history as complete", chatResult.status === "complete");
    check("aider readLines surfaces the planted key from the chat log",
      chatResult.lines.some((l) => l.includes(docExampleKey)));

    const inputResult = await aiderSource.readLines(inputHistoryFile);
    check("aider readLines surfaces the planted key through a '+'-prefixed input-history line",
      inputResult.lines.some((l) => l.includes(docExampleKey)));

    let filesThrew = false;
    try { for (const _ of aiderSource.files()) { /* drain */ } } catch { filesThrew = true; }
    check("aider files() does not throw when walked", !filesThrew);
  }

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error("smoke crashed:", e); process.exit(1); });
