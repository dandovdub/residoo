"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { scan } = require("./scan");
const { guidanceFor, fingerprintFinding, loadAcks, loadDismissed, statePath } = require("./rotation");
const { c, makePaint } = require("./color");

/**
 * `residoo watch`: continuous, near-real-time scanning of the same
 * transcript stores `residoo scan` covers, instead of a single snapshot.
 * No competitor in this project's own benchmark (bench/) has anything like
 * it, verified directly against the installed tools' own --help output,
 * not assumed. ggshield's AI hook is the one adjacent thing, and it works
 * a different way entirely: a per-agent-tool hook that ships content to
 * GitGuardian's server. This is one local process, zero network, covering
 * every known agent source at once.
 *
 * Design in one sentence: a poll sweep re-runs each source's own files()
 * generator (every adapter already knows its own topology) and diffs
 * {sizeBytes, mtimeMs} against an in-memory offset table; new bytes on a
 * `.jsonl` file are TAILED (only the new bytes are ever read); a change to
 * any other file (a config rewritten in place, a SQLite-backed source's
 * files, a legacy whole-file-per-turn format) triggers a full re-read via
 * the real source's own readLines(), made idempotent by dedup. fs.watch is
 * layered on top purely as a latency hint (an early trigger for the next
 * sweep) and is never load-bearing -- it is inert on Linux for files
 * written to subdirectories of a non-recursively-watched root, and
 * unavailable on some filesystems entirely; every guarantee here comes
 * from polling.
 *
 * scan() (see scan.js) never touches disk itself: it is driven entirely by
 * the {id, files, readLines} source contract. A synthetic, in-memory
 * source built from a batch of newly-read lines gets suppression, AWS/
 * PlanetScale/MongoDB-Atlas pairing, base64 decoding, and split-line
 * joining for free, identically to a real `residoo scan`.
 */

// ── small pure helpers, duplicated rather than imported ─────────────────────
// report.js and scan.js each keep their own copy of a couple of tiny,
// stable helpers rather than exporting them for one extra call site; this
// file follows the same precedent (see scan.js's own comment on this).

function localTimestamp(d) {
  const p2 = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}`;
}

const INVISIBLES_RE = /[​‌‍⁠﻿\u{e0000}-\u{e007f}]/gu;
function safeBasename(file) {
  return path.basename(String(file))
    .replace(/[\x00-\x1f\x7f]/g, "")
    .replace(INVISIBLES_RE, (ch) => "\\u{" + ch.codePointAt(0).toString(16).toUpperCase() + "}");
}

/**
 * `.jsonl` is append-only by construction across every source in
 * src/sources/ (verified: each adapter that emits `.jsonl` either only
 * ever appends, or -- openclaw session resets, qwen-code archiving --
 * renames/moves the whole file rather than rewriting its content in
 * place). Every other extension a source can yield (settings JSON,
 * SQLite-backed session state, legacy whole-file-per-turn formats like
 * gemini-cli's session-*.json) gets rewritten, not appended, so it is
 * always fully re-read on change. This is a property of the FILE, not the
 * source: gemini-cli alone yields both kinds from one adapter, which is
 * exactly why the split is per-file, not per-source.
 */
function isTailable(file) {
  return file.endsWith(".jsonl");
}

/**
 * First 64 bytes, hashed, to catch "the file was truncated and rewritten
 * to a size at or past the old offset between two sweeps" -- the one case
 * a plain size/mtime comparison cannot distinguish from ordinary growth.
 * Read only when a file looks like it grew; the common case (genuinely
 * nothing changed, or genuinely just appended to) never pays this cost.
 */
function prefixHash(file) {
  let fd;
  try {
    fd = fs.openSync(file, "r");
    const buf = Buffer.alloc(64);
    const n = fs.readSync(fd, buf, 0, 64, 0);
    return crypto.createHash("sha256").update(buf.subarray(0, n)).digest("hex");
  } catch {
    return null;
  } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* already gone */ } }
  }
}

/**
 * Whole-file SHA-256, used only for rescan-class (non-tailable) files to
 * tell "the file was touched but the bytes are identical" apart from "the
 * bytes actually changed." Many CLIs rewrite their entire settings/config
 * file on every run even when there is nothing new to say, which would
 * otherwise force a real rescan (and, worse, risk re-surfacing a secret
 * that was already there at baseline) on pure churn. A hash can only gate
 * whether to rescan; unlike the scan itself it never sees redacted output
 * or alerts, so computing it unconditionally on a same-size touch is safe.
 */
function wholeFileHash(file) {
  try {
    return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  } catch {
    return null;
  }
}

/**
 * Split a just-read Buffer on raw newline bytes (0x0A) BEFORE decoding any
 * text, so a multi-byte UTF-8 sequence straddling the read boundary is
 * never partially decoded (0x0A cannot appear as a continuation byte of a
 * multi-byte sequence, so byte-level splitting is always safe). Returns
 * only COMPLETE lines and how many bytes they consumed; an incomplete
 * trailing fragment (no `\n` yet) is deliberately left unread and
 * unreturned -- the caller must NOT advance its offset past
 * `consumedBytes`, so the next sweep re-reads the still-incomplete tail
 * from scratch rather than holding fragile partial-line state across
 * sweeps.
 */
function splitCompleteLines(buf) {
  const lines = [];
  let start = 0;
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] === 0x0a) {
      let end = i;
      if (end > start && buf[end - 1] === 0x0d) end--; // trailing \r, matches readLines' crlfDelay handling
      lines.push(buf.toString("utf-8", start, end));
      start = i + 1;
    }
  }
  return { lines, consumedBytes: start };
}

/**
 * Read new bytes from `fromOffset` to EOF (capped per sweep, leftover
 * carries to the next one) via a plain fd, not a stream: a watcher issues
 * this far more often, on far smaller reads, than scan.js's one-shot
 * whole-file readLines(), so the lighter-weight sync primitive fits
 * better here. Returns null if the file vanished or became unreadable
 * between the caller's stat and this open.
 */
const MAX_TAIL_BYTES_PER_SWEEP = 64 * 1024 * 1024;
function tailRead(file, fromOffset) {
  let fd;
  try {
    fd = fs.openSync(file, "r");
    const stat = fs.fstatSync(fd);
    const available = stat.size - fromOffset;
    if (available <= 0) return { buffer: Buffer.alloc(0), size: stat.size };
    const toRead = Math.min(available, MAX_TAIL_BYTES_PER_SWEEP);
    const buf = Buffer.alloc(toRead);
    const n = fs.readSync(fd, buf, 0, toRead, fromOffset);
    return { buffer: buf.subarray(0, n), size: stat.size, mtimeMs: stat.mtimeMs };
  } catch {
    return null;
  } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* already gone */ } }
  }
}

/**
 * Advance one TAILABLE file's tracked entry by whatever new complete lines
 * are available, mutating `entry` in place. Returns a batch object for
 * scan(), or null when there was nothing new to read yet (grew by less
 * than one full line -- normal for a session mid-write).
 *
 * The overlap: when this file already produced a batch on some earlier
 * sweep, `entry.lastLine` holds that batch's final line, prepended here so
 * scan()'s own split-across-lines boundary pass (see decode.js) can join a
 * secret that straddles the seam between sweeps. That line inevitably gets
 * independently re-matched too (scan() matches every line in a batch, not
 * just the boundary pass), which is exactly why `lineNumberFor` returns
 * null for it below: the caller drops any finding that resolves to null,
 * since it was already alerted on last sweep.
 */
function advanceTail(entry, file, sizeBytes) {
  const tail = tailRead(file, entry.offset);
  if (tail === null) { entry.vanished = true; return null; }
  const { lines: newLines, consumedBytes } = splitCompleteLines(tail.buffer);
  if (entry.prefixHash === null) entry.prefixHash = prefixHash(file);
  if (newLines.length === 0) return null;

  const hasOverlap = entry.lastLine !== null;
  const lines = hasOverlap ? [entry.lastLine, ...newLines] : newLines;
  const lineCountBefore = entry.lineCount;

  entry.offset += consumedBytes;
  entry.sizeBytes = sizeBytes;
  entry.lineCount += newLines.length;
  entry.lastLine = newLines[newLines.length - 1];

  return {
    lines, bytesRead: consumedBytes, sizeBytes, mtimeMs: tail.mtimeMs, absolute: false,
    // batch-relative line k (1-based) -> "line since watch started for
    // this file"; null on the overlap line (batch line 1, when present)
    // since that line was already reported last sweep. A genuine boundary
    // match spanning the seam still comes through on its SECOND line.
    lineNumberFor(batchLine) {
      const k = batchLine - 1;
      if (hasOverlap && k === 0) return null;
      return lineCountBefore + (hasOverlap ? k : k + 1);
    },
  };
}

/**
 * Full re-read of a non-tailable (rewritten-in-place) file, through the
 * REAL source's own readLines() -- its size cap, read timeout, and
 * partial/too-large/failed handling all apply exactly as they would in a
 * real `residoo scan`. The whole file is fresh content every time, so
 * scan()'s own line numbers are already true absolute positions; no
 * remapping needed.
 */
async function readWholeFile(source, file, sizeBytes, mtimeMs) {
  let result;
  try {
    result = await source.readLines(file);
  } catch {
    return null;
  }
  if (result.status === "failed" || result.status === "too-large") return null;
  if (result.lines.length === 0) return null;
  return {
    lines: result.lines, bytesRead: result.bytesRead, sizeBytes, mtimeMs, absolute: true,
    lineNumberFor(batchLine) { return batchLine; },
  };
}

/**
 * One synthetic source per REAL source per sweep, wrapping whatever new
 * line batches were collected for it. `id()` delegates to the real
 * source's id so finding.source, rotation guidance, and fingerprints all
 * come out identical to a real `residoo scan` of the same content.
 */
function makeSyntheticSource(realId, batchesByFile) {
  return {
    id: () => realId,
    label: () => realId,
    available: () => true,
    *files() {
      for (const [file, b] of batchesByFile) {
        yield { file, mtimeMs: b.mtimeMs, sizeBytes: b.sizeBytes, broken: false };
      }
    },
    async readLines(file) {
      const b = batchesByFile.get(file);
      return { lines: b.lines, status: "complete", bytesRead: b.bytesRead };
    },
  };
}

/**
 * Silently seed the dedup ledger from a rescan-class file's CURRENT
 * content the first time watch ever sees it, without alerting on any of
 * it. Baseline never alerts (that promise is unchanged), but for a
 * whole-file source specifically, a later edit ANYWHERE in the file
 * forces a full rescan of everything in it, including a secret that was
 * already sitting there at baseline -- without this seeding step, that
 * unrelated edit would make an old, already-known secret look brand new.
 * (Tailable files don't need this: their baseline skips straight to EOF,
 * so past content is never re-read at all, let alone re-surfaced.)
 * `verify` is always forced off here: seeding a dedup cache must never be
 * the reason a live vendor API gets hit.
 */
async function baselineSeed(source, sourceId, file, sizeBytes, mtimeMs, seen, includeNoisy, includeSuppressed, noColor, includePii) {
  const batch = await readWholeFile(source, file, sizeBytes, mtimeMs);
  if (!batch) return;
  let result;
  try {
    result = await scan({
      sources: [makeSyntheticSource(sourceId, new Map([[file, batch]]))],
      includeNoisy, includeSuppressed, verify: false, noColor, includePii,
    });
  } catch {
    return; // best-effort: a failure here just leaves this file's dedup
             // slate empty, no worse off than before baseline seeding existed
  }
  for (const finding of result.findings) {
    const dedupKey = finding.ruleId + "\0" + finding.preview;
    if (!seen.has(dedupKey)) seen.set(dedupKey, { count: 1, fingerprint: fingerprintFinding(finding) });
  }
}

/**
 * One sweep: re-enumerate every source's files(), tail/rescan whatever
 * changed, feed the results through the real scan() engine, and emit
 * events. Pure enough to unit test directly with no timers: call it
 * yourself in a loop, or let startWatch() below drive it.
 *
 * `tracked` (path -> per-file state) and `seen` (dedup key -> alert count)
 * are the state that persists ACROSS calls, both plain Maps owned by the
 * caller so tests can inspect them directly. `ledger` is
 * `{ acks, dismissed }` (fingerprint -> entry), reloaded by the caller on
 * the rotations.json mtime changing, so a mid-watch `residoo ack`/
 * `dismiss` takes effect without a restart.
 */
async function sweepOnce({ sources, tracked, seen, ledger, options, emit }) {
  const { includeNoisy, includeSuppressed, verify, noColor, includePii } = options || {};
  let loud = 0;
  let quiet = 0;
  let suppressedByLedger = 0;

  for (const source of sources) {
    const sourceId = source.id();
    const batchesByFile = new Map();
    const stillPresent = new Set();

    let entries;
    try {
      entries = [...source.files()];
    } catch (err) {
      emit({ type: "watch-error", at: new Date(), source: sourceId, detail: "files() failed: " + (err && err.message) });
      continue;
    }

    for (const entry of entries) {
      if (entry.broken) continue; // same as scan.js: a dangling symlink, nothing to tail
      const { file, mtimeMs, sizeBytes } = entry;
      stillPresent.add(file);
      const prev = tracked.get(file);
      const tailable = isTailable(file);

      if (!prev) {
        const migrated = migrateVanishedEntry(tracked, sourceId, file, sizeBytes);
        if (migrated) {
          tracked.set(file, migrated);
          migrated.mtimeMs = mtimeMs;
          migrated.sizeBytes = sizeBytes;
          // A rename alone is not new content -- if the file ALSO grew or
          // (for a tailable file) changed since the old name's last known
          // state, that's handled the normal way on this sweep's tail/
          // rescan branches below via `prev`/`tracked`, not here.
          if (tailable && sizeBytes > migrated.offset) {
            const batch = advanceTail(migrated, file, sizeBytes);
            if (batch) batchesByFile.set(file, batch);
          }
          continue;
        }

        // Genuinely new file, of EITHER class: baseline WITHOUT alerting.
        // Watch-from-now is a promise about every source uniformly --
        // `residoo scan` is what covers whatever is already on disk,
        // including in a settings file this is the first time seeing.
        // Emitting an alert for a rescan-class file's CURRENT content
        // immediately would quietly break that promise for exactly one
        // class of source and duplicate what scan already does, the first
        // time `residoo watch` ever runs on a machine with existing
        // config-file findings -- caught live, not merely reasoned about,
        // running this for real. For that same class, content IS read once
        // here (never for tailable files, whose baseline skips straight to
        // EOF): not to alert, only to seed the dedup ledger, so a later
        // edit ELSEWHERE in the file doesn't make an already-known secret
        // look newly discovered (see baselineSeed's own doc comment).
        let ino = null, dev = null;
        try { const st = fs.statSync(file); ino = st.ino; dev = st.dev; } catch { /* raced with deletion */ }
        tracked.set(file, {
          sourceId, tailable, offset: sizeBytes, sizeBytes, mtimeMs,
          ino, dev, lineCount: 0, prefixHash: null, lastLine: null, vanished: false,
          contentHash: tailable ? null : wholeFileHash(file),
        });
        if (!tailable) {
          await baselineSeed(source, sourceId, file, sizeBytes, mtimeMs, seen, includeNoisy, includeSuppressed, noColor, includePii);
        }
        continue;
      }

      prev.vanished = false;

      if (!prev.tailable) {
        if (sizeBytes !== prev.sizeBytes) {
          // The byte count itself changed: unambiguous, always a real
          // rescan (no need to hash-gate first; something is different by
          // definition).
          const batch = await readWholeFile(source, file, sizeBytes, mtimeMs);
          if (batch) batchesByFile.set(file, batch);
          prev.mtimeMs = mtimeMs;
          prev.sizeBytes = sizeBytes;
          prev.contentHash = wholeFileHash(file);
        } else if (mtimeMs !== prev.mtimeMs) {
          // Same size, but touched: could be a same-length content swap (a
          // rotated secret of equal length) or pure mtime churn. The whole-
          // file hash tells the two apart without ever running the
          // detection engine on bytes that did not change.
          const h = wholeFileHash(file);
          if (h !== null && prev.contentHash !== null && h === prev.contentHash) {
            prev.mtimeMs = mtimeMs;
            continue;
          }
          const batch = await readWholeFile(source, file, sizeBytes, mtimeMs);
          if (batch) batchesByFile.set(file, batch);
          prev.mtimeMs = mtimeMs;
          prev.contentHash = h;
        }
        continue;
      }

      // Tailable file, already tracked.
      if (sizeBytes < prev.offset) {
        rebaseline(prev, sizeBytes, mtimeMs); // shrank: truncated/reset, not new content
        continue;
      }
      if (sizeBytes > prev.offset) {
        const h = prefixHash(file);
        if (prev.prefixHash !== null && h !== null && h !== prev.prefixHash) {
          rebaseline(prev, sizeBytes, mtimeMs); // grew, but the START of the file changed too: a rewrite, not a real append
          continue;
        }
        const batch = advanceTail(prev, file, sizeBytes);
        prev.mtimeMs = mtimeMs;
        if (batch) batchesByFile.set(file, batch);
      }
      // sizeBytes === prev.offset: no new bytes; mtime-only churn ignored.
    }

    // Anything tracked for this source that files() did not yield this
    // sweep either vanished or was renamed/moved. Keep its offset one more
    // sweep so a rename showing up as a "new" path above can migrate it,
    // then let it drop out of `tracked` for good.
    for (const [file, trackedEntry] of tracked) {
      if (trackedEntry.sourceId !== sourceId || stillPresent.has(file)) continue;
      if (trackedEntry.vanished) tracked.delete(file);
      else trackedEntry.vanished = true;
    }

    if (batchesByFile.size === 0) continue;

    let result;
    try {
      result = await scan({
        sources: [makeSyntheticSource(sourceId, batchesByFile)],
        includeNoisy, includeSuppressed, verify, noColor, includePii,
      });
    } catch (err) {
      emit({ type: "watch-error", at: new Date(), source: sourceId, detail: "scan failed: " + (err && err.message) });
      continue;
    }

    for (const finding of result.findings) {
      const b = batchesByFile.get(finding.file);
      const line = b.lineNumberFor(finding.line);
      if (line === null) continue; // seam re-report: lies entirely on the overlap line, already alerted last sweep

      const fp = fingerprintFinding(finding);
      if ((ledger.acks && ledger.acks[fp]) || (ledger.dismissed && ledger.dismissed[fp])) {
        suppressedByLedger++;
        continue;
      }

      const dedupKey = finding.ruleId + "\0" + finding.preview;
      const already = seen.get(dedupKey);
      if (already) {
        already.count++;
        quiet++;
        emit({ type: "reexposure", at: new Date(), ruleId: finding.ruleId, preview: finding.preview, count: already.count });
        continue;
      }
      seen.set(dedupKey, { count: 1, fingerprint: fp });
      loud++;
      emit({
        type: "finding", at: new Date(), ruleId: finding.ruleId, label: finding.label,
        confidence: finding.confidence, source: finding.source, relFile: safeBasename(finding.relFile),
        line, lineIsAbsolute: b.absolute, preview: finding.preview,
        fingerprint: fp, guidance: guidanceFor(finding.ruleId),
      });
    }
  }

  return { loud, quiet, suppressedByLedger };
}

function rebaseline(entry, sizeBytes, mtimeMs) {
  entry.offset = sizeBytes;
  entry.sizeBytes = sizeBytes;
  entry.mtimeMs = mtimeMs;
  entry.lineCount = 0;
  entry.lastLine = null;
  entry.prefixHash = null; // re-hashed lazily next time the file looks like it grew
}

/**
 * A path files() just yielded that was never tracked before might be a
 * rename/move of a path that WAS tracked and then vanished (openclaw
 * session resets rename to `*.jsonl.reset.<ts>`; qwen-code moves inactive
 * sessions into chats/archive/). Recognized by inode identity, not name,
 * and only when the new size is at least the old offset -- a smaller
 * "match" is coincidence (inode reuse after deletion), not a real rename.
 * Migrating carries the offset forward so the content already alerted on
 * under the old name is never re-scanned under the new one.
 */
function migrateVanishedEntry(tracked, sourceId, file, sizeBytes) {
  let st;
  try { st = fs.statSync(file); } catch { return null; }
  for (const [oldPath, entry] of tracked) {
    if (!entry.vanished || entry.sourceId !== sourceId) continue;
    if (entry.ino === st.ino && entry.dev === st.dev && sizeBytes >= entry.offset) {
      tracked.delete(oldPath);
      entry.vanished = false;
      return entry;
    }
  }
  return null;
}

// ── rendering ────────────────────────────────────────────────────────────

/** Human-readable line for one event, or null for an event that prints
 * nothing (there is no such event today, but keeping the contract explicit
 * matches the "nothing on a findings-free sweep" rule this file is built
 * around: silence is the default, every printed line is deliberate). */
function renderHumanLine(event, paint) {
  const ts = localTimestamp(event.at);
  if (event.type === "finding") {
    const g = event.guidance || {};
    const rotate = g.rotateUrl || g.consolePath || "no rotation guidance shipped for this rule yet";
    const where = event.lineIsAbsolute ? `line ${event.line}` : `line ${event.line} since watch started`;
    return paint(c.red + c.bold, `⚠ ${ts}  ${event.label}`) +
      `  ${event.preview}  in ${event.relFile} (${event.source}), ${where}\n` +
      paint(c.dim, `    ${event.fingerprint}  rotate: ${rotate}`);
  }
  if (event.type === "reexposure") {
    return paint(c.dim, `  ${ts}  ${event.ruleId}  ${event.preview}  re-exposed (seen ${event.count}x so far)`);
  }
  if (event.type === "watch-error") {
    return paint(c.yellow, `residoo watch: ${event.source ? event.source + ": " : ""}${event.detail}`);
  }
  return null;
}

/** `{ acks, dismissed }`, reloaded only when rotations.json's own mtime
 * changed since the last check -- cheap (one stat per tick) and means a
 * mid-watch `residoo ack`/`dismiss` takes effect within one poll interval,
 * not only on restart. Missing ledger file is not an error: it just means
 * nothing has been triaged yet, same as loadAcks()/loadDismissed() already
 * treat it.
 */
function reloadLedgerIfChanged(prev) {
  let mtimeMs = null;
  try { mtimeMs = fs.statSync(statePath()).mtimeMs; } catch { /* no ledger yet */ }
  if (prev && prev.mtimeMs === mtimeMs) return prev;
  return { acks: loadAcks(), dismissed: loadDismissed(), mtimeMs };
}

/**
 * Start watching. Returns `{ promise, stop, stats }`: `promise` resolves
 * with the final `stats` when `stop()` is called (by a caller, or by the
 * SIGINT/SIGTERM handlers cli.js wires up); `stats` is also readable live.
 * All I/O is injectable (`sources`, `out`, `errOut`) so tests drive this
 * in-process with a tiny `options.pollMs` and real temp
 * directories, never a spawned child process.
 *
 * fs.watch is deliberately NOT used in v1: every source's public contract
 * ({id, label, available, files, readLines}) has no way to ask "what root
 * directory do you watch", so there is no clean hook to attach an
 * fs.watch() to without reaching into adapter internals. Polling alone is
 * not a degraded fallback here, it is the correctness backstop this whole
 * design already leans on (fs.watch is well known to be inert on Linux for
 * writes to subdirectories of a non-recursively-watched root, and
 * unavailable on some filesystems entirely) -- v1 ships with exactly that
 * backstop and nothing riding on top of it. `options.fsWatch` is accepted
 * and ignored, reserved for when a future version adds real hints.
 */
function startWatch({ sources, options = {}, out = process.stdout, errOut = process.stderr } = {}) {
  const paint = makePaint(options.noColor, out);
  const tracked = new Map();
  const seen = new Map();
  let ledger = reloadLedgerIfChanged(null);
  let sweeping = false;
  let pendingTick = false;
  let stopped = false;
  let timer = null;
  const stats = { loud: 0, quiet: 0, suppressedByLedger: 0, sweeps: 0, errors: 0 };

  function emit(event) {
    if (event.type === "watch-error") stats.errors++;
    if (options.json) {
      out.write(JSON.stringify(event) + "\n");
      return;
    }
    const line = renderHumanLine(event, paint);
    if (line !== null) out.write(line + "\n");
  }

  async function tick() {
    if (sweeping) { pendingTick = true; return; }
    sweeping = true;
    try {
      ledger = reloadLedgerIfChanged(ledger);
      const result = await sweepOnce({ sources, tracked, seen, ledger, options, emit });
      stats.loud += result.loud;
      stats.quiet += result.quiet;
      stats.suppressedByLedger += result.suppressedByLedger;
      stats.sweeps++;
    } catch (err) {
      // An uncaught throw here would be an unhandled promise rejection
      // (process crash on modern Node) if it ever escaped the timer
      // callback that drives this in the real CLI. One stderr note, the
      // loop keeps running -- one bad sweep must not end the whole watch.
      stats.errors++;
      errOut.write(`residoo watch: sweep failed unexpectedly: ${err && err.message}\n`);
    } finally {
      sweeping = false;
      if (pendingTick && !stopped) { pendingTick = false; tick(); }
    }
  }

  // No floor enforced here: that belongs to CLI argument validation
  // (runWatch in cli.js, --interval's stated 1-second floor), not this
  // engine. Tests need real sub-second polling to stay fast; `pollMs` is
  // the raw, unclamped knob for that.
  const intervalMs = options.pollMs || 5000;
  let resolvePromise;
  const promise = new Promise((resolve) => { resolvePromise = resolve; });

  function scheduleNext() {
    if (stopped) return;
    timer = setTimeout(() => { tick().finally(scheduleNext); }, intervalMs);
  }

  function stop() {
    if (stopped) return stats;
    stopped = true;
    if (timer) clearTimeout(timer);
    resolvePromise(stats);
    return stats;
  }

  // First sweep runs immediately (this is the baseline sweep -- see
  // sweepOnce's own doc comment), not after waiting a full interval.
  tick().finally(scheduleNext);

  return { promise, stop, stats };
}

module.exports = {
  sweepOnce, startWatch, isTailable, splitCompleteLines, localTimestamp, safeBasename,
};
