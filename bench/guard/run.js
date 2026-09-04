"use strict";

/**
 * Scores `residoo guard`'s decision function (src/guard.js's
 * evaluateToolInput) against bench/guard/corpus.js. Two numbers, reported
 * separately on purpose, same reasoning as the main scan benchmark
 * (bench/harness/score.js): a blended single score would hide exactly the
 * tradeoff this exists to measure.
 *
 *   recall           -- of the genuinely sensitive cases, how many were
 *                       blocked. Misses here are the security cost.
 *   false-positive rate -- of the ordinary/near-miss/safe cases, how many
 *                       were wrongly blocked. Hits here are the usability
 *                       cost -- the reason a blocklist tool gets disabled.
 *
 * Run: node bench/guard/run.js [--md]
 */

const path = require("path");
const { evaluateToolInput } = require("../../src/guard");
const { shouldBlock, shouldAllow } = require("./corpus");

function score() {
  const blockResults = shouldBlock.map((c) => ({ ...c, got: evaluateToolInput(c.tool, c.input).block }));
  const allowResults = shouldAllow.map((c) => ({ ...c, got: evaluateToolInput(c.tool, c.input).block }));

  const missedBlocks = blockResults.filter((r) => r.got !== true);
  const falsePositives = allowResults.filter((r) => r.got !== false);

  return {
    recall: { total: shouldBlock.length, caught: shouldBlock.length - missedBlocks.length, missed: missedBlocks },
    precision: { total: shouldAllow.length, correct: shouldAllow.length - falsePositives.length, falsePositives },
  };
}

function render(result) {
  const { recall, precision } = result;
  const lines = [];
  lines.push(`residoo guard corpus: ${recall.total} should-block cases, ${precision.total} should-allow cases`);
  lines.push(`  recall (sensitive reads correctly blocked): ${recall.caught}/${recall.total} (${pct(recall.caught, recall.total)})`);
  lines.push(`  false-positive rate (safe commands wrongly blocked): ${precision.falsePositives.length}/${precision.total} (${pct(precision.falsePositives.length, precision.total)})`);
  if (recall.missed.length > 0) {
    lines.push(`\n  MISSED (should have blocked, did not):`);
    for (const m of recall.missed) lines.push(`    - [${m.tool}] ${JSON.stringify(m.input)} -- ${m.why}`);
  }
  if (precision.falsePositives.length > 0) {
    lines.push(`\n  FALSE POSITIVES (should have allowed, blocked instead):`);
    for (const f of precision.falsePositives) lines.push(`    - [${f.tool}] ${JSON.stringify(f.input)} -- ${f.why}`);
  }
  return lines.join("\n");
}

function pct(n, total) { return total === 0 ? "n/a" : `${Math.round((n / total) * 1000) / 10}%`; }

function renderMd(result) {
  const { recall, precision } = result;
  const { version } = require("../../package.json");
  const lines = [];
  lines.push(`# residoo guard: scored corpus results (residoo ${version})`);
  lines.push("");
  lines.push(`| metric | result |`);
  lines.push(`|---|---|`);
  lines.push(`| Recall (sensitive reads correctly blocked) | **${recall.caught}/${recall.total} (${pct(recall.caught, recall.total)})** |`);
  lines.push(`| False-positive rate (safe commands wrongly blocked) | **${precision.falsePositives.length}/${precision.total} (${pct(precision.falsePositives.length, precision.total)})** |`);
  lines.push("");
  if (recall.missed.length > 0) {
    lines.push(`## Missed (should have blocked)`);
    for (const m of recall.missed) lines.push(`- \`${JSON.stringify(m.input)}\` (${m.tool}) -- ${m.why}`);
    lines.push("");
  }
  if (precision.falsePositives.length > 0) {
    lines.push(`## False positives (should have allowed)`);
    for (const f of precision.falsePositives) lines.push(`- \`${JSON.stringify(f.input)}\` (${f.tool}) -- ${f.why}`);
    lines.push("");
  }
  return lines.join("\n");
}

if (require.main === module) {
  const result = score();
  const wantsMd = process.argv.includes("--md");
  console.log(wantsMd ? renderMd(result) : render(result));
  const clean = result.recall.missed.length === 0 && result.precision.falsePositives.length === 0;
  process.exitCode = clean ? 0 : 1;
}

module.exports = { score, render, renderMd };
