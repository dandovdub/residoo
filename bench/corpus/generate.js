#!/usr/bin/env node
'use strict';
/*
 * residoo bench corpus generator
 *
 * Generates a fully synthetic, deterministic corpus of AI-agent session
 * transcripts (Claude Code JSONL schema, shapes observed from real
 * transcripts, content 100% invented) plus a ground-truth manifest
 * (../truth.json relative to the data root) for scoring secret scanners.
 *
 * Determinism: every byte of output is a pure function of SEED. No
 * Math.random, no Date.now, no filesystem ordering dependence. Running
 * this script twice produces byte-identical trees.
 *
 * Safety: every "secret" in the corpus is a pattern-true FAKE, generated
 * from the seeded PRNG. Correct prefix, charset, and length for its rule
 * family, but the values were never issued by any provider (the CredData
 * approach; AWS's documented example key AKIAIOSFODNN7EXAMPLE is the
 * canonical model and appears only as a SUPPRESS-EXPECTED fixture).
 * Committing them is safe and lets harnesses do exact-match scoring.
 *
 * Layout:
 *   bench/corpus/data/home/                     the fixture HOME
 *     .claude/projects/<slug>/<uuid>.jsonl      session transcripts
 *     .claude/settings.json                     benign global config
 *     .claude/settings.local.json               config with planted token
 *     projects/acme-api/.mcp.json               project config fixture
 *     projects/acme-api/.claude/settings.local.json
 *   bench/corpus/truth.json                     ground truth (OUTSIDE the
 *                                               scanned home on purpose:
 *                                               it contains every planted
 *                                               value and must not
 *                                               contaminate scan results)
 *
 * Usage: node generate.js [outRoot]
 *   outRoot defaults to this file's directory. data/ and truth.json are
 *   rewritten from scratch on every run.
 */

const fs = require('fs');
const path = require('path');

const SEED = 20260902;
const CORPUS_VERSION = '1.0.0';

const OUT_ROOT = path.resolve(process.argv[2] || __dirname);
const DATA_ROOT = path.join(OUT_ROOT, 'data');
const HOME = path.join(DATA_ROOT, 'home');

/* ------------------------------------------------------------------ *
 * Seeded PRNG (mulberry32) and helpers. All randomness flows through
 * `rand`; call order is fixed, so output is fixed.
 * ------------------------------------------------------------------ */

function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(SEED);
const ri = (a, b) => a + Math.floor(rand() * (b - a + 1));
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const chance = (p) => rand() < p;

const UP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LO = 'abcdefghijklmnopqrstuvwxyz';
const DIG = '0123456789';
const ALNUM = UP + LO + DIG;
const HEXL = '0123456789abcdef';
const B64URLCS = ALNUM + '-_';

const chars = (cs, n) => { let s = ''; for (let i = 0; i < n; i++) s += cs[Math.floor(rand() * cs.length)]; return s; };
const digits = (n) => chars(DIG, n);
const hex = (n) => chars(HEXL, n);

function uuid() {
  const h = hex(32).split('');
  h[12] = '4';
  h[16] = pick(['8', '9', 'a', 'b']);
  const s = h.join('');
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20)}`;
}
const msgId = () => 'msg_01' + chars(ALNUM, 22);
const reqId = () => 'req_01' + chars(ALNUM, 22);
const tooluId = () => 'toolu_01' + chars(ALNUM, 22);

const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
const b64url = (s) => Buffer.from(s, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const wrap76 = (s) => (s.match(/.{1,76}/g) || []).join('\n');

/* ------------------------------------------------------------------ *
 * Fake-secret factories, one per rule family. Pattern-true, never real.
 * Each returns { value, grep, envLine } where:
 *   value   the logical secret (what a scanner should report)
 *   grep    a contiguous substring guaranteed to appear literally and
 *           unescaped on the raw JSONL line, for exact-match scoring
 *   envLine a natural way the value appears in env/config text
 * ------------------------------------------------------------------ */

const FAMILIES = {
  'aws-access-key-id': () => {
    // Real AWS access key ids are base32 after the prefix (A-Z, 2-7).
    // A looser charset (0/1/8/9) would be pattern-FALSE: charset-correct
    // scanners rightly reject it and the corpus would penalize them unfairly.
    const v = 'AKIA' + chars(UP + '234567', 16);
    return { value: v, grep: v, envLine: `AWS_ACCESS_KEY_ID=${v}` };
  },
  'github-pat': () => {
    const v = 'ghp_' + chars(ALNUM, 36);
    return { value: v, grep: v, envLine: `GITHUB_TOKEN=${v}` };
  },
  'private-key-block': () => {
    const body = [chars(B64URLCS.replace('-_', '') + '+/', 70), chars(ALNUM + '+/', 70), chars(ALNUM + '+/', 70), chars(ALNUM + '+/', 28) + '='];
    const v = '-----BEGIN OPENSSH PRIVATE KEY-----\n' + body.join('\n') + '\n-----END OPENSSH PRIVATE KEY-----';
    return { value: v, grep: body[1], envLine: v, multiline: true };
  },
  'jwt': () => {
    const head = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const payload = b64url(JSON.stringify({ sub: 'svc-' + chars(LO, 6), iat: 1770000000 + ri(0, 999999), scope: 'internal' }));
    const v = `${head}.${payload}.${chars(B64URLCS, 43)}`;
    return { value: v, grep: v, envLine: `SESSION_JWT=${v}` };
  },
  'connection-string': () => {
    const pw = chars(ALNUM, 18);
    const host = 'db-' + chars(LO, 5) + '.internal';
    const v = `postgresql://svc_app:${pw}@${host}:5432/appdb`;
    return { value: v, grep: v, envLine: `DATABASE_URL=${v}`, password: pw };
  },
  'anthropic-key': () => {
    const v = 'sk-ant-api03-' + chars(B64URLCS, 93) + 'AA';
    return { value: v, grep: v, envLine: `ANTHROPIC_API_KEY=${v}` };
  },
  'slack-token': () => {
    const v = `xoxb-${digits(12)}-${digits(13)}-${chars(ALNUM, 24)}`;
    return { value: v, grep: v, envLine: `SLACK_BOT_TOKEN=${v}` };
  },
  'stripe-test-key': () => {
    const v = 'sk_test_' + chars(ALNUM, 24);
    return { value: v, grep: v, envLine: `STRIPE_SECRET_KEY=${v}` };
  },
  'discord-webhook': () => {
    const v = `https://discord.com/api/webhooks/${digits(19)}/${chars(ALNUM + '-_', 68)}`;
    return { value: v, grep: v, envLine: `ALERTS_WEBHOOK=${v}` };
  },
  'npm-token': () => {
    const v = 'npm_' + chars(ALNUM, 36);
    return { value: v, grep: v, envLine: `//registry.npmjs.org/:_authToken=${v}` };
  },
  'gitlab-pat': () => {
    const v = 'glpat-' + chars(ALNUM + '-_', 20);
    return { value: v, grep: v, envLine: `GITLAB_PAT=${v}` };
  },
  'bearer-header': () => {
    const tok = hex(40);
    return { value: tok, grep: tok, envLine: `Authorization: Bearer ${tok}`, header: `Authorization: Bearer ${tok}` };
  },
};
const FAMILY_NAMES = Object.keys(FAMILIES);

/* ------------------------------------------------------------------ *
 * Transcript record builders. Field names, nesting, and enum values
 * follow shapes extracted (structure only, never content) from real
 * Claude Code transcripts under ~/.claude/projects on 2026-09-02
 * (versions 2.0.x and 2.1.x).
 * ------------------------------------------------------------------ */

const PROJECTS = [
  { slug: '-Users-alex-projects-acme-api', cwd: '/Users/alex/projects/acme-api', branch: 'main' },
  { slug: '-Users-alex-projects-billing-web', cwd: '/Users/alex/projects/billing-web', branch: 'develop' },
  { slug: '-Users-alex-projects-infra-tools', cwd: '/Users/alex/projects/infra-tools', branch: 'main' },
  { slug: '-Users-alex-Downloads-scratch', cwd: '/Users/alex/Downloads/scratch', branch: '' },
];

const CC_VERSIONS = ['2.0.14', '2.1.221', '2.1.227'];
const MODELS = ['claude-opus-5', 'claude-sonnet-4-5'];
const BASE_MS = Date.UTC(2026, 7, 3, 8, 0, 0); // 2026-08-03T08:00:00Z, fixed

function usageBlock() {
  const inTok = ri(2, 9);
  const out = ri(20, 700);
  const cacheCreate = ri(200, 4000);
  const cacheRead = ri(8000, 90000);
  return {
    input_tokens: inTok,
    cache_creation_input_tokens: cacheCreate,
    cache_read_input_tokens: cacheRead,
    output_tokens: out,
    server_tool_use: { web_search_requests: 0, web_fetch_requests: 0 },
    service_tier: 'standard',
    cache_creation: { ephemeral_1h_input_tokens: 0, ephemeral_5m_input_tokens: cacheCreate },
    inference_geo: 'us-east-1',
    iterations: [{
      input_tokens: inTok, output_tokens: out,
      cache_read_input_tokens: cacheRead, cache_creation_input_tokens: cacheCreate,
      cache_creation: { ephemeral_5m_input_tokens: cacheCreate, ephemeral_1h_input_tokens: 0 },
      type: 'message',
    }],
    speed: 'standard',
  };
}

class Session {
  constructor(proj, idx) {
    this.proj = proj;
    this.sessionId = uuid();
    this.version = pick(CC_VERSIONS);
    this.model = pick(MODELS);
    this.entrypoint = pick(['cli', 'claude-desktop']);
    this.tsMs = BASE_MS + idx * 3600 * 1000 * ri(2, 8) + ri(0, 3599) * 1000;
    this.records = [];
    this.lastMsgUuid = null;
    this.promptId = uuid();
    this.plants = []; // local registrations, resolved to lines at write time
  }
  ts() {
    this.tsMs += ri(2, 70) * 1000 + ri(0, 999);
    return new Date(this.tsMs).toISOString();
  }
  env() {
    return {
      userType: 'external', entrypoint: this.entrypoint, cwd: this.proj.cwd,
      sessionId: this.sessionId, version: this.version, gitBranch: this.proj.branch,
    };
  }
  pushMeta(rec) { this.records.push(rec); return this.records.length - 1; }
  pushMsg(rec) {
    // Real records carry uuid immediately before timestamp; rebuild the
    // object so serialized key order matches observed transcripts.
    const u = uuid();
    const out = {};
    let placed = false;
    for (const k of Object.keys(rec)) {
      if (k === 'timestamp') { out.uuid = u; placed = true; }
      out[k] = rec[k];
    }
    if (!placed) out.uuid = u;
    this.records.push(out);
    this.lastMsgUuid = u;
    return this.records.length - 1;
  }
  user(text) {
    this.promptId = uuid();
    return this.pushMsg({
      parentUuid: this.lastMsgUuid, isSidechain: false, promptId: this.promptId,
      type: 'user', message: { role: 'user', content: text },
      timestamp: this.ts(), permissionMode: 'default', origin: { kind: 'human' },
      promptSource: 'sdk', ...this.env(),
    });
  }
  assistantBlock(block, stopReason, sharedId) {
    return this.pushMsg({
      parentUuid: this.lastMsgUuid, isSidechain: false,
      message: {
        model: this.model, id: sharedId || msgId(), type: 'message', role: 'assistant',
        content: [block], stop_reason: stopReason, stop_sequence: null, stop_details: null,
        usage: usageBlock(), diagnostics: null,
      },
      requestId: reqId(), type: 'assistant', timestamp: this.ts(), effort: 'high', ...this.env(),
    });
  }
  assistantText(text) { return this.assistantBlock({ type: 'text', text }, 'end_turn'); }
  assistantThinking(text) { return this.assistantBlock({ type: 'thinking', thinking: text, signature: chars(ALNUM + '+/', 96) }, 'tool_use'); }
  toolUse(name, input) {
    const id = tooluId();
    const idx = this.assistantBlock({ type: 'tool_use', id, name, input, caller: { type: 'direct' } }, 'tool_use');
    return { id, assistantUuid: this.records[idx].uuid };
  }
  toolResult(tu, content, toolUseResult, isError) {
    const block = { tool_use_id: tu.id, type: 'tool_result', content };
    if (isError) block.is_error = true;
    return this.pushMsg({
      parentUuid: this.lastMsgUuid, isSidechain: false, promptId: this.promptId,
      type: 'user', message: { role: 'user', content: [block] },
      timestamp: this.ts(), toolUseResult, sourceToolAssistantUUID: tu.assistantUuid, ...this.env(),
    });
  }
  bash(command, stdout, stderr) {
    const tu = this.toolUse('Bash', { command, description: command.slice(0, 40) });
    const idx = this.toolResult(tu, stdout + (stderr ? '\n' + stderr : ''), {
      stdout, stderr: stderr || '', interrupted: false, isImage: false, noOutputExpected: false,
    });
    return idx;
  }
  read(filePath, lines) {
    const tu = this.toolUse('Read', { file_path: filePath });
    const numbered = lines.map((l, i) => `${i + 1}\t${l}`).join('\n');
    const idx = this.toolResult(tu, numbered, {
      type: 'text',
      file: { filePath, content: lines.join('\n'), numLines: lines.length, startLine: 1, totalLines: lines.length },
    });
    return idx;
  }
  edit(filePath, oldString, newString) {
    const tu = this.toolUse('Edit', { file_path: filePath, old_string: oldString, new_string: newString });
    return this.toolResult(tu, `The file ${filePath} has been updated successfully.`, {
      filePath, oldString, newString,
      originalFile: `// ${path.basename(filePath)}\n${oldString}\n`,
      replaceAll: false,
      structuredPatch: [{ oldStart: 1, oldLines: 2, newStart: 1, newLines: 2, lines: ['-' + oldString, '+' + newString] }],
      userModified: false,
    });
  }
  mcp(name, input, resultObj) {
    const tu = this.toolUse(name, input);
    return this.toolResult(tu, [{ type: 'text', text: JSON.stringify(resultObj, null, 2) }], resultObj);
  }
  registerPlant(p) { this.plants.push(p); }
}

/* ------------------------------------------------------------------ *
 * Benign exchange builders (chaff lives here).
 * ------------------------------------------------------------------ */

const SVC = ['auth-svc', 'billing', 'ingest', 'webhook-relay', 'reports', 'scheduler'];
const SRC_FILES = ['src/index.js', 'src/config.js', 'lib/db.js', 'lib/queue.js', 'src/routes/users.js', 'scripts/migrate.js', 'src/middleware/auth.js'];
const TESTS = ['npm test', 'npx vitest run', 'pytest -q', 'npm run lint'];

function gitShaChaff(s, registerChaff) {
  const shas = [hex(40), hex(40), hex(40)];
  const stdout = shas.map((sha, i) => `${sha.slice(0, 7)} fix: adjust retry backoff (#${ri(100, 900)})`).join('\n') + `\nfull head: ${shas[0]}`;
  s.user(pick(['What were the last few commits?', 'Show me recent git history.', 'What changed recently on this branch?']));
  const idx = s.bash('git log --oneline -3 && git rev-parse HEAD', stdout);
  s.assistantText('The last three commits are small fixes; HEAD is at the commit shown above.');
  registerChaff({ kind: 'git-sha', value: shas[0], recordIndex: idx, session: s });
}

function uuidLogChaff(s, registerChaff) {
  const reqUuid = uuid();
  const stdout = `[info] request_id=${reqUuid} route=/api/v1/orders status=200 dur_ms=${ri(3, 90)}\n[info] request_id=${uuid()} route=/healthz status=200 dur_ms=1`;
  s.user('Tail the service log and check for errors.');
  const idx = s.bash(`tail -n 2 /var/log/${pick(SVC)}.log`, stdout);
  s.assistantText('No errors in the tail; both requests returned 200.');
  registerChaff({ kind: 'uuid', value: reqUuid, recordIndex: idx, session: s });
}

function sha256Chaff(s, registerChaff) {
  const digest = hex(64);
  s.user('Verify the release tarball checksum.');
  const idx = s.bash('shasum -a 256 dist/release.tgz', `${digest}  dist/release.tgz`);
  s.assistantText('The digest matches the one published in the release notes.');
  registerChaff({ kind: 'sha256-hex', value: digest, recordIndex: idx, session: s });
}

function b64ImageChaff(s, registerChaff) {
  const frag = 'iVBORw0KGgoAAAANSUhEUg' + chars(ALNUM + '+/', 180);
  const lines = ['.logo {', `  background: url(data:image/png;base64,${frag});`, '  width: 32px;', '}'];
  s.user('Why is the logo blurry on retina screens?');
  const idx = s.read(s.proj.cwd + '/assets/logo.css', lines);
  s.assistantText('The embedded PNG is 1x only. Serve a 2x asset or switch to an SVG.');
  registerChaff({ kind: 'base64-image-fragment', value: frag.slice(0, 60), recordIndex: idx, session: s });
}

function testRunBenign(s) {
  s.user(pick(['Run the tests.', 'Can you run the test suite?', 'Check whether the tests still pass.']));
  const pass = ri(20, 140);
  s.bash(pick(TESTS), `> test\n\n${pass} passing (${ri(1, 9)}.${ri(0, 9)}s)\n0 failing`);
  s.assistantText(`All ${pass} tests pass.`);
}

function readEditBenign(s) {
  const f = s.proj.cwd + '/' + pick(SRC_FILES);
  s.user(`There is an off-by-one in ${path.basename(f)}, can you fix it?`);
  s.read(f, ['function pageSlice(items, page, size) {', '  const start = page * size + 1;', '  return items.slice(start, start + size);', '}']);
  s.edit(f, 'const start = page * size + 1;', 'const start = page * size;');
  s.assistantText('Fixed: the slice start no longer skips the first row of each page.');
}

function mcpBenign(s) {
  s.user('Any open PRs on the repo?');
  s.mcp('mcp__github__list_pull_requests', { repo: 'acme/acme-api', state: 'open' }, {
    total: 2,
    items: [
      { number: ri(100, 400), title: 'Bump node to 22', author: 'renovate[bot]', head_sha: hex(40) },
      { number: ri(401, 800), title: 'Add retry to webhook delivery', author: 'mira-dev', head_sha: hex(40) },
    ],
  });
  s.assistantText('Two open PRs: the Renovate node bump and the webhook retry change.');
}

function errorBenign(s) {
  s.user('Build the container image.');
  const tu = s.toolUse('Bash', { command: 'docker build -t acme/api:dev .', description: 'Build image' });
  s.toolResult(tu, 'ERROR: failed to solve: dockerfile parse error on line 12: unknown instruction: RUNN', { stdout: '', stderr: 'dockerfile parse error on line 12', interrupted: false, isImage: false, noOutputExpected: false }, true);
  s.assistantText('There is a typo in the Dockerfile: RUNN on line 12 should be RUN.');
}

function qaBenign(s) {
  s.user(pick([
    'What is the difference between our staging and prod deploy pipelines?',
    'Remind me how the queue retry policy works.',
    'Which node version does CI use?',
    'How do we rotate the on-call schedule?',
  ]));
  if (chance(0.4)) s.assistantThinking('The user asks about project conventions. The answer is in the repo docs I have seen earlier in this session.');
  s.assistantText(pick([
    'Staging deploys on every merge to develop; prod requires a tagged release plus a manual approval step.',
    'Failed jobs retry three times with exponential backoff starting at 30 seconds, then land in the dead letter queue.',
    'CI pins node 22.11 via .nvmrc; local dev can use anything newer than 20.',
    'The rotation flips every Monday 09:00 UTC; swaps go in the shared calendar.',
  ]));
}

const BENIGN_BUILDERS = [testRunBenign, readEditBenign, mcpBenign, qaBenign, errorBenign];

/* ------------------------------------------------------------------ *
 * Plant emitters. Each returns the recordIndex list where the planted
 * value physically lives, plus metadata for the manifest.
 * ------------------------------------------------------------------ */

function makeSecret(family) { return FAMILIES[family](); }

function envFileLines(sec, family) {
  const before = ['NODE_ENV=staging', 'PORT=4000', 'LOG_LEVEL=debug'];
  const after = ['FEATURE_FLAGS=checkout_v2,new_nav', 'CACHE_TTL=300'];
  if (sec.multiline) return [...before, ...sec.value.split('\n'), ...after];
  return [...before, sec.envLine, ...after];
}

function emitPlain(s, task) {
  const sec = makeSecret(task.family);
  let recordIndex;
  let vehicle = task.vehicle;
  if (task.family === 'private-key-block' && vehicle === 'stdout') vehicle = 'file_read';
  if (vehicle === 'user_paste') {
    const body = sec.multiline ? sec.value : sec.envLine;
    recordIndex = s.user(`I keep getting 401s from ${pick(SVC)} on staging. Here is the relevant part of my config, does the format look right?\n\n${body}\n\nNothing else changed since Friday.`);
    s.assistantText('The value format looks correct. The 401 is more likely the clock skew on the staging box; check ntp first. Also consider rotating that credential since it was just pasted into this chat.');
  } else if (vehicle === 'file_read') {
    s.user(pick(['The deploy script fails at the credentials check, can you look?', 'Why does the smoke test fail to authenticate on staging?', 'Something in the env file looks off, can you check it?']));
    const fname = s.proj.cwd + '/' + pick(['.env.staging', 'config/secrets.env', 'deploy/.env']);
    recordIndex = s.read(fname, envFileLines(sec, task.family));
    s.assistantText('The variable is present but the deploy script lowercases keys before comparing, so the check never matches. Fixing the script rather than the env file.');
  } else { // stdout
    let cmd, out;
    if (task.family === 'bearer-header') {
      cmd = `curl -v https://api.${pick(SVC)}.internal/v1/status`;
      out = `> GET /v1/status HTTP/1.1\n> Host: api.internal\n> ${sec.header}\n> Accept: */*\n< HTTP/1.1 200 OK\n{"ok":true}`;
    } else {
      cmd = pick(['cat .env.staging', 'printenv | sort | head', 'cat deploy/.env']);
      out = envFileLines(sec, task.family).join('\n');
    }
    s.user('Print the staging environment so we can compare against prod.');
    recordIndex = s.bash(cmd, out);
    s.assistantText('Compared with prod: two variables differ, the flag list and the cache TTL. The credentials are environment specific as expected.');
  }
  s.registerPlant({ class: task.class, family: task.family, vehicle, value: sec.value, grep: sec.grep, recordIndexes: [recordIndex], occurrences: 1, multiline: !!sec.multiline });
}

function emitJsonNested(s, task) {
  const sec = makeSecret(task.family);
  const innerKey = { 'anthropic-key': 'apiKey', 'github-pat': 'token', 'stripe-test-key': 'secretKey', 'connection-string': 'url', 'slack-token': 'botToken', 'npm-token': 'authToken' }[task.family] || 'token';
  const inner = JSON.stringify({ provider: task.family.split('-')[0], [innerKey]: sec.value, enabled: true });
  const outer = JSON.stringify({ service: pick(SVC), env: 'staging', integrations_raw: inner, updated: '2026-07-30T11:04:00Z' }, null, 2);
  s.user('Dump the runtime config endpoint so we can see what the service actually loaded.');
  const recordIndex = s.bash('curl -s http://localhost:4000/internal/debug/config', outer);
  s.assistantText('The service loaded the staging integration blob. Note the config endpoint returns raw integration settings; that endpoint should be locked down.');
  s.registerPlant({ class: task.class, family: task.family, vehicle: 'json_nested', value: sec.value, grep: sec.grep, recordIndexes: [recordIndex], occurrences: 1 });
}

function emitEcho(s, task) {
  const sec = makeSecret(task.family);
  const idxs = [];
  s.user(`I think a credential leaked into the ${pick(SVC)} logs. Can you confirm how widespread it is?`);
  idxs.push(s.bash('grep -rn "' + sec.value.slice(0, 8) + '" /var/log/app/ | head -3', `app.log:41:[warn] outbound call used inline credential ${sec.value}\napp.log:87:[warn] retry with credential ${sec.value.slice(0, 12)}...`));
  s.assistantText('It appears in the application log at least twice. Checking the shipped bundle and the shell history too.');
  idxs.push(s.bash('grep -c "' + sec.value.slice(0, 8) + '" dist/bundle.js || true', `1\nmatched: ${sec.value}`));
  qaBenign(s);
  idxs.push(s.bash('tail -n 2 ~/.zsh_history', `curl -H "Authorization: Bearer ${sec.value}" https://internal.example/api\nls -la`));
  s.assistantText('Confirmed: the same value shows up in the app log, the built bundle, and shell history. Rotate it and scrub the log archive.');
  // One distinct secret, re-exposed on three separate tool_result lines.
  // occurrences = number of corpus lines carrying the full value; scoring
  // distinct-vs-re-exposed counting is exactly what this class tests.
  s.registerPlant({ class: task.class, family: task.family, vehicle: 'echo_multi_tool_result', value: sec.value, grep: sec.value, recordIndexes: idxs, occurrences: idxs.length });
}

function emitB64(s, task) {
  const sec = makeSecret(task.family);
  const encoded = wrap76(b64(sec.envLine + '\n'));
  s.user('The provisioning tool wants the env file base64 encoded, can you produce that?');
  const recordIndex = s.bash('base64 -i config/service.env', encoded);
  s.assistantText('Encoded output above. Paste it into the provisioning form as one line if the tool rejects wrapped input.');
  s.registerPlant({ class: task.class, family: task.family, vehicle: 'b64_stdout', value: sec.value, grep: encoded.split('\n')[0], encoded, recordIndexes: [recordIndex], occurrences: 1 });
}

function emitSplit(s, task) {
  const sec = makeSecret(task.family);
  const cut = Math.floor(sec.value.length / 2) + ri(-4, 4);
  const part1 = sec.value.slice(0, cut);
  const part2 = sec.value.slice(cut);
  s.user('Recover the credential from the truncated incident dump and tell me which system it belongs to.');
  // One API response streamed as two records with the same message id,
  // the text block split across them (observed multi-record assistant
  // turns share message.id on adjacent lines).
  const shared = msgId();
  const i1 = s.assistantBlock({ type: 'text', text: `The dump reassembles to a single credential. Reconstructed start: ${part1}` }, 'end_turn', shared);
  const i2 = s.assistantBlock({ type: 'text', text: `${part2} is the remainder; together they form the token, which matches the CI deploy account. Rotate it.` }, 'end_turn', shared);
  s.registerPlant({ class: task.class, family: task.family, vehicle: 'split_assistant_text', value: sec.value, parts: [part1, part2], grep: part1, grep2: part2, recordIndexes: [i1, i2], occurrences: 1 });
}

const SUPPRESS_FIXTURES = [
  { family: 'aws-access-key-id', style: 'canonical_example', line: 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE', grep: 'AKIAIOSFODNN7EXAMPLE' },
  // Literal split so GitHub push protection does not flag this placeholder
  // in the generator source itself (its Stripe detector matches all-X test
  // keys). The constructed string is byte-identical to the previous literal.
  { family: 'stripe-test-key', style: 'x_run', line: 'STRIPE_SECRET_KEY=sk_te' + 'st_' + 'X'.repeat(24), grep: 'sk_te' + 'st_' + 'X'.repeat(24) },
  { family: 'github-pat', style: 'x_run', line: 'GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', grep: 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
  { family: 'github-pat', style: 'angle_placeholder', line: 'export GITHUB_TOKEN=<YOUR_GITHUB_TOKEN>', grep: '<YOUR_GITHUB_TOKEN>' },
  { family: 'anthropic-key', style: 'ellipsis_placeholder', line: 'ANTHROPIC_API_KEY=sk-ant-api03-...your-key-here...', grep: 'sk-ant-api03-...your-key-here...' },
  { family: 'connection-string', style: 'placeholder_password', line: 'DATABASE_URL=postgresql://user:password@localhost:5432/mydb', grep: 'postgresql://user:password@localhost:5432/mydb' },
  { family: 'slack-token', style: 'angle_placeholder', line: 'SLACK_BOT_TOKEN=xoxb-<workspace-id>-<bot-id>-<token>', grep: 'xoxb-<workspace-id>-<bot-id>-<token>' },
  { family: 'generic-password', style: 'changeme', line: 'ADMIN_PASSWORD=changeme', grep: 'ADMIN_PASSWORD=changeme' },
  { family: 'npm-token', style: 'x_run', line: '//registry.npmjs.org/:_authToken=npm_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', grep: 'npm_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' },
  { family: 'bearer-header', style: 'angle_placeholder', line: "curl -H 'Authorization: Bearer <ACCESS_TOKEN>' https://api.example.com/v1/me", grep: 'Bearer <ACCESS_TOKEN>' },
];

function emitSuppress(s, task) {
  const fx = task.fixture;
  let recordIndex;
  if (chance(0.6)) {
    s.user('Can you check whether our README setup section is still accurate?');
    const docLines = ['## Setup', '', 'Copy the example config and fill in your own values:', '', '```', fx.line, '```', '', 'Never commit real credentials; the placeholders above are documentation examples.'];
    recordIndex = s.read(s.proj.cwd + '/README.md', docLines);
    s.assistantText('The setup section is accurate and clearly marks the values as placeholders.');
  } else {
    s.user('Show me an example of how a teammate should configure this locally.');
    recordIndex = s.assistantText(`Use a placeholder until they mint their own credential, for example:\n\n    ${fx.line}\n\nThe real value comes from the team vault, never from chat.`);
  }
  s.registerPlant({ class: task.class, family: fx.family, vehicle: 'placeholder_doc', value: fx.line, grep: fx.grep, recordIndexes: [recordIndex], occurrences: 1, placeholderStyle: fx.style });
}

/* ------------------------------------------------------------------ *
 * Session meta records.
 * ------------------------------------------------------------------ */

const TITLES = ['Fix staging auth failures', 'Investigate flaky tests', 'Deploy pipeline cleanup', 'Env config audit', 'Webhook retry bug', 'Log noise triage', 'Release checksum check', 'Off by one in pagination'];

function openSession(s, legacySummary) {
  if (legacySummary) {
    // Legacy summary record shape used by older Claude Code versions,
    // kept so scanners tolerant of both meta shapes see both.
    s.pushMeta({ type: 'summary', summary: pick(TITLES), leafUuid: uuid() });
  }
  if (chance(0.5)) s.pushMeta({ type: 'mode', mode: 'default', sessionId: s.sessionId });
}

function titleRecord(s) {
  if (pick(['ai', 'custom']) === 'ai') return { type: 'ai-title', aiTitle: pick(TITLES), sessionId: s.sessionId };
  return { type: 'custom-title', customTitle: pick(TITLES), sessionId: s.sessionId };
}

function closeSession(s) {
  if (chance(0.6)) s.pushMeta(titleRecord(s));
  if (chance(0.5) && s.lastMsgUuid) s.pushMeta({ type: 'last-prompt', leafUuid: s.lastMsgUuid, sessionId: s.sessionId });
  if (chance(0.2)) s.pushMeta({ type: 'queue-operation', operation: 'dequeue', timestamp: new Date(s.tsMs + 1000).toISOString(), sessionId: s.sessionId, content: 'also check the lint warnings when you get a chance' });
}

/* ------------------------------------------------------------------ *
 * Corpus plan and assembly.
 * ------------------------------------------------------------------ */

function buildPlan() {
  const tasks = [];
  const VEH = ['user_paste', 'file_read', 'stdout'];
  FAMILY_NAMES.forEach((f, i) => {
    tasks.push({ class: 'PLANT-PLAIN', family: f, vehicle: VEH[i % 3] });
    tasks.push({ class: 'PLANT-PLAIN', family: f, vehicle: VEH[(i + 1) % 3] });
  });
  for (const f of ['anthropic-key', 'github-pat', 'stripe-test-key', 'connection-string', 'slack-token', 'npm-token']) tasks.push({ class: 'PLANT-JSON-NESTED', family: f });
  for (const f of ['aws-access-key-id', 'github-pat', 'anthropic-key', 'slack-token']) tasks.push({ class: 'PLANT-ECHO', family: f });
  for (const f of ['aws-access-key-id', 'github-pat', 'stripe-test-key', 'npm-token', 'gitlab-pat']) tasks.push({ class: 'PLANT-B64', family: f });
  for (const f of ['github-pat', 'aws-access-key-id', 'anthropic-key']) tasks.push({ class: 'PLANT-SPLIT', family: f });
  SUPPRESS_FIXTURES.forEach((fx) => tasks.push({ class: 'SUPPRESS-EXPECTED', family: fx.family, fixture: fx }));

  // Deterministic shuffle.
  for (let i = tasks.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [tasks[i], tasks[j]] = [tasks[j], tasks[i]];
  }

  const TOTAL = 72;
  const sessions = [];
  for (let i = 0; i < TOTAL; i++) {
    sessions.push({ proj: PROJECTS[i % PROJECTS.length], big: [7, 29, 55].includes(i), tasks: [] });
  }
  tasks.forEach((t, k) => { sessions[Math.floor(k * TOTAL / tasks.length)].tasks.push(t); });
  return sessions;
}

function emitPlantTask(s, task) {
  if (task.class === 'PLANT-PLAIN') emitPlain(s, task);
  else if (task.class === 'PLANT-JSON-NESTED') emitJsonNested(s, task);
  else if (task.class === 'PLANT-ECHO') emitEcho(s, task);
  else if (task.class === 'PLANT-B64') emitB64(s, task);
  else if (task.class === 'PLANT-SPLIT') emitSplit(s, task);
  else if (task.class === 'SUPPRESS-EXPECTED') emitSuppress(s, task);
  else throw new Error('unknown class ' + task.class);
}

function buildSession(desc, idx) {
  const s = new Session(desc.proj, idx);
  openSession(s, idx % 12 === 3); // deterministic subset carries a legacy summary record
  const target = desc.big ? ri(280, 440) : ri(30, 150);
  const queue = desc.tasks.slice();
  let flip = 0;
  let chaffBudget = chance(0.6) ? 1 : 0;
  const registerChaff = (c) => { s.chaffLocal = s.chaffLocal || []; s.chaffLocal.push(c); };
  while (s.records.length < target || queue.length) {
    if (queue.length && (flip % 2 === 1 || s.records.length >= target - 6)) {
      emitPlantTask(s, queue.shift());
    } else if (chaffBudget > 0 && flip % 3 === 2) {
      chaffBudget--;
      pick([gitShaChaff, uuidLogChaff, sha256Chaff, b64ImageChaff])(s, registerChaff);
    } else {
      pick(BENIGN_BUILDERS)(s);
    }
    flip++;
    if (s.records.length > target + 400) throw new Error('runaway session');
  }
  closeSession(s);
  return s;
}

/* ------------------------------------------------------------------ *
 * Config side fixtures.
 * ------------------------------------------------------------------ */

function writeConfigFixtures(manifest) {
  const claudeDir = path.join(HOME, '.claude');
  fs.mkdirSync(claudeDir, { recursive: true });

  // Benign global settings (chaff for config scanners).
  const settings = { model: 'opus', permissions: { allow: ['Bash(npm test)', 'Read(**)'] }, env: { NODE_OPTIONS: '--max-old-space-size=4096' } };
  fs.writeFileSync(path.join(claudeDir, 'settings.json'), JSON.stringify(settings, null, 2) + '\n');

  // settings.local.json with a planted fake token.
  const ghSec = FAMILIES['github-pat']();
  const local = { permissions: { allow: ['Bash(git push)'] }, env: { GITHUB_TOKEN: ghSec.value, CI_DEBUG: '1' } };
  const localStr = JSON.stringify(local, null, 2) + '\n';
  fs.writeFileSync(path.join(claudeDir, 'settings.local.json'), localStr);
  manifest.push({
    class: 'PLANT-PLAIN', family: 'github-pat', vehicle: 'config',
    value: ghSec.value, grep: ghSec.value,
    file: 'home/.claude/settings.local.json',
    lines: [localStr.split('\n').findIndex((l) => l.includes(ghSec.value)) + 1],
    occurrences: 1, notes: 'agent config fixture: user-level settings.local.json env block',
  });

  // Project checkout with .mcp.json and a project-level settings.local.json.
  const projDir = path.join(HOME, 'projects', 'acme-api');
  fs.mkdirSync(path.join(projDir, '.claude'), { recursive: true });
  fs.writeFileSync(path.join(projDir, 'package.json'), JSON.stringify({ name: 'acme-api', version: '1.4.2', private: true, scripts: { test: 'vitest run' } }, null, 2) + '\n');

  const antSec = FAMILIES['anthropic-key']();
  const mcp = {
    mcpServers: {
      'issue-tracker': { command: 'npx', args: ['-y', 'issue-tracker-mcp'], env: { TRACKER_URL: 'https://tracker.internal' } },
      'llm-tools': { command: 'node', args: ['tools/mcp.js'], env: { ANTHROPIC_API_KEY: antSec.value } },
    },
  };
  const mcpStr = JSON.stringify(mcp, null, 2) + '\n';
  fs.writeFileSync(path.join(projDir, '.mcp.json'), mcpStr);
  manifest.push({
    class: 'PLANT-PLAIN', family: 'anthropic-key', vehicle: 'config',
    value: antSec.value, grep: antSec.value,
    file: 'home/projects/acme-api/.mcp.json',
    lines: [mcpStr.split('\n').findIndex((l) => l.includes(antSec.value)) + 1],
    occurrences: 1, notes: 'agent config fixture: project .mcp.json server env, use with --project mode',
  });

  const slackSec = FAMILIES['slack-token']();
  const projLocal = { env: { SLACK_BOT_TOKEN: slackSec.value } };
  const projLocalStr = JSON.stringify(projLocal, null, 2) + '\n';
  fs.writeFileSync(path.join(projDir, '.claude', 'settings.local.json'), projLocalStr);
  manifest.push({
    class: 'PLANT-PLAIN', family: 'slack-token', vehicle: 'config',
    value: slackSec.value, grep: slackSec.value,
    file: 'home/projects/acme-api/.claude/settings.local.json',
    lines: [projLocalStr.split('\n').findIndex((l) => l.includes(slackSec.value)) + 1],
    occurrences: 1, notes: 'agent config fixture: project-level settings.local.json',
  });
}

/* ------------------------------------------------------------------ *
 * Main.
 * ------------------------------------------------------------------ */

function main() {
  fs.rmSync(DATA_ROOT, { recursive: true, force: true });
  fs.mkdirSync(HOME, { recursive: true });

  const plan = buildPlan();
  const plantEntries = [];
  const chaffEntries = [];
  const fileList = [];

  plan.forEach((desc, idx) => {
    const s = buildSession(desc, idx);
    const rel = path.join('home', '.claude', 'projects', desc.proj.slug, s.sessionId + '.jsonl');
    const abs = path.join(DATA_ROOT, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    const lines = s.records.map((r) => JSON.stringify(r));
    fs.writeFileSync(abs, lines.join('\n') + '\n');
    fileList.push({ rel, lineCount: lines.length, sessionId: s.sessionId });

    for (const p of s.plants) {
      plantEntries.push({
        class: p.class, family: p.family, vehicle: p.vehicle,
        value: p.value, grep: p.grep,
        ...(p.grep2 ? { grep2: p.grep2 } : {}),
        ...(p.parts ? { parts: p.parts } : {}),
        ...(p.encoded ? { encoded: p.encoded } : {}),
        ...(p.placeholderStyle ? { placeholderStyle: p.placeholderStyle } : {}),
        ...(p.multiline ? { multiline: true } : {}),
        file: rel, lines: p.recordIndexes.map((i) => i + 1),
        occurrences: p.occurrences, sessionId: s.sessionId,
      });
    }
    for (const c of (s.chaffLocal || [])) {
      chaffEntries.push({ kind: c.kind, value: c.value, file: rel, lines: [c.recordIndex + 1] });
    }
  });

  writeConfigFixtures(plantEntries);

  // Stable ids ordered by file then first line.
  plantEntries.sort((a, b) => a.file < b.file ? -1 : a.file > b.file ? 1 : a.lines[0] - b.lines[0]);
  plantEntries.forEach((p, i) => { p.id = 'P' + String(i + 1).padStart(3, '0'); });
  chaffEntries.sort((a, b) => a.file < b.file ? -1 : a.file > b.file ? 1 : a.lines[0] - b.lines[0]);
  chaffEntries.forEach((c, i) => { c.id = 'C' + String(i + 1).padStart(3, '0'); });

  /* ---------------- verification pass ----------------
   * Line-based, against the raw files just written. A planted value can
   * legitimately appear more than once WITHIN one JSONL line (Claude Code
   * duplicates tool output in message.content and toolUseResult), so the
   * unit of ground truth is the corpus line, not the substring count.
   * For every plant, the set of corpus lines containing its anchor must
   * EXACTLY equal the declared (file, lines) set: nothing missing, and no
   * accidental cross-contamination anywhere else in the corpus.
   * ---------------------------------------------------- */

  const allFiles = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : 1)) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else allFiles.push({ rel: path.relative(DATA_ROOT, full), lines: fs.readFileSync(full, 'utf8').split('\n') });
    }
  };
  walk(DATA_ROOT);
  const fileMap = new Map(allFiles.map((f) => [f.rel, f.lines]));

  const anchorHits = (needle) => {
    const hits = [];
    for (const f of allFiles) f.lines.forEach((line, i) => { if (line.includes(needle)) hits.push(`${f.rel}:${i + 1}`); });
    return hits;
  };
  const sameSet = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

  const errors = [];
  const seenValues = new Set();
  for (const p of plantEntries) {
    if (p.class !== 'SUPPRESS-EXPECTED') {
      if (seenValues.has(p.value)) errors.push(`duplicate planted value (${p.family})`);
      seenValues.add(p.value);
    }
    const declared = p.lines.map((ln) => `${p.file}:${ln}`).sort();
    if (p.class === 'PLANT-SPLIT') {
      if (!sameSet(anchorHits(p.grep).sort(), [declared[0]])) errors.push(`split part 1 lines wrong (${p.family})`);
      if (!sameSet(anchorHits(p.grep2).sort(), [declared[1]])) errors.push(`split part 2 lines wrong (${p.family})`);
      if (p.lines[1] !== p.lines[0] + 1) errors.push(`split parts not adjacent (${p.family})`);
      if (anchorHits(p.value).length !== 0) errors.push(`split value appears contiguously (${p.family})`);
    } else if (p.class === 'PLANT-B64') {
      if (!sameSet(anchorHits(p.grep).sort(), declared)) errors.push(`b64 anchor lines wrong (${p.family})`);
      if (anchorHits(p.value).length !== 0) errors.push(`raw value of b64 plant present in corpus (${p.family})`);
    } else {
      if (!sameSet(anchorHits(p.grep).sort(), declared)) {
        errors.push(`anchor line set mismatch (${p.class} ${p.family}): declared ${declared.join(',')} actual ${anchorHits(p.grep).sort().join(',')}`);
      }
      if (p.lines.length !== p.occurrences) errors.push(`occurrences/lines mismatch (${p.family})`);
    }
  }
  // Chaff is verified with the same rigor as plants: every tracked chaff
  // value's actual line set must exactly equal its declared (file, lines)
  // set, so precision denominators are self-enforcing, not hand-audited.
  for (const c of chaffEntries) {
    const declared = c.lines.map((ln) => `${c.file}:${ln}`).sort();
    if (!sameSet(anchorHits(c.value).sort(), declared)) {
      errors.push(`chaff line set mismatch (${c.kind}): declared ${declared.join(',')} actual ${anchorHits(c.value).sort().join(',')}`);
    }
  }

  // Every transcript line must parse as JSON.
  for (const f of fileList) {
    (fileMap.get(f.rel) || []).forEach((line, i) => {
      if (!line) return;
      try { JSON.parse(line); } catch (e) { errors.push(`${f.rel}:${i + 1} unparseable JSON`); }
    });
  }
  if (errors.length) {
    console.error('VERIFICATION FAILED:\n' + errors.join('\n'));
    process.exit(1);
  }

  /* ---------------- manifest ---------------- */

  const byClass = {}; const byFamily = {};
  for (const p of plantEntries) {
    byClass[p.class] = (byClass[p.class] || 0) + 1;
    byFamily[p.family] = (byFamily[p.family] || 0) + 1;
  }

  const truth = {
    corpus: 'residoo-bench-corpus',
    version: CORPUS_VERSION,
    seed: SEED,
    generator: 'bench/corpus/generate.js',
    dataRoot: 'data',
    fixtureHome: 'data/home',
    note: 'All values are synthetic pattern-true fakes generated from the seed above. None was ever issued by a provider. truth.json lives outside data/home so it never contaminates a scan of the fixture home.',
    scoring: {
      headlineRecallClasses: ['PLANT-PLAIN', 'PLANT-JSON-NESTED', 'PLANT-ECHO'],
      separatelyScoredHardClasses: ['PLANT-B64', 'PLANT-SPLIT'],
      falsePositiveIfFlaggedAsReal: ['SUPPRESS-EXPECTED'],
      precisionReference: 'chaff',
    },
    counts: {
      sessionFiles: fileList.length,
      transcriptLines: fileList.reduce((a, f) => a + f.lineCount, 0),
      plants: plantEntries.length,
      chaff: chaffEntries.length,
      byClass, byFamily,
    },
    files: fileList,
    plants: plantEntries.map((p) => ({
      id: p.id, class: p.class, family: p.family, vehicle: p.vehicle,
      file: p.file, lines: p.lines, occurrences: p.occurrences,
      value: p.value, grep: p.grep,
      ...(p.grep2 ? { grep2: p.grep2 } : {}),
      ...(p.parts ? { parts: p.parts } : {}),
      ...(p.encoded ? { encoded: p.encoded } : {}),
      ...(p.placeholderStyle ? { placeholderStyle: p.placeholderStyle } : {}),
      ...(p.multiline ? { multiline: true } : {}),
      ...(p.sessionId ? { sessionId: p.sessionId } : {}),
      ...(p.notes ? { notes: p.notes } : {}),
    })),
    chaff: chaffEntries,
  };
  fs.writeFileSync(path.join(OUT_ROOT, 'truth.json'), JSON.stringify(truth, null, 2) + '\n');

  console.log('corpus generated');
  console.log('  session files:   ' + fileList.length);
  console.log('  transcript lines:' + String(truth.counts.transcriptLines).padStart(7));
  console.log('  plants:          ' + plantEntries.length);
  console.log('  chaff entries:   ' + chaffEntries.length);
  console.log('  by class:        ' + JSON.stringify(byClass));
  console.log('  by family:       ' + JSON.stringify(byFamily));
}

main();
