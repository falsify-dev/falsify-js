#!/usr/bin/env node
// Node.js native test runner — no external dependencies. Tests the JS
// reference impl against the full conformance suite locked in the spec
// repo: 13 v0.1 normative vectors + 8 v0.2 candidate vectors = 21 total.
// Run via `npm test`.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { canonicalize, manifestHash, evaluatePredicate, validateManifest } = require('./falsify.js');

// JSON parser that preserves precision for large integers via BigInt
// (mirrors the CLI's `test-vectors` subcommand). JS Number loses precision
// above 2^53; PRML's seed field allows uint64.
function parseWithBigInt(raw) {
  const wrapped = raw.replace(/(?<=[\s:,\[])(\-?\d{16,})(?=[\s,\]\}])/g, '"__BIGINT__$1"');
  const obj = JSON.parse(wrapped);
  function unwrap(o) {
    if (typeof o === 'string' && o.startsWith('__BIGINT__')) return BigInt(o.slice(10));
    if (Array.isArray(o)) return o.map(unwrap);
    if (o !== null && typeof o === 'object') {
      const out = {};
      for (const k of Object.keys(o)) out[k] = unwrap(o[k]);
      return out;
    }
    return o;
  }
  return unwrap(obj);
}

// Conformance vectors: 13 v0.1 normative + 8 v0.2 candidate. Sources, tried
// in order; the first that yields BOTH suites wins:
//   1. $PRML_VECTORS_DIR — a directory containing v0.1/test-vectors.json and
//      v0.2/test-vectors.json (CI sets this after fetching from the spec repo).
//   2. The sibling falsify-hackathon checkout (local development layout).
//   3. raw.githubusercontent.com at SPEC_COMMIT via curl (network fallback,
//      same source CI fetches from).
// If no source yields both suites, or a suite has the wrong vector count,
// exit 1. A partial or shrunken suite must fail loudly, never pass silently.
const SPEC_COMMIT = '4023615eb8f0090e5849fad2605412dfcf2a6623';
const V01_COUNT = 13;
const V02_COUNT = 8;

function readSuite(dir, sub) {
  const p = path.join(dir, sub, 'test-vectors.json');
  if (!fs.existsSync(p)) return null;
  return parseWithBigInt(fs.readFileSync(p, 'utf-8'));
}

function fetchSuite(sub) {
  const url = 'https://raw.githubusercontent.com/falsify-dev/falsify/'
    + SPEC_COMMIT + '/spec/test-vectors/' + sub + '/test-vectors.json';
  try {
    const raw = execFileSync('curl', ['-fsSL', url],
      { encoding: 'utf-8', maxBuffer: 16 * 1024 * 1024 });
    return parseWithBigInt(raw);
  } catch (e) {
    return null;
  }
}

function loadVectors() {
  const candidates = [];
  if (process.env.PRML_VECTORS_DIR) candidates.push(process.env.PRML_VECTORS_DIR);
  candidates.push(path.resolve(__dirname, '..', 'falsify-hackathon', 'spec', 'test-vectors'));

  let v01 = null, v02 = null, source = null;
  for (const dir of candidates) {
    const a = readSuite(dir, 'v0.1');
    const b = readSuite(dir, 'v0.2');
    if (a && b) { v01 = a; v02 = b; source = dir; break; }
  }
  if (!v01 || !v02) {
    v01 = fetchSuite('v0.1');
    v02 = fetchSuite('v0.2');
    source = 'raw.githubusercontent.com @ ' + SPEC_COMMIT.slice(0, 12);
  }
  if (!v01 || !v02) {
    console.error('FATAL: could not load the conformance vectors.');
    console.error('Tried: $PRML_VECTORS_DIR, the sibling falsify-hackathon checkout,');
    console.error('and raw.githubusercontent.com @ ' + SPEC_COMMIT.slice(0, 12) + ' (curl).');
    process.exit(1);
  }
  if (v01.length !== V01_COUNT || v02.length !== V02_COUNT) {
    console.error('FATAL: unexpected vector counts from ' + source + ':');
    console.error('  v0.1: got ' + v01.length + ', want ' + V01_COUNT);
    console.error('  v0.2: got ' + v02.length + ', want ' + V02_COUNT);
    console.error('Refusing to run a partial suite.');
    process.exit(1);
  }
  return [...v01, ...v02];
}

const VECTORS = loadVectors();
// TV-006 exercises the 2^64-1 seed; JS Number tops out at 2^53-1 and the
// regex BigInt-rewrite in parseWithBigInt converts only well-isolated tokens.
// The maximum-seed vector is documented as a known JS-Number-precision
// limitation and is excluded from the byte-equivalence assertion.
const HASH_SKIP = new Set(['TV-006']);

test('exports public API', () => {
  for (const fn of ['canonicalize', 'manifestHash', 'evaluatePredicate', 'validateManifest']) {
    assert.equal(typeof require('./falsify.js')[fn], 'function', `missing export: ${fn}`);
  }
});

test('manifestHash is deterministic', () => {
  const m = VECTORS[0].input;
  assert.equal(manifestHash(m), manifestHash(m));
  assert.equal(manifestHash(m), VECTORS[0].hash);
});

test('canonicalize sorts keys lexicographically', () => {
  const a = canonicalize({ b: 2, a: 1 });
  const b = canonicalize({ a: 1, b: 2 });
  assert.equal(a, b);
});

test('evaluatePredicate handles all five comparators (returns boolean)', () => {
  assert.equal(evaluatePredicate(0.95, '>=', 0.9), true);
  assert.equal(evaluatePredicate(0.85, '>=', 0.9), false);
  assert.equal(evaluatePredicate(0.5,  '<=', 0.6), true);
  assert.equal(evaluatePredicate(1.0,  '==', 1.0), true);
  assert.equal(evaluatePredicate(0.91, '>',  0.9), true);
  assert.equal(evaluatePredicate(0.91, '<',  0.9), false);
});

test('validateManifest accepts canonical v0.1 manifests (returns empty error array)', () => {
  // validateManifest is a strict v0.1 subset check. v0.2 vectors that exercise
  // streaming mode (pre_registered_from/to instead of created_at) and other
  // RFC extensions are intentionally outside its scope until v0.2 freeze.
  for (const v of VECTORS) {
    if (v.input.version !== 'prml/0.1') continue;
    const errors = validateManifest(v.input);
    assert.equal(Array.isArray(errors), true, `${v.id}: expected array, got ${typeof errors}`);
    assert.equal(errors.length, 0, `${v.id} should validate: ${JSON.stringify(errors)}`);
  }
});

test(`all ${VECTORS.length} conformance vectors hash byte-equivalently (13 v0.1 + 8 v0.2)`, () => {
  let passed = 0;
  for (const v of VECTORS) {
    if (HASH_SKIP.has(v.id)) continue;
    const got = manifestHash(v.input);
    assert.equal(got, v.hash, `${v.id}: ${v.title}\n  expected ${v.hash}\n  got      ${got}`);
    passed += 1;
  }
  assert.equal(passed, VECTORS.length - HASH_SKIP.size);
});

// ── prml-linkage/0 (experimental) ─────────────────────────────────────────

const linkage = require('./linkage.js');

const LINK_MANIFEST_HASH = 'a'.repeat(64);
const LINK_DATASET_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const LINK_DIGEST = 'b'.repeat(64);

function linkStart() {
  return linkage.buildStart(LINK_MANIFEST_HASH, 'run-0001', 'node-test', LINK_DATASET_HASH, {
    startedAt: '2026-08-13T10:00:00Z',
  });
}

test('linkage: roundtrip start→finalize→verify passes at tier L2', () => {
  const start = linkStart();
  const final = linkage.finalize(start, 0.9, LINK_DIGEST, 0, { finishedAt: '2026-08-13T10:05:00Z' });
  const report = linkage.verify(final, { startRecord: start });
  assert.equal(report.ok, true, JSON.stringify(report.failures));
  assert.equal(report.tier, 'L2');
});

test('linkage: integer observed canonicalizes with .0 suffix (spec float rule)', () => {
  const start = linkStart();
  const final = linkage.finalize(start, 1, LINK_DIGEST, 0, { finishedAt: '2026-08-13T10:05:00Z' });
  assert.match(canonicalize(final), /observed: 1\.0\n/);
});

test('linkage: tampered start record breaks the chain', () => {
  const start = linkStart();
  const final = linkage.finalize(start, 0.9, LINK_DIGEST, 0, { finishedAt: '2026-08-13T10:05:00Z' });
  const tampered = { ...start, run: { ...start.run, started_at: '2026-08-13T09:00:00Z' } };
  const report = linkage.verify(final, { startRecord: tampered });
  assert.equal(report.ok, false);
  assert.equal(report.failures.every((f) => f.check === 'chain-broken'), true);
});

test('linkage: chronology violation is caught', () => {
  const start = linkStart();
  const final = linkage.finalize(start, 0.9, LINK_DIGEST, 0, { finishedAt: '2026-08-13T09:00:00Z' });
  const report = linkage.verify(final);
  assert.equal(report.ok, false);
  assert.equal(report.failures[0].check, 'chronology');
});

// ─────────────────────────────────────────────────────────────────────────
// PRML v0.1 erratum 2026-11-15: reading and canonical forms. The full case list
// is falsify-hackathon/tests/fixtures/erratum-2026-11-15-cases.json; these are
// the JavaScript-specific ones.
// ─────────────────────────────────────────────────────────────────────────
const { parseManifest } = require('./falsify.js');
const BASE_YAML = [
  'version: prml/0.1', 'claim_id: 01900000-0000-7000-8000-000000000000',
  "created_at: '2026-05-01T12:00:00Z'", 'metric: accuracy', "comparator: '>='",
  'threshold: 0.85', 'dataset:', '  id: ds',
  '  hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  'seed: 42', 'producer:', '  id: falsify.dev', '',
].join('\n');
const baseJson = (extra) => JSON.stringify({
  version: 'prml/0.1', claim_id: '01900000-0000-7000-8000-000000000000', created_at: '2026-05-01T12:00:00Z',
  metric: 'accuracy', comparator: '>=', threshold: 0.85,
  dataset: { id: 'ds', hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
  seed: 42, producer: { id: 'falsify.dev' },
}).slice(0, -1) + (extra ? ', ' + extra : '') + '}';
const canonOf = (text, fmt) => {
  const m = parseManifest(text, fmt);
  assert.deepEqual(validateManifest(m), []);
  return canonicalize(m);
};
const rejects = (text, fmt) => {
  let errs;
  try { errs = validateManifest(parseManifest(text, fmt)); } catch (e) { return; }
  assert.notDeepEqual(errs, [], 'expected a rejection');
};

test('erratum 2026-11-15: a float spelled 1.0 renders 1.0, an integer 1 renders 1 (JSON and YAML)', () => {
  assert.match(canonOf(baseJson('"metric_args": {"t": 1.0, "k": 1, "z": -0.0}'), 'json'), /\n  k: 1\n  t: 1\.0\n  z: -0\.0\n/);
  assert.match(canonOf(BASE_YAML + 'metric_args:\n  t: 1.0\n  k: 1\n', 'yaml'), /\n  k: 1\n  t: 1\.0\n/);
});

test('erratum 2026-11-15: integers beyond 2^53-1 stay exact (JSON and YAML)', () => {
  assert.match(canonOf(baseJson('"metric_args": {"k": 18446744073709551617}'), 'json'), /k: 18446744073709551617\n/);
  assert.match(canonOf(BASE_YAML.replace('seed: 42', 'seed: 18446744073709551615'), 'yaml'), /seed: 18446744073709551615\n/);
});

test('erratum 2026-11-15: empty mapping and sequence render {} and []', () => {
  const c = canonOf(baseJson('"metric_args": {"a": {}, "l": [], "i": [{}]}'), 'json');
  assert.match(c, /\n  a: \{\}\n  i:\n  - \{\}\n  l: \[\]\n/);
});

test('erratum 2026-11-15: YAML numbers must be spelled as JSON numbers; timestamps must be quoted', () => {
  for (const sp of ['010', '0x1F', '0o17', '1_000', '1:30', '.5', '5.', '+1']) {
    assert.throws(() => parseManifest(BASE_YAML + `metric_args:\n  k: ${sp}\n`, 'yaml'), /JSON number/, sp);
  }
  assert.throws(() => parseManifest(BASE_YAML + 'metric_args:\n  d: 2026-05-01\n', 'yaml'), /unquoted timestamp/);
  assert.match(canonOf(BASE_YAML + "metric_args:\n  k: 1e3\n  q: '010'\n", 'yaml'), /k: 1000\.0\n  q: '010'\n/);
});

test('erratum 2026-11-15: rejections (non-finite, seed range, nested sequence, depth, lone surrogate, float seed)', () => {
  rejects(BASE_YAML + 'metric_args:\n  k: .inf\n', 'yaml');
  rejects(baseJson().replace('"seed":42', '"seed":-1'), 'json');
  rejects(baseJson().replace('"seed":42', '"seed":18446744073709551616'), 'json');
  rejects(baseJson().replace('"seed":42', '"seed":42.0'), 'json');
  rejects(baseJson('"metric_args": {"m": [[1, 2]]}'), 'json');
  rejects(baseJson('"metric_args": ' + '{"a": '.repeat(100) + '1' + '}'.repeat(100)), 'json');
  rejects(baseJson('"notes": "a\\ud800b"'), 'json');
  assert.throws(() => parseManifest(baseJson() + ' {}', 'json'));
});

test('erratum 2026-11-15: constructor, prototype and __proto__ are ordinary keys', () => {
  const m = parseManifest(baseJson('"metric_args": {"constructor": 1, "prototype": 2, "__proto__": 3}'), 'json');
  assert.equal(Object.getPrototypeOf(m.metric_args), Object.prototype);
  assert.match(canonicalize(m), /\n  __proto__: 3\n  constructor: 1\n  prototype: 2\n/);
});

test('erratum 2026-11-15: TV-006 (2^64-1 seed) hashes to its published value when read from text', () => {
  const v = VECTORS.find((x) => x.id === 'TV-006');
  const text = JSON.stringify(v.input, (k, val) => (typeof val === 'bigint' ? `__BIG__${val}` : val))
    .replace(/"__BIG__(\d+)"/g, '$1');
  assert.equal(manifestHash(parseManifest(text, 'json')), v.expected_hash || v.hash);
});

test('erratum 2026-11-15 (second part): mapping keys must be strings in YAML', () => {
  for (const frag of ['1: a', 'true: a', 'null: a', '1.5: a', '? [a, b]\n  : c', '? {a: 1}\n  : c']) {
    assert.throws(() => parseManifest(BASE_YAML + `metric_args:\n  ${frag}\n`, 'yaml'), /mapping keys must be strings/, frag);
  }
  assert.match(canonOf(BASE_YAML + "metric_args:\n  '1': a\n  'true': b\n", 'yaml'), /\n  '1': a\n  'true': b\n/);
});

test('erratum 2026-11-15 (second part): U+FFFE, U+FFFF and U+10FFFF are refused; other noncharacters are not', () => {
  for (const esc of ['\\ufffe', '\\uffff', '\\udbff\\udfff']) rejects(baseJson(`"notes": "a${esc}b"`), 'json');
  assert.equal(validateManifest(parseManifest(baseJson('"notes": "a\\ufdd0b"'), 'json')).length, 0);
});

test('erratum 2026-11-15 (second part): field types of the published schema', () => {
  const cases = { comparator: null, metric: 123, dataset: '"x"', producer: null, claim_id: 5, created_at: 5, model: '"m"', metric_args: '[1]', notes: null, prior_hash: null };
  for (const [k, v] of Object.entries(cases)) {
    const m = JSON.parse(baseJson());
    m[k] = typeof v === 'string' ? JSON.parse(v) : v;
    assert.ok(validateManifest(m).length > 0, `${k}: ${JSON.stringify(m[k])} must be rejected`);
  }
  const ok = JSON.parse(baseJson('"model": {"id": "m", "version": "2"}'));
  assert.deepEqual(validateManifest(ok), []);
});

test('erratum 2026-11-15 (second part): a nested threshold renders by its spelling (G4)', () => {
  assert.match(canonOf(baseJson('"metric_args": {"threshold": 1, "inner": {"threshold": 2.0}}'), 'json'),
    /\n  inner:\n    threshold: 2\.0\n  threshold: 1\n/);
});

test('erratum 2026-11-15 (second part): lock requires created_at as YYYY-MM-DDTHH:MM:SSZ; hash still reads other spellings', () => {
  const { newManifestErrors } = require('./falsify.js');
  const m = parseManifest(baseJson().replace('"2026-05-01T12:00:00Z"', '"2026-05-01T12:00:00+00:00"'), 'json');
  assert.deepEqual(validateManifest(m), []);
  assert.match(newManifestErrors(m)[0], /YYYY-MM-DDTHH:MM:SSZ/);
  assert.deepEqual(newManifestErrors(parseManifest(baseJson(), 'json')), []);
});

test('erratum 2026-11-15 (third part): code is an optional mapping (spec §2.2)', () => {
  assert.deepEqual(validateManifest(JSON.parse(baseJson('"code": {"id": "eval.py", "hash": "' + 'a'.repeat(64) + '"}'))), []);
  assert.ok(validateManifest(JSON.parse(baseJson('"code": "eval.py"'))).includes('code must be a mapping'));
});

test('a manifest with a very long error list validates without overflowing the call stack', () => {
  // ~330,000 nested empty sequences (about 1 MB) give one structural error each.
  // Before 0.4.2, `errors.push(...list)` threw RangeError at Node's default stack size.
  const m = JSON.parse(baseJson('"x": [' + Array(330000).fill('[]').join(',') + ']'));
  const errors = validateManifest(m);
  assert.ok(errors.length > 330000);
  assert.ok(errors.some(e => e.includes('a sequence inside a sequence')));
});
