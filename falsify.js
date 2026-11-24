#!/usr/bin/env node
// falsify-js — second reference implementation of PRML v0.1
//
// Single file, ~400 LOC, zero runtime dependencies beyond Node.js stdlib.
// Reproduces all 13 PRML v0.1 conformance vectors byte-for-byte.
//
// Spec:    https://spec.falsify.dev/v0.1
// Vectors: https://github.com/falsify-dev/falsify/tree/main/spec/test-vectors
// Python:  https://github.com/falsify-dev/falsify (reference implementation)
//
// Usage:
//   falsify-js init <name>                    create skeleton manifest
//   falsify-js lock <path>                    canonicalize + hash + write sidecar
//   falsify-js verify <path> --observed <v>   verify hash + evaluate verdict
//   falsify-js test-vectors <vectors.json>    run against conformance suite
//
// License: MIT.

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─────────────────────────────────────────────────────────────────────────
// Canonicalization
// ─────────────────────────────────────────────────────────────────────────

// §3.6 / README §C5 — the plain-scalar predicate, stated exactly.
// A string renders plain iff P1–P6 all hold; otherwise single-quoted.
// P2: first-character indicators that always force quoting.
const P2_FIRST = new Set(['#', ',', '[', ']', '{', '}', '&', '*', '!', '|', '>', "'", '"', '%', '@', '`']);
// P6: YAML 1.1 implicit resolvers — a plain scalar matching one of these would
// read back as a non-string, so it must be quoted. Transcribed from the
// specification (spec/grammar/README.md §C5); do not "simplify".
const P6_RESOLVERS = [
  /^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$/,
  /^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$/,
  /^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$/,
  /^(?:~|null|Null|NULL)$/,
  /^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$/,
  /^(?:<<)$/,
  /^(?:=)$/,
  /^(?:!|&|\*)$/,
];

// Fields whose value MUST round-trip as a float even when integer-valued.
// PyYAML preserves float-ness via its number type; JSON parsers in many
// languages do not. The spec field type is the source of truth, and it is
// version-aware: v0.1 fixed threshold as float64 (integer-valued thresholds
// render with explicit ".0" suffix), v0.2 RFC P-XX relaxes threshold to
// int|float (integer-valued thresholds render as plain integers).
const FLOAT_FIELDS_V01 = new Set(['threshold']);
const FLOAT_FIELDS_V02 = new Set();
// prml-linkage/0 spec §3.2 float rule: observed is float64, integer values
// render with an explicit ".0" suffix (same convention as v0.1 threshold).
const FLOAT_FIELDS_LINKAGE = new Set(['observed']);

function floatFieldsFor(version) {
  return version === 'prml/0.1' ? FLOAT_FIELDS_V01 : FLOAT_FIELDS_V02;
}

function floatFieldsForRecord(obj) {
  if (obj && obj.linkage_version === 'prml-linkage/0') return FLOAT_FIELDS_LINKAGE;
  return floatFieldsFor(obj && obj.version);
}

// Returns true when the string must be single-quoted (i.e. it is NOT a plain
// scalar under README §C5 P1–P6). Whitespace in P3–P5 is U+0020 only: every
// other character PyYAML would treat as whitespace is outside the §3.4
// portable set and is rejected before this code runs.
function needsQuoting(s) {
  if (typeof s !== 'string') return false;
  if (s.length === 0) return true;                                  // P1
  const first = s[0];
  if (P2_FIRST.has(first)) return true;                             // P2
  if ((first === '?' || first === ':' || first === '-') &&
      (s.length === 1 || s[1] === ' ')) return true;                // P3
  if (first === ' ' || s[s.length - 1] === ' ') return true;        // P4
  for (let i = 1; i < s.length; i++) {                              // P5
    const c = s[i];
    if (c === ':' && (i === s.length - 1 || s[i + 1] === ' ')) return true;
    if (c === '#' && s[i - 1] === ' ') return true;
  }
  for (const re of P6_RESOLVERS) if (re.test(s)) return true;       // P6
  // Defensive: control characters never reach here (§3.4 rejects them), but
  // if they did, quoting is the safe failure.
  if (/[\x00-\x1f\x7f]/.test(s)) return true;
  return false;
}

function quoteSingle(s) {
  return "'" + s.replace(/'/g, "''") + "'";
}

// Match PyYAML's safe_dump float rendering. PyYAML inherits Python's
// repr(float): magnitudes < 1e-4 or >= 1e16 use scientific notation; the
// mantissa always carries a `.0` if otherwise integer-valued; the exponent
// is zero-padded to at least two digits with explicit sign. JS's
// Number.prototype.toString switches to scientific only at magnitudes
// below ~1e-7 and uses no `.0` mantissa decoration, so for the small-float
// regime we need an explicit formatter to reproduce PyYAML's bytes.
//
// Examples (PyYAML / desired output):
//   0.85           -> "0.85"
//   1.0            -> handled by the hint=='float' branch above (toFixed(1))
//   0.000001       -> "1.0e-06"
//   1.5e-7         -> "1.5e-07"
//   1.234e-15      -> "1.234e-15"
function pythonRepr(v) {
  if (v === 0) return '0.0';
  const abs = Math.abs(v);
  if (abs < 1e-4 || abs >= 1e16) {
    const s = v.toExponential();
    const m = s.match(/^(-?)(\d+)(\.\d+)?e([+-])(\d+)$/);
    if (m) {
      const sign = m[1];
      const intPart = m[2];
      const fracPart = m[3] || '.0';
      const expSign = m[4];
      const expDigits = m[5].padStart(2, '0');
      return `${sign}${intPart}${fracPart}e${expSign}${expDigits}`;
    }
    return s;
  }
  return v.toString();
}

function renderScalar(v, hint) {
  if (v === null || v === undefined) return 'null';
  if (hint === 'v02-threshold' && (typeof v === 'number' || typeof v === 'bigint')) {
    // PRML v0.2 `threshold` renders by VALUE (RFC post-freeze clarification,
    // 2026-09-13; spec/grammar/README.md §C6): integral and |v| < 2^53 ->
    // integer digits; otherwise the §C4 float form. So 1300.0 and 1300 are one
    // manifest with one hash — the one distinction JSON.parse and js-yaml
    // cannot carry, which is why the rule is by value and why 2^53 (the safe
    // integer bound) is where it stops.
    const TWO_53 = 9007199254740992;
    if (typeof v === 'bigint') {
      if (v < 9007199254740992n && v > -9007199254740992n) return v.toString();
      v = Number(v);
    }
    if (Number.isFinite(v)) {
      if (Number.isInteger(v) && Math.abs(v) < TWO_53) return v === 0 ? '0' : v.toString();
      if (Number.isInteger(v)) return Math.abs(v) >= 1e16 ? pythonRepr(v) : v.toFixed(1);
      return pythonRepr(v);
    }
  }
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  // A float field (v0.1 `threshold`) holds a float64 even when spelled as a big integer.
  if (typeof v === 'bigint' && hint === 'float') v = Number(v);
  if (typeof v === 'bigint') return v.toString();
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) {
      if (Number.isNaN(v)) return '.nan';
      return v > 0 ? '.inf' : '-.inf';
    }
    if (hint === 'float' && Object.is(v, -0)) return '-0.0';
    if (hint === 'float' && Number.isInteger(v)) {
      // Large integer-valued floats (|v| >= 1e16) must render in Python's
      // exponential form ("1.0e+20"), not toFixed ("100000000000000000000.0").
      // pythonRepr already produces the exponential form for that magnitude.
      if (Math.abs(v) >= 1e16) return pythonRepr(v);
      return v.toFixed(1);
    }
    if (Number.isInteger(v)) return v.toString();
    return pythonRepr(v);
  }
  if (typeof v === 'string') {
    return needsQuoting(v) ? quoteSingle(v) : v;
  }
  throw new Error('renderScalar: unsupported value type ' + typeof v);
}

// §C5 applies to keys as well as values (spec/grammar/README.md): a key that
// is not a plain scalar renders single-quoted, exactly as a value would.
function renderKey(k) {
  return needsQuoting(k) ? quoteSingle(k) : k;
}

// §C2: keys sort by Unicode code point (the same order as UTF-8 bytes).
// Array.prototype.sort() compares UTF-16 code units, which puts a key above
// U+FFFF (a surrogate pair) before a key in U+E000..U+FFFF.
function byCodePoint(a, b) {
  const x = Array.from(a, (c) => c.codePointAt(0));
  const y = Array.from(b, (c) => c.codePointAt(0));
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

function renderMapping(obj, indent, floatFields, opts) {
  const keys = Object.keys(obj).sort(byCodePoint);
  const lines = [];
  const pad = ' '.repeat(indent);
  for (const k of keys) {
    const v = obj[k];
    const rk = renderKey(k);
    if (v !== null && typeof v === 'object' && !Array.isArray(v) && typeof v !== 'bigint') {
      // §C8: an empty mapping renders `{}` and an empty sequence `[]`.
      if (Object.keys(v).length === 0) { lines.push(`${pad}${rk}: {}`); continue; }
      lines.push(`${pad}${rk}:`);
      lines.push(renderMapping(v, indent + 2, floatFields, opts));
    } else if (Array.isArray(v)) {
      if (v.length === 0) { lines.push(`${pad}${rk}: []`); continue; }
      lines.push(`${pad}${rk}:`);
      for (let idx = 0; idx < v.length; idx++) {
        const item = v[idx];
        const hint = (floatFields.has(k) && (k !== 'threshold' || indent === 0)) || isFloatSpelled(v, idx) ? 'float' : null;
        if (item !== null && typeof item === 'object' && !Array.isArray(item)) {
          if (Object.keys(item).length === 0) { lines.push(`${pad}- {}`); continue; }
          const sub = renderMapping(item, indent + 2, floatFields, opts);
          // Prefix first nested line with "- " instead of indent
          const padNested = ' '.repeat(indent + 2);
          const subLines = sub.split('\n');
          subLines[0] = `${pad}- ${subLines[0].slice(padNested.length)}`;
          for (let i = 1; i < subLines.length; i++) {
            subLines[i] = subLines[i];
          }
          lines.push(subLines.join('\n'));
        } else {
          lines.push(`${pad}- ${renderScalar(item, hint)}`);
        }
      }
    } else {
      // §C6 renders by type: a number spelled as a float stays a float (`1.0`).
      // The float-field rule applies to the root `threshold` only (grammar G4,
      // erratum 2026-11-15); a nested `threshold` renders by its spelling (C6).
      // A linkage record's `result.observed` keeps its own float rule.
      let hint = (floatFields.has(k) && (k !== 'threshold' || indent === 0)) || isFloatSpelled(obj, k) ? 'float' : null;
      if (indent === 0 && k === 'threshold' && opts && opts.v02ThresholdByValue) hint = 'v02-threshold';
      lines.push(`${pad}${rk}: ${renderScalar(v, hint)}`);
    }
  }
  return lines.join('\n');
}

function canonicalize(obj) {
  const floatFields = floatFieldsForRecord(obj);
  const opts = { v02ThresholdByValue: !!(obj && obj.version === 'prml/0.2') };
  return renderMapping(obj, 0, floatFields, opts) + '\n';
}

function manifestHash(obj) {
  const bytes = canonicalize(obj);
  return crypto.createHash('sha256').update(bytes, 'utf-8').digest('hex');
}

// ─────────────────────────────────────────────────────────────────────────
// Required-field validation (subset of v0.1)
// ─────────────────────────────────────────────────────────────────────────

const REQUIRED_FIELDS = [
  'version', 'claim_id', 'created_at', 'metric',
  'comparator', 'threshold', 'dataset', 'seed', 'producer',
];
const REQUIRED_DATASET = ['id', 'hash'];
const REQUIRED_PRODUCER = ['id'];
const VALID_COMPARATORS = new Set(['>=', '<=', '>', '<', '==']);

// Control / non-portable chars forbidden in any PRML string field (key or value):
// C0 (U+0000–U+001F), DEL + C1 (U+007F–U+009F), line/paragraph separators
// (U+2028/U+2029), and BOM (U+FEFF). They canonicalize inconsistently across YAML
// engines, so a manifest carrying them is non-portable. Mirrors the Python
// reference (_FORBIDDEN_CHARS in falsify_prml.py). Additive — no conformance
// vector contains them, so no valid manifest's hash changes. A lone surrogate
// (a JSON "\ud800" escape with no pair) has no UTF-8 encoding at all and is
// refused for the same reason.
const FORBIDDEN_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\ufeff\ufffe\uffff]|\udbff\udfff|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

// Append without spreading: `target.push(...src)` passes every element as an argument and
// overflows the call stack once src holds very many entries (a manifest of about 1 MB with
// ~330,000 nested empty sequences threw RangeError at Node's default stack size).
function pushAll(target, src) {
  for (const x of src) target.push(x);
  return target;
}

function badCharFields(obj, path = '') {
  const out = [];
  if (typeof obj === 'string') {
    if (FORBIDDEN_CHARS.test(obj)) out.push(path || '(value)');
  } else if (Array.isArray(obj)) {
    obj.forEach((v, i) => pushAll(out, badCharFields(v, `${path}[${i}]`)));
  } else if (obj && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      const child = path ? `${path}.${k}` : k;
      // A forbidden char in a KEY canonicalizes non-portably just as in a value.
      if (FORBIDDEN_CHARS.test(k)) out.push(`${child} (key)`);
      pushAll(out, badCharFields(v, child));
    }
  }
  return out;
}

// Mirrors _non_nfc_fields in falsify_prml.py. NFC and NFD spellings of the same
// text read identically and hash differently, so the same claim would lock to two
// hashes depending on the authoring platform. Rejected rather than normalized:
// rewriting the text would change the bytes the author believes they locked.
function nonNfcFields(obj, path = '') {
  const out = [];
  if (typeof obj === 'string') {
    if (obj.normalize('NFC') !== obj) out.push(path || '(value)');
  } else if (Array.isArray(obj)) {
    obj.forEach((v, i) => pushAll(out, nonNfcFields(v, `${path}[${i}]`)));
  } else if (obj && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      const child = path ? `${path}.${k}` : String(k);
      if (k.normalize('NFC') !== k) out.push(`${child} (key)`);
      pushAll(out, nonNfcFields(v, child));
    }
  }
  return out;
}

function validateManifest(m) {
  const errors = [];
  for (const f of REQUIRED_FIELDS) {
    if (!(f in m)) errors.push(`missing required field: ${f}`);
  }
  if (m.version !== 'prml/0.1' && m.version !== 'prml/0.2') {
    errors.push(`version must be "prml/0.1" or "prml/0.2", got "${m.version}"`);
  }
  if (typeof m.threshold !== 'number' || !Number.isFinite(m.threshold)) {
    errors.push(`threshold must be a finite number`);
  }
  if (m.comparator && !VALID_COMPARATORS.has(m.comparator)) {
    errors.push(`comparator must be one of ${[...VALID_COMPARATORS].join(', ')}`);
  }
  if (m.dataset && typeof m.dataset === 'object') {
    for (const f of REQUIRED_DATASET) {
      if (!(f in m.dataset)) errors.push(`missing required field: dataset.${f}`);
    }
    if (m.dataset.hash && !/^[0-9a-f]{64}$/.test(m.dataset.hash)) {
      errors.push(`dataset.hash must be 64 lowercase hex chars`);
    }
  }
  if (m.producer && typeof m.producer === 'object') {
    for (const f of REQUIRED_PRODUCER) {
      if (!(f in m.producer)) errors.push(`missing required field: producer.${f}`);
    }
  }
  for (const fld of badCharFields(m)) {
    errors.push(`${fld}: contains a control / non-portable character `
      + `(C0/C1, U+007F, U+2028/U+2029, U+FEFF, U+FFFE/U+FFFF/U+10FFFF or a lone surrogate) — not allowed in a PRML string field`);
  }
  for (const fld of nonNfcFields(m)) {
    errors.push(`${fld}: string is not in Unicode NFC — the same text in a `
      + `different normalization form hashes differently; normalize to NFC`);
  }
  // Full published-schema conformance (spec/schema/prml-v0.1.schema.json).
  // Added in v0.3.12 (Andes assessment, finding 1): validators must agree
  // with the published JSON Schema, or "validated PRML" is ambiguous.
  const UUIDV7 = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
  const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;
  const TOP_KEYS = new Set(['version','claim_id','created_at','metric','comparator','threshold','dataset','seed','producer','model','compute_envelope','prior_hash','notes','metric_args','code']);
  if (typeof m.claim_id === 'string' && !UUIDV7.test(m.claim_id)) {
    errors.push('claim_id must be a UUIDv7 (schema pattern: version nibble 7, variant 8/9/a/b)');
  }
  if (typeof m.created_at === 'string' && !RFC3339.test(m.created_at)) {
    errors.push('created_at must be an RFC 3339 date-time');
  }
  if (typeof m.metric === 'string' && (m.metric.length < 1 || m.metric.length > 256)) {
    errors.push('metric must be 1..256 characters');
  }
  if (m.seed !== null && m.seed !== undefined && ((typeof m.seed !== 'bigint' && (typeof m.seed !== 'number' || !Number.isInteger(m.seed))) || isFloatSpelled(m, 'seed'))) {
    errors.push('seed must be an integer or null');
  } else if (typeof m.seed === 'number' && !Number.isSafeInteger(m.seed)) {
    errors.push('seed exceeds 2^53-1 and cannot be held exactly in a Number; pass it as a BigInt');
  } else if ((typeof m.seed === 'number' || typeof m.seed === 'bigint') && (m.seed < 0 || BigInt(m.seed) >= 18446744073709551616n)) {
    errors.push('seed must be a non-negative 64-bit integer (0 to 2^64-1)');
  }
  if (m.dataset && typeof m.dataset === 'object') {
    if (typeof m.dataset.id === 'string' && m.dataset.id.length < 1) errors.push('dataset.id must be non-empty');
    for (const k of Object.keys(m.dataset)) if (!['id','hash','uri'].includes(k)) errors.push(`dataset.${k}: unknown field (schema additionalProperties: false)`);
  }
  if (m.producer && typeof m.producer === 'object') {
    if (typeof m.producer.id === 'string' && m.producer.id.length < 1) errors.push('producer.id must be non-empty');
    for (const k of Object.keys(m.producer)) if (!['id','signature'].includes(k)) errors.push(`producer.${k}: unknown field (schema additionalProperties: false)`);
  }
  if (m.prior_hash !== undefined && !(typeof m.prior_hash === 'string' && /^[0-9a-fA-F]{64}$/.test(m.prior_hash))) {
    errors.push('prior_hash must be 64 hex characters');
  }
  if (m.notes !== undefined && !(typeof m.notes === 'string' && m.notes.length <= 4096)) {
    errors.push('notes must be a string of at most 4096 characters');
  }
  for (const k of Object.keys(m)) if (!TOP_KEYS.has(k)) errors.push(`${k}: unknown top-level field (schema additionalProperties: false)`);
  pushAll(errors, structuralErrors(m));
  pushAll(errors, typeErrors(m));
  return errors;
}

// Field types of the published schema, checked wherever a field is present
// (erratum 2026-11-15, second part). Same messages as the other references.
const isMapping = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
function typeErrors(m) {
  const errors = [];
  for (const f of ['claim_id', 'created_at', 'metric', 'comparator']) {
    if (f in m && typeof m[f] !== 'string') errors.push(`${f} must be a string`);
  }
  for (const f of ['dataset', 'producer', 'model', 'metric_args', 'compute_envelope', 'code']) {
    if (f in m && !isMapping(m[f])) errors.push(`${f} must be a mapping`);
  }
  const subs = { dataset: ['id', 'hash', 'uri'], producer: ['id', 'signature'], model: ['id', 'hash', 'uri'] };
  for (const [f, ks] of Object.entries(subs)) {
    if (!isMapping(m[f])) continue;
    for (const k of ks) if (k in m[f] && typeof m[f][k] !== 'string') errors.push(`${f}.${k} must be a string`);
  }
  // `model` keeps its other keys (`version` is common): only the types are checked.
  return errors;
}

// A new manifest carries `created_at` in one spelling (spec §2.1: UTC, second
// precision). `lock` enforces it; `hash` and `verify` still read manifests locked
// before 2026-11-15 in any RFC 3339 spelling.
function newManifestErrors(m) {
  if (typeof m.created_at === 'string' && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(m.created_at)) {
    return [`created_at must be written YYYY-MM-DDTHH:MM:SSZ (UTC, second precision) in a new manifest, got '${m.created_at}'`];
  }
  return [];
}


// ─────────────────────────────────────────────────────────────────────────
// Verifier
// ─────────────────────────────────────────────────────────────────────────

const EXIT_PASS = 0;
const EXIT_BAD = 2;       // bad input / spec: unreadable, unparseable, invalid manifest, bad --observed
const EXIT_TAMPERED = 3;
const EXIT_FAIL = 10;
const EXIT_GUARD = 11;    // environmental guard: missing sidecar / missing lib

function evaluatePredicate(observed, comparator, threshold, tolerance = 1e-9) {
  switch (comparator) {
    case '>=': return observed >= threshold;
    case '<=': return observed <= threshold;
    case '>':  return observed >  threshold;
    case '<':  return observed <  threshold;
    // Spec 5.1: equality is within a tolerance (default 1e-9, overridable via
    // metric_args.tolerance). Exact === was a footgun and did not match spec.
    case '==': return Math.abs(observed - threshold) < tolerance;
    default: throw new Error('invalid comparator: ' + comparator);
  }
}

// ─────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────

function cmdInit(name) {
  const dir = path.join('.falsify', name);
  fs.mkdirSync(dir, { recursive: true });
  const skeleton = {
    version: 'prml/0.1',
    claim_id: '01900000-0000-0000-0000-000000000000',
    created_at: new Date().toISOString().replace(/\.\d+/, ''),
    metric: 'accuracy',
    comparator: '>=',
    threshold: 0.0,
    dataset: { id: 'PLACEHOLDER', hash: '0'.repeat(64) },
    seed: 0,
    producer: { id: 'PLACEHOLDER' },
  };
  const yamlText = canonicalize(skeleton);
  fs.writeFileSync(path.join(dir, 'spec.yaml'), yamlText);
  console.log(`init: wrote ${dir}/spec.yaml`);
  console.log('Edit the placeholder values, then run: falsify-js lock ' + dir + '/spec.yaml');
  return EXIT_PASS;
}

// Reject prototype-polluting keys anywhere in a parsed manifest. Returns the
// object unchanged if clean; throws otherwise. Bounded depth as a DoS guard.
// ─────────────────────────────────────────────────────────────────────────
// Input layer: one closed reading of JSON and YAML, shared with the Python
// reference (falsify_prml.py) and the registry (canonical.js).
//
// - Numbers. A JSON number token, or in YAML a plain scalar spelled exactly as
//   a JSON number, is a number: an integer spelling is an integer (exact at any
//   magnitude: BigInt beyond 2^53-1), a spelling with a fraction or exponent is
//   a float64. YAML also reads `.inf`/`.nan` (rejected later as non-finite).
//   Any other plain scalar that YAML 1.1 or YAML 1.2 would type as a number
//   (`010`, `0x1F`, `1_000`, `1:30`, `.5`, `5.`, `+1`) is rejected: readers
//   disagree on its value. Quote it to make it a string.
// - An unquoted YAML timestamp is rejected; quote it.
// - Float spelling is remembered (FLOAT_SPELLED): `1.0` renders `1.0` and `1`
//   renders `1`, as in the other implementations (§C6 renders by type).
// - At most MAX_DEPTH levels of mappings and sequences (the root is level 1).
// ─────────────────────────────────────────────────────────────────────────

const MAX_DEPTH = 100;
const JSON_INT = /^-?(?:0|[1-9][0-9]*)$/;
const JSON_FLOAT = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?$/;
const SPECIAL_FLOAT = /^(?:[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$/;
const NUMBER_LIKE = [
  // YAML 1.1 int and float (PyYAML resolvers)
  /^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$/,
  /^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*)$/,
  // YAML 1.2 core int and float
  /^[-+]?(?:[0-9]+|0b[01]+|0o[0-7]+|0x[0-9a-fA-F]+)$/,
  /^(?:[-+]?[0-9]+(?:\.[0-9]*)?(?:[eE][-+]?[0-9]+)?|\.[0-9]+(?:[eE][-+]?[0-9]+)?)$/,
];
const YAML_TIMESTAMP = /^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$/;

// parent object/array -> Set of keys (indices for arrays) whose number was
// spelled as a float. Values stay plain Numbers, so every other check is unchanged.
const FLOAT_SPELLED = new WeakMap();
function markFloat(parent, key) {
  let s = FLOAT_SPELLED.get(parent);
  if (!s) { s = new Set(); FLOAT_SPELLED.set(parent, s); }
  s.add(key);
}
function isFloatSpelled(parent, key) {
  const s = parent && typeof parent === 'object' ? FLOAT_SPELLED.get(parent) : undefined;
  return !!(s && s.has(key));
}

function setOwn(obj, k, v) {
  // An own data property, even for "__proto__": never the prototype setter.
  if (k === '__proto__') Object.defineProperty(obj, k, { value: v, writable: true, enumerable: true, configurable: true });
  else obj[k] = v;
}

function numberFromSpelling(tok) {
  if (JSON_INT.test(tok)) {
    const n = Number(tok);
    if (Number.isSafeInteger(n)) return { v: n === 0 ? 0 : n, float: false };
    return { v: BigInt(tok), float: false };
  }
  return { v: Number(tok), float: true };
}

// parseJsonStrict: RFC 8259 JSON with no tolerance: no duplicate names, nothing
// after the value, depth limited, numbers read from their spelling. Strings are
// decoded by JSON.parse on the exact token. Same behaviour on every Node.js version.
function parseJsonStrict(text) {
  let i = 0;
  const fail = (msg) => { throw new SyntaxError(`${msg} at position ${i}`); };
  const ws = () => { while (i < text.length && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++; };
  function str() {
    const start = i++;
    while (i < text.length && text[i] !== '"') {
      const c = text.charCodeAt(i);
      if (c < 0x20) fail('Bad control character in string literal');
      i += text[i] === '\\' ? 2 : 1;
    }
    if (i >= text.length) fail('Unterminated string in JSON');
    i++;
    return JSON.parse(text.slice(start, i));
  }
  function value(parent, key, depth) {
    ws();
    const c = text[i];
    if (c === '{' || c === '[') {
      if (depth > MAX_DEPTH) throw new Error('manifest nesting too deep');
      i++;
      if (c === '{') {
        const obj = {};
        const seen = new Set();
        ws();
        if (text[i] === '}') { i++; return obj; }
        for (;;) {
          ws();
          if (text[i] !== '"') fail('Expected property name');
          const k = str();
          if (seen.has(k)) throw new SyntaxError(`duplicate key "${k}" — a PRML manifest MUST NOT repeat a key`);
          seen.add(k);
          ws();
          if (text[i] !== ':') fail("Expected ':' after property name");
          i++;
          setOwn(obj, k, value(obj, k, depth + 1));
          ws();
          if (text[i] === ',') { i++; continue; }
          if (text[i] === '}') { i++; return obj; }
          fail("Expected ',' or '}'");
        }
      }
      const arr = [];
      ws();
      if (text[i] === ']') { i++; return arr; }
      for (;;) {
        arr.push(value(arr, arr.length, depth + 1));
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; return arr; }
        fail("Expected ',' or ']'");
      }
    }
    if (c === '"') return str();
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    const m = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?/y;
    m.lastIndex = i;
    const hit = m.exec(text);
    if (!hit || hit[0] === '-') fail('Unexpected token in JSON');
    i += hit[0].length;
    const n = numberFromSpelling(hit[0]);
    if (n.float) markFloat(parent, key);
    return n.v;
  }
  const holder = {};
  const v = value(holder, '', 1);
  ws();
  if (i !== text.length) fail('Unexpected non-whitespace character after JSON');
  return v;
}

class FloatSpelled {
  constructor(v) { this.v = v; }
  get [Symbol.toStringTag]() { return 'PrmlFloat'; }
  toString() { return String(this.v); }
}

let _yamlSchema = null;
// Works with js-yaml 4 (falsify-js, CDN pages) and js-yaml 5 (the registry).
function prmlYamlSchema(yaml) {
  if (_yamlSchema && _yamlSchema.lib === yaml) return _yamlSchema.schema;
  const badNumberMsg = (d) => `'${d}' is not a JSON number spelling and YAML readers disagree on its value; write it as a JSON number, or quote it for a string`;
  const badTimestampMsg = (d) => `unquoted timestamp '${d}': quote it (YAML readers disagree on its value)`;
  // Implicitly, an integer spelling is taken by the int tag first; an explicit
  // `!!float 1` reaches this tag and reads as the float 1.0 (as in Python).
  const isFloatSpelling = (d) => JSON_FLOAT.test(d) || SPECIAL_FLOAT.test(d);
  const floatValue = (d) => {
    if (SPECIAL_FLOAT.test(d)) return /nan/i.test(d) ? NaN : (d[0] === '-' ? -Infinity : Infinity);
    return new FloatSpelled(Number(d));
  };
  let schema;
  if (typeof yaml.defineScalarTag === 'function') {
    const NR = yaml.NOT_RESOLVED;
    const S = (tag, fn) => yaml.defineScalarTag(tag, { implicit: true, identify: () => false, resolve: (d) => fn(d) });
    const keyOf = (k) => { if (typeof k !== 'string') throw new Error(nonStringKeyMsg(k)); return k; };
    const M = yaml.mapTag;
    const mapT = yaml.defineMappingTag('tag:yaml.org,2002:map', {
      create: M.create, identify: M.identify, represent: M.represent, keys: M.keys, get: M.get,
      addPair: (c, k, v) => M.addPair(c, keyOf(k), v),
      has: (c, k) => M.has(c, keyOf(k)),
    });
    schema = new yaml.Schema([
      yaml.strTag, yaml.seqTag, mapT, yaml.nullCoreTag, yaml.boolCoreTag,
      S('tag:yaml.org,2002:int', (d) => (JSON_INT.test(d) ? numberFromSpelling(d).v : NR)),
      S('tag:yaml.org,2002:float', (d) => (isFloatSpelling(d) ? floatValue(d) : NR)),
      S('tag:falsify.dev,2026:number-spelling', (d) => { if (NUMBER_LIKE.some((re) => re.test(d))) throw new Error(badNumberMsg(d)); return NR; }),
      S('tag:falsify.dev,2026:timestamp', (d) => { if (YAML_TIMESTAMP.test(d)) throw new Error(badTimestampMsg(d)); return NR; }),
    ]);
  } else {
    const T = (tag, resolve, construct) => new yaml.Type(tag, { kind: 'scalar', resolve, construct });
    schema = yaml.FAILSAFE_SCHEMA.extend({ implicit: [
      yaml.types.null, yaml.types.bool,
      T('tag:yaml.org,2002:int', (d) => JSON_INT.test(d), (d) => numberFromSpelling(d).v),
      T('tag:yaml.org,2002:float', isFloatSpelling, floatValue),
      T('tag:falsify.dev,2026:number-spelling', (d) => NUMBER_LIKE.some((re) => re.test(d)), (d) => { throw new Error(badNumberMsg(d)); }),
      T('tag:falsify.dev,2026:timestamp', (d) => YAML_TIMESTAMP.test(d), (d) => { throw new Error(badTimestampMsg(d)); }),
    ] });
  }
  _yamlSchema = { lib: yaml, schema };
  return schema;
}

// A mapping key MUST be a string (erratum 2026-11-15): a number, boolean, null or
// collection key reads differently in each YAML library.
function nonStringKeyMsg(k) {
  const shown = k instanceof FloatSpelled ? String(k.v) : Array.isArray(k) ? 'a sequence'
    : (k !== null && typeof k === 'object') ? 'a mapping' : String(k);
  return `mapping keys must be strings (quote the key): got ${shown}`;
}

// js-yaml 4 turns every key into a string before the schema sees it, so a key
// is recognised by its position: a node whose next significant character is a
// `:` indicator was read as a mapping key (implicit or explicit `?` form).
function nonStringKeyListener(event, state) {
  if (event !== 'close') return;
  const r = state.result;
  if (typeof r === 'string' && state.kind !== 'mapping' && state.kind !== 'sequence') return;
  const t = state.input;
  let i = state.position;
  for (;;) {
    while (i < t.length && (t[i] === ' ' || t[i] === '\t' || t[i] === '\n' || t[i] === '\r')) i++;
    if (t[i] === '#') { while (i < t.length && t[i] !== '\n') i++; continue; }
    break;
  }
  if (t[i] !== ':') return;
  // After a collection or a quoted scalar a key's `:` may touch the next node
  // (`{[a]:x}`, `{"1":x}`); after a plain scalar it needs a space or a flow
  // indicator, since `1:x` is one plain scalar.
  const adjacentOk = state.kind === 'mapping' || state.kind === 'sequence' || /["']/.test(t[state.position - 1]);
  if (adjacentOk || i + 1 >= t.length || /[\s,\[\]{}]/.test(t[i + 1])) throw new Error(nonStringKeyMsg(r));
}

// parseYamlStrict: js-yaml with the schema above; float markers are replaced by
// plain Numbers and recorded in FLOAT_SPELLED; depth limited.
function parseYamlStrict(yaml, text) {
  const opts = { schema: prmlYamlSchema(yaml) };
  if (typeof yaml.defineScalarTag !== 'function') opts.listener = nonStringKeyListener;
  const doc = yaml.load(text, opts);
  const seen = new Set();
  (function walk(o, depth) {
    if (!o || typeof o !== 'object' || o instanceof FloatSpelled) return;
    if (depth > MAX_DEPTH || seen.has(o)) throw new Error('manifest nesting too deep');
    seen.add(o);
    const keys = Array.isArray(o) ? o.keys() : Object.keys(o);
    for (const k of keys) {
      const v = o[k];
      if (v instanceof FloatSpelled) { setOwn(o, k, v.v); markFloat(o, k); } else walk(v, depth + 1);
    }
    seen.delete(o);
  })(doc, 1);
  return doc instanceof FloatSpelled ? doc.v : doc;
}

// structuralErrors: values with no canonical form, wherever they sit.
function structuralErrors(m) {
  const errors = [];
  (function walk(o, path, depth, inSeq) {
    if (typeof o === 'number') {
      if (!Number.isFinite(o) && path !== 'threshold') errors.push(`${path}: number is not a finite float64`);
      return;
    }
    if (!o || typeof o !== 'object') return;
    if (depth > MAX_DEPTH) { errors.push(`${path}: nesting deeper than ${MAX_DEPTH} levels`); return; }
    if (Array.isArray(o)) {
      if (inSeq) errors.push(`${path}: a sequence inside a sequence has no canonical form`);
      o.forEach((v, i) => walk(v, `${path}[${i}]`, depth + 1, true));
    } else {
      for (const k of Object.keys(o)) walk(o[k], path ? `${path}.${k}` : k, depth + 1, false);
    }
  })(m, '', 1, false);
  return errors;
}

// Invalid UTF-8 is an error rather than being replaced with U+FFFD, as in the
// other implementations. A BOM is kept, so the JSON reader still rejects it.
function readUtf8Strict(filePath) {
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(fs.readFileSync(filePath));
}

// parseManifest(text, format): the CLI's reading of a manifest, for library
// callers who hold the text. format is 'json' or 'yaml'.
function parseManifest(text, format) {
  if (format === 'json') {
    const parsed = parseJsonStrict(text);
    if (parsed && typeof parsed.threshold === 'bigint') parsed.threshold = Number(parsed.threshold);
    return parsed;
  }
  const parsed = parseYamlStrict(require('js-yaml'), text);
  if (parsed && typeof parsed.threshold === 'bigint') parsed.threshold = Number(parsed.threshold);
  return parsed;
}

function loadManifest(filePath) {
  if (filePath.endsWith('.json')) {
    const parsed = parseJsonStrict(readUtf8Strict(filePath));
    // §3.5: v0.1 threshold is a float64 whatever its spelling.
    if (parsed && typeof parsed.threshold === 'bigint') parsed.threshold = Number(parsed.threshold);
    return parsed;
  }
  // Otherwise use js-yaml. Declared dependency since 0.2.0: the canonical media
  // type is application/vnd.prml+yaml, so a verifier that cannot read YAML cannot
  // read the format. It stays behind require() so a JSON-only caller in a locked-down
  // environment still works if the module is absent.
  let yaml;
  try {
    yaml = require('js-yaml');
  } catch (e) {
    throw new Error('YAML loading requires js-yaml (a declared dependency of falsify-js; reinstall the package, or run: npm install js-yaml). Or pass a .json file.');
  }
  // The schema has only null, bool, int, float and str: no custom/JS type tags
  // (e.g. !!js/function) can be instantiated from untrusted manifest content.
  const parsed = parseYamlStrict(yaml, readUtf8Strict(filePath));
  if (parsed && typeof parsed.threshold === 'bigint') parsed.threshold = Number(parsed.threshold);
  return parsed;
}

function cmdLock(filePath) {
  const m = loadManifest(filePath);
  let errors = validateManifest(m);
  if (!errors.length) errors = newManifestErrors(m);
  if (errors.length) {
    console.error('lock: invalid manifest:');
    errors.forEach(e => console.error('  - ' + e));
    return EXIT_BAD;
  }
  const canonical = canonicalize(m);
  const hash = crypto.createHash('sha256').update(canonical, 'utf-8').digest('hex');
  const sidecar = filePath.replace(/\.[^.]+$/, '') + '.prml.sha256';
  fs.writeFileSync(sidecar, hash + '\n');
  console.log(`locked: ${filePath}`);
  console.log(`  canonical bytes: ${canonical.length}`);
  console.log(`  sha256:          ${hash}`);
  console.log(`  sidecar:         ${sidecar}`);
  return EXIT_PASS;
}

function cmdVerify(filePath, observedStr) {
  const m = loadManifest(filePath);
  const errors = validateManifest(m);
  if (errors.length) {
    console.error('verify: invalid manifest:');
    errors.forEach(e => console.error('  - ' + e));
    return EXIT_BAD;
  }
  const canonical = canonicalize(m);
  const computed = crypto.createHash('sha256').update(canonical, 'utf-8').digest('hex');
  const sidecar = filePath.replace(/\.[^.]+$/, '') + '.prml.sha256';
  if (!fs.existsSync(sidecar)) {
    console.error(`verify: sidecar not found: ${sidecar}`);
    return EXIT_GUARD;
  }
  const claimedHash = fs.readFileSync(sidecar, 'utf-8').trim();
  if (computed !== claimedHash) {
    console.error('TAMPERED');
    console.error(`  recorded:    ${claimedHash}`);
    console.error(`  recomputed:  ${computed}`);
    return EXIT_TAMPERED;
  }
  if (observedStr === undefined) {
    console.log(`hash OK: ${computed}`);
    console.log('(no --observed value given; predicate not evaluated)');
    return EXIT_PASS;
  }
  const observed = parseFloat(observedStr);
  if (!Number.isFinite(observed)) {
    console.error('verify: --observed must be a finite number');
    return EXIT_BAD;
  }
  const _tol = (m.metric_args && typeof m.metric_args.tolerance === 'number') ? m.metric_args.tolerance : 1e-9;
  const ok = evaluatePredicate(observed, m.comparator, m.threshold, _tol);
  if (ok) {
    console.log(`PASS  metric=${m.metric}  observed=${observed}  ${m.comparator}  threshold=${m.threshold}`);
    return EXIT_PASS;
  } else {
    console.log(`FAIL  metric=${m.metric}  observed=${observed}  NOT ${m.comparator}  threshold=${m.threshold}`);
    return EXIT_FAIL;
  }
}

function cmdTestVectors(vectorsPath) {
  // The strict reader keeps every input as written: integers beyond 2^53-1 as
  // BigInt and float spelling (`1.0`), which a vector may depend on.
  const vectors = parseJsonStrict(readUtf8Strict(vectorsPath));

  let pass = 0, fail = 0;
  for (const v of vectors) {
    const produced = canonicalize(v.input);
    const producedHash = crypto.createHash('sha256').update(produced, 'utf-8').digest('hex');
    const ok = produced === v.canonical && producedHash === v.hash;
    if (ok) {
      pass++;
      console.log(`PASS  ${v.id}  ${v.title}`);
    } else {
      fail++;
      console.log(`FAIL  ${v.id}  ${v.title}`);
      const a = v.canonical, b = produced;
      let i = 0;
      while (i < a.length && i < b.length && a[i] === b[i]) i++;
      console.log(`        first diff @ char ${i}`);
      console.log(`        expected: ${JSON.stringify(a.slice(Math.max(0,i-10), i+30))}`);
      console.log(`        produced: ${JSON.stringify(b.slice(Math.max(0,i-10), i+30))}`);
    }
  }
  console.log(`\nResult: ${pass}/${vectors.length} vectors passed.`);
  return fail === 0 ? EXIT_PASS : EXIT_FAIL;
}

function usage() {
  process.stderr.write(`falsify-js — PRML v0.1 reference implementation (Node.js)

Commands:
  init <name>                            create skeleton in .falsify/<name>/
  lock <spec.json|spec.yaml>             canonicalize, hash, write sidecar
  verify <spec.json> [--observed <v>]    verify hash; if --observed, evaluate
  test-vectors <vectors.json>            run conformance suite
  hash <spec.json>                       print canonical SHA-256 only

Exit codes: 0=PASS, 2=BAD (bad input/spec), 3=TAMPERED, 10=FAIL, 11=GUARD (missing sidecar/lib)
Spec:    https://spec.falsify.dev/v0.1
`);
  return EXIT_GUARD;
}

function cmdHash(filePath) {
  const m = loadManifest(filePath);
  // Validate before hashing: an invalid or non-portable manifest would
  // otherwise emit a hash the other reference impls reject — a silent,
  // non-portable commitment. Matches lock/verify here and the Go/Rust impls.
  const errors = validateManifest(m);
  if (errors.length) {
    console.error('hash: invalid manifest:');
    errors.forEach(e => console.error('  - ' + e));
    return EXIT_BAD;
  }
  console.log(manifestHash(m));
  return EXIT_PASS;
}

function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0) return usage();
  const cmd = args[0];
  try {
    switch (cmd) {
      case 'init':         return cmdInit(args[1] || 'default');
      case 'lock':         return cmdLock(args[1]);
      case 'verify': {
        const idx = args.indexOf('--observed');
        const observed = idx >= 0 ? args[idx + 1] : undefined;
        return cmdVerify(args[1], observed);
      }
      case 'test-vectors': return cmdTestVectors(args[1]);
      case 'hash':         return cmdHash(args[1]);
      case '-h':
      case '--help':       return usage() === EXIT_GUARD ? EXIT_PASS : EXIT_PASS;
      default:             return usage();
    }
  } catch (e) {
    // Unreadable file, malformed JSON/YAML — bad input (EXIT_BAD=2), matching
    // the Python reference, not an environmental guard.
    console.error(`${cmd}: ${e.message}`);
    return EXIT_BAD;
  }
}

if (require.main === module) {
  process.exit(main(process.argv));
}

// Programmatic API for embedders
module.exports = {
  canonicalize,
  loadManifest,
  parseManifest,
  manifestHash,
  validateManifest,
  newManifestErrors,
  evaluatePredicate,
  needsQuoting,
  EXIT_PASS, EXIT_BAD, EXIT_TAMPERED, EXIT_FAIL, EXIT_GUARD,
};
