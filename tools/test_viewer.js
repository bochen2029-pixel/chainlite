// Regression tests for web/viewer.html's escaping, run against the real file so
// they cannot drift from it. Requires node; build.bat skips this step if absent.
//
//   node tools\test_viewer.js
//
// Chain data is attacker-controlled: anyone can put 1 KB of arbitrary bytes on
// the chain as a RECORD, and a proof file comes from whoever handed it to you.
// The page keeps a spendable key in localStorage, so an injection here is a key
// theft, not a defacement.
const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '..', 'web', 'viewer.html');
const src = fs.readFileSync(file, 'utf8');

let fails = 0;
function check(name, cond) {
  if (!cond) { console.log('FAIL ' + name); fails++; }
}

// Pull the real esc() and tshort() out of the page rather than reimplementing them.
function extract(sig) {
  const i = src.indexOf(sig);
  if (i < 0) throw new Error('could not find ' + sig + ' in viewer.html');
  const end = src.indexOf('\n', i);
  return src.slice(i, end);
}
const esc = eval('(' + extract('function esc(s)').replace(/^function esc/, 'function') + ')');
const tshort = eval('(' + extract('function tshort(h,n=16)').replace(/^function tshort/, 'function') + ')');

// Multi-line functions: these are top-level in the page, so their body ends at the
// first "}" sitting in column 0. Lifting them verbatim keeps the tests honest —
// they exercise the shipped code, not a copy of it.
function extractFn(name) {
  const i = src.indexOf('function ' + name + '(');
  if (i < 0) throw new Error('could not find function ' + name);
  const end = src.indexOf('\n}', i);
  if (end < 0) throw new Error('could not find end of ' + name);
  return src.slice(i, end + 2);
}
const NOTE_FNS = ['noteEnvelope', 'buildNotePayload', 'parseNoteEnvelope', 'decodePayload']
  .map(extractFn).join('\n');
const V = new Function('enc', 'fromHex',
  NOTE_FNS + '\nreturn {noteEnvelope,buildNotePayload,parseNoteEnvelope,decodePayload};'
)(new TextEncoder(), eval('(' + extract('function fromHex(s)').replace(/^function fromHex/, 'function') + ')'));

const toHexBytes = b => [...b].map(x => x.toString(16).padStart(2, '0')).join('');

// ---- the timestamp envelope goes INSIDE the signed payload ----
{
  const iso = '2026-07-25T14:45:18.123Z';
  const env = JSON.parse(V.noteEnvelope('Hello World!', iso));
  check('envelope carries the message', env.msg === 'Hello World!');
  check('envelope carries the timestamp', env.t === iso);

  // round-trip through the exact bytes that land on chain
  const hex = toHexBytes(V.buildNotePayload('Hello World!', iso));
  const d = V.decodePayload(hex);
  check('round-trip kind', d.kind === 'text');
  check('round-trip shows only the message', d.text === 'Hello World!');
  check('round-trip exposes authored time', d.authored === iso);

  // a real timestamp is emitted when none is supplied
  const auto = JSON.parse(V.noteEnvelope('x'));
  check('auto timestamp is a valid ISO instant', isFinite(Date.parse(auto.t)));
  check('auto timestamp is UTC', /Z$/.test(auto.t));
  check('auto timestamp has second resolution or better', /T\d\d:\d\d:\d\d/.test(auto.t));
}

// ---- backward compatibility: plain notes must still render ----
{
  const plain = toHexBytes(new TextEncoder().encode('an older plain note'));
  const d = V.decodePayload(plain);
  check('plain note still decodes as text', d.kind === 'text' && d.text === 'an older plain note');
  check('plain note has no authored time', d.authored === undefined);
}

// ---- an anchor record must NOT be mistaken for a timestamped note ----
{
  const anchor = '{"v":1,"kind":"intercom-anchor","from":1,"to":9,"n":9,"root":"ab"}';
  check('anchor JSON is not treated as an envelope', V.parseNoteEnvelope(anchor) === null);
  const d = V.decodePayload(toHexBytes(new TextEncoder().encode(anchor)));
  check('anchor renders as its raw text', d.kind === 'text' && d.text === anchor && !d.authored);
}

// ---- malformed / hostile envelopes are rejected, not half-parsed ----
{
  check('non-JSON rejected', V.parseNoteEnvelope('just text') === null);
  check('array rejected', V.parseNoteEnvelope('[1,2]') === null);
  check('null rejected', V.parseNoteEnvelope('null') === null);
  check('missing msg rejected', V.parseNoteEnvelope('{"t":"2026-01-01T00:00:00Z"}') === null);
  check('missing t rejected', V.parseNoteEnvelope('{"msg":"hi"}') === null);
  check('non-string msg rejected', V.parseNoteEnvelope('{"t":"2026-01-01T00:00:00Z","msg":5}') === null);
  check('unparseable t rejected', V.parseNoteEnvelope('{"t":"not a date","msg":"hi"}') === null);
  // a binary payload (file hash) must still be reported as a hash, not text
  const bin = toHexBytes(new Uint8Array([0, 1, 2, 3, 255]));
  check('binary payload still reported as hash', V.decodePayload(bin).kind === 'hash');
}

// ---- an injected message inside the envelope stays inert ----
{
  const hex = toHexBytes(V.buildNotePayload('<svg onload=alert()>', '2026-01-01T00:00:00Z'));
  const d = V.decodePayload(hex);
  check('injected msg survives decode verbatim', d.text === '<svg onload=alert()>');
  check('but esc() neutralises it for rendering', esc(d.text).indexOf('<') === -1);
  // the authored field is chain-controlled too and must be escaped wherever shown
  const evil = V.parseNoteEnvelope('{"t":"2026-01-01T00:00:00Z\\" onmouseover=alert()","msg":"x"}');
  check('hostile t either rejected or escapable',
        evil === null || esc(evil.t).indexOf('"') === -1);
}

// ---- the byte counter must include the envelope, not just the text ----
{
  check('updateCounter measures the full payload',
        /const n = t \? buildNotePayload\(t\)\.length : 0/.test(src));
  check('postNote builds the envelope', /const payload = buildNotePayload\(text\)/.test(src));
  const overhead = V.buildNotePayload('', '2026-07-25T14:45:18.123Z').length;
  check('envelope overhead is small and known (' + overhead + ' B)', overhead > 0 && overhead < 60);
}

// ---- esc() covers every character that matters in text AND attribute context ----
check('esc <', esc('<b>') === '&lt;b&gt;');
check('esc &', esc('a&b') === 'a&amp;b');
check('esc double quote', esc('a"b') === 'a&quot;b');
check('esc single quote', esc("a'b") === 'a&#39;b');
check('esc combined', esc(`<img src=x onerror="alert('1')">`).indexOf('<') === -1);
check('esc non-string input', esc(undefined) === 'undefined');

// ---- the proof verifier must escape every field it renders ----
// Regression: blockhash went in raw through tshort(), and tshort keeps 20 chars —
// exactly the length of "<svg onload=alert()>".
const PAYLOAD = '<svg onload=alert()>';
check('payload is exactly the 20 chars tshort keeps', PAYLOAD.length === 20);
check('tshort alone does NOT neutralise it', tshort(PAYLOAD, 20).indexOf('<svg') === 0);
check('esc(tshort(...)) does', esc(tshort(PAYLOAD, 20)).indexOf('<') === -1);

// Assert against the file itself: the verify-output template must not interpolate
// blockhash/height bare. Find the line and require esc( on every ${...}.
const verifyLine = src.split('\n').find(l => l.includes('committed at'));
check('found the verify output line', !!verifyLine);
if (verifyLine) {
  const interps = verifyLine.match(/\$\{[^}]*\}/g) || [];
  check('verify line interpolates something', interps.length > 0);
  for (const it of interps)
    check('verify output escapes ' + it, /\besc\(/.test(it));
}

// ---- the notes feed must escape note bodies ----
const feedLines = src.split('\n').filter(l => l.includes('note-body'));
check('found note-body rendering', feedLines.length > 0);
for (const l of feedLines)
  for (const it of l.match(/\$\{[^}]*\}/g) || [])
    check('note body escapes ' + it, /\besc\(/.test(it) || /^\$\{(cls|body|status|actions)\}$/.test(it));

// ---- writes must carry the CSRF header the node now requires ----
check('rpost sends X-Chainlite', /X-Chainlite/.test(src));
check('rpost still POSTs', /method:"POST"/.test(src));

// ---- node list is coerced to numbers before reaching markup/onclick ----
check('discoverNodes filters to integers', /Number\.isInteger/.test(src));

// ---- the wildcard CORS assumption must be gone from the comments/code ----
check('no fetch to a non-loopback host', !/fetch\((["'`])https?:\/\/(?!\$\{host\})/.test(src));

console.log(fails ? `\nVIEWER TESTS: ${fails} FAILURE(S)` : '\nVIEWER TESTS: ALL PASS');
process.exit(fails ? 1 : 0);
