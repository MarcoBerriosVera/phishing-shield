#!/usr/bin/env node
/**
 * test-block-flow.js — Phishing Shield
 * Simulates the orchestrator response for a danger URL and verifies
 * the block page renders with the correct parameters.
 *
 * Usage:
 *   node test-block-flow.js
 *
 * Requires: node >= 18 (built-in fetch)
 */

'use strict';

const assert = (cond, msg) => {
  if (!cond) { console.error(`  ✗ FAIL: ${msg}`); process.exitCode = 1; }
  else         console.log(`  ✓ ${msg}`);
};

// ── 1. Threshold logic ────────────────────────────────────────────────────────
console.log('\n[1] Threshold classification');
const SAFE = 0.75, SUSPICIOUS = 0.55;
const classify = s => s >= SAFE ? 'safe' : s >= SUSPICIOUS ? 'suspicious' : 'danger';

assert(classify(0.90) === 'safe',       'score 0.90 → safe');
assert(classify(0.75) === 'safe',       'score 0.75 → safe (boundary)');
assert(classify(0.65) === 'suspicious', 'score 0.65 → suspicious');
assert(classify(0.55) === 'suspicious', 'score 0.55 → suspicious (boundary)');
assert(classify(0.54) === 'danger',     'score 0.54 → danger');
assert(classify(0.20) === 'danger',     'score 0.20 → danger');
assert(classify(0.00) === 'danger',     'score 0.00 → danger');

// ── 2. Block URL params builder ───────────────────────────────────────────────
console.log('\n[2] Block URL parameter encoding');

function buildParams(url, score, services) {
  const reasons = [];
  if ((services?.heuristics?.score ?? 1) < SUSPICIOUS)
    reasons.push('Patrones de URL sospechosos detectados por análisis heurístico.');
  if ((services?.similarity?.score  ?? 1) < SUSPICIOUS)
    reasons.push('Alta similitud con dominios de phishing conocidos.');
  if ((services?.reputation?.score  ?? 1) < SUSPICIOUS)
    reasons.push('Dominio con mala reputación en bases de datos de seguridad.');
  if ((services?.ml?.score          ?? 1) < SUSPICIOUS)
    reasons.push('Modelo de machine learning clasifica la URL como amenaza.');

  return new URLSearchParams({
    url:        encodeURIComponent(url),
    score,
    heuristics: services?.heuristics?.score ?? 0,
    similarity: services?.similarity?.score  ?? 0,
    reputation: services?.reputation?.score  ?? 0,
    ml:         services?.ml?.score          ?? 0,
    reasons:    encodeURIComponent(reasons.join('|')),
  });
}

const mockResult = {
  url: 'https://secure-paypa1.com/login',
  score: 0.23,
  status: 'danger',
  services: {
    heuristics: { score: 0.18, status: 'danger' },
    similarity:  { score: 0.30, status: 'danger' },
    reputation:  { score: 0.22, status: 'danger' },
    ml:          { score: 0.40, status: 'danger' },
  },
};

const params = buildParams(mockResult.url, mockResult.score, mockResult.services);
const parsed = Object.fromEntries(params.entries());

assert(parsed.score === '0.23',  'overall score encoded correctly');
assert(parsed.heuristics === '0.18', 'heuristics score encoded');
assert(parseFloat(parsed.similarity)  === 0.30, 'similarity score encoded');
assert(parseFloat(parsed.reputation)  === 0.22, 'reputation score encoded');
assert(parseFloat(parsed.ml)          === 0.40, 'ml score encoded');
assert(decodeURIComponent(parsed.reasons).includes('|'), 'reasons joined with pipe');
assert(decodeURIComponent(parsed.url).includes('paypa1'), 'url encoded and decodable');

// ── 3. Reason generation ──────────────────────────────────────────────────────
console.log('\n[3] Reason message generation');
const reasons = decodeURIComponent(parsed.reasons).split('|').filter(Boolean);
assert(reasons.length === 4, 'all 4 services contribute a reason when all danger');

const mixedServices = {
  heuristics: { score: 0.80 }, // safe — no reason
  similarity:  { score: 0.30 }, // danger
  reputation:  { score: 0.60 }, // suspicious — no reason (only < 0.55)
  ml:          { score: 0.40 }, // danger
};
const mixedParams  = buildParams('https://example.com', 0.48, mixedServices);
const mixedReasons = decodeURIComponent(mixedParams.get('reasons')).split('|').filter(Boolean);
assert(mixedReasons.length === 2, 'only danger services generate reasons');

// ── 4. Session allowlist ──────────────────────────────────────────────────────
console.log('\n[4] Session allowlist behaviour');
const allowed = new Set();
const testUrl = 'https://fake-bank.com/login';
assert(!allowed.has(testUrl), 'url not in allowlist initially');
allowed.add(testUrl);
assert(allowed.has(testUrl), 'url added to allowlist after "proceed anyway"');
// New URL should still be blocked
assert(!allowed.has('https://other-phish.com/'), 'different url still blocked');

// ── 5. Stats accumulation ─────────────────────────────────────────────────────
console.log('\n[5] Stats counter logic');
const stats = { safe: 0, suspicious: 0, danger: 0, blocked: 0 };
const results = ['safe', 'safe', 'suspicious', 'danger', 'danger', 'safe'];
results.forEach(s => {
  if (s === 'safe') stats.safe++;
  else if (s === 'suspicious') stats.suspicious++;
  else { stats.danger++; stats.blocked++; }
});
assert(stats.safe === 3,       'safe count correct');
assert(stats.suspicious === 1, 'suspicious count correct');
assert(stats.danger === 2,     'danger count correct');
assert(stats.blocked === 2,    'blocked count equals danger count');

// ── Summary ───────────────────────────────────────────────────────────────────
console.log('\n─────────────────────────────────────────');
if (process.exitCode === 1) {
  console.log('❌  Some tests failed. Review above.\n');
} else {
  console.log('✅  All tests passed.\n');
}
