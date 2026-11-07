import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { DEMO_SAMPLE_FILES } from '../src/demoSamples.js';

const here = dirname(fileURLToPath(import.meta.url));
const sampleDirectory = resolve(here, '../public/demo-samples');
const hostnamePattern = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;

/**
 * Extract DNS-style hostnames from a raw email fixture.
 * IPv4 literals are excluded by the alphabetic final-label requirement.
 */
function extractHostnames(raw) {
  return [...new Set(raw.match(hostnamePattern) || [])];
}

test('Quick Demo mapping contains the three documented scenarios', () => {
  assert.deepEqual(Object.keys(DEMO_SAMPLE_FILES).sort(), ['benign', 'phishing', 'spoofed']);
  assert.equal(new Set(Object.values(DEMO_SAMPLE_FILES)).size, 3);
});

for (const [scenario, filename] of Object.entries(DEMO_SAMPLE_FILES)) {
  test(`${scenario} demo is a safe, parseable-looking RFC 5322 text fixture`, () => {
    assert.match(filename, /^[a-z_]+\.eml$/);
    const raw = readFileSync(resolve(sampleDirectory, filename), 'utf8');

    assert.ok(raw.length > 100, 'sample should not be empty');
    assert.match(raw, /^From:/m);
    assert.match(raw, /^To:/m);
    assert.match(raw, /^Subject:/m);
    assert.match(raw, /^Date:/m);
    assert.match(raw, /^Message-ID:/m);
    assert.match(raw, /^MIME-Version:/m);
    const hostnames = extractHostnames(raw);
    assert.ok(hostnames.length > 0, 'sample should contain at least one hostname');
    for (const hostname of hostnames) {
      assert.match(
        hostname,
        /\.test$/i,
        `hostname ${hostname} must use the reserved .test namespace`,
      );
    }

    const ipLiterals = [...raw.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)].map(([ip]) => ip);
    for (const ip of ipLiterals) {
      assert.match(
        ip,
        /^(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)\d{1,3}$/,
        `IP literal ${ip} must be in an RFC 5737 documentation range`,
      );
    }

    assert.doesNotMatch(raw, /password\s*[:=]\s*\S+/i, 'no credential values');
    assert.doesNotMatch(raw, /BEGIN (?:RSA |OPENSSH )?PRIVATE KEY/i, 'no private keys');
  });
}
