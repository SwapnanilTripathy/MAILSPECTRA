import test from 'node:test';
import assert from 'node:assert/strict';
import { maskAnalysis } from '../src/utils/privacy.js';

test('masks nested presentation fields without altering the evidence', () => {
  const analysis = {
    metadata: {
      from_sender: {
        display_name: 'Alice Smith',
        address: 'alice@example.test',
        raw: 'Alice Smith <alice@example.test>',
      },
    },
    body: {
      text_plain:
        'From Alice Smith at alice@example.test, IP 192.0.2.44 and 2001:db8::1.',
    },
    ips: [{ ip: '192.0.2.44', defanged_ip: '192[.]0[.]2[.]44' }],
    geolocation: { '192.0.2.44': { ip: '192.0.2.44' } },
  };
  const original = structuredClone(analysis);
  const masked = maskAnalysis(analysis);
  assert.deepEqual(analysis, original);
  assert.equal(masked.metadata.from_sender.address, 'a***e@example.test');
  assert.equal(masked.metadata.from_sender.display_name, 'A***e S***h');
  assert.doesNotMatch(
    JSON.stringify(masked),
    /alice@example\.test|192\.0\.2\.44|2001:db8::1|Alice Smith/,
  );
  assert.equal(masked.ips[0].defanged_ip, '192[.]0[.]***[.]***');
});
