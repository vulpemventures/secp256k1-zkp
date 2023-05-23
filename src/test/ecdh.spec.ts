import anyTest, { TestInterface } from 'ava';

import { loadSecp256k1ZKP } from '../lib/cmodule';
import { ecdh } from '../lib/ecdh';
import { ZKP } from '../lib/interface';

import fixtures from './fixtures/ecdh.json';

const test = anyTest as TestInterface<{ ecdh: ZKP['ecdh'] }>;

test.before(async (t) => {
  const cModule = await loadSecp256k1ZKP();
  t.context = { ecdh: ecdh(cModule) };
});

test('ecdh', (t) => {
  const { ecdh } = t.context;

  fixtures.ecdh.forEach((f) => {
    const pubkey = Buffer.from(f.pubkey, 'hex');
    const scalar = Buffer.from(f.scalar, 'hex');
    t.is(Buffer.from(ecdh(pubkey, scalar)).toString('hex'), f.expected);
  });
});
