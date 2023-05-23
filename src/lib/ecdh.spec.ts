import anyTest, { TestInterface } from 'ava';

import fixtures from '../fixtures/ecdh.json';

import { loadSecp256k1ZKP } from './cmodule';
import { ecdh } from './ecdh';
import { ZKP } from './interface';

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
