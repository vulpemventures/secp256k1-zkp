import anyTest, { TestInterface } from 'ava';

import { loadSecp256k1ZKP } from '../lib/cmodule';
import { generator } from '../lib/generator';
import { Secp256k1ZKP } from '../lib/interface';

import fixtures from './fixtures/generator.json';

const test = anyTest as TestInterface<Secp256k1ZKP['generator']>;

test.before(async (t) => {
  const cModule = await loadSecp256k1ZKP();
  t.context = generator(cModule);
});

test('generate', (t) => {
  const { generate } = t.context;

  fixtures.generate.forEach((f) => {
    const seed = new Uint8Array(Buffer.from(f.seed, 'hex'));
    t.is(Buffer.from(generate(seed)).toString('hex'), f.expected);
  });
});

test('generate_blinded', (t) => {
  const { generateBlinded } = t.context;

  fixtures.generateBlinded.forEach((f) => {
    const key = new Uint8Array(Buffer.from(f.key, 'hex'));
    const blindingKey = new Uint8Array(Buffer.from(f.blind, 'hex'));
    t.is(
      Buffer.from(generateBlinded(key, blindingKey)).toString('hex'),
      f.expected
    );
  });
});
