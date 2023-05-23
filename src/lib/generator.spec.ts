import anyTest, { TestInterface } from 'ava';

import fixtures from '../fixtures/generator.json';

import { loadSecp256k1ZKP } from './cmodule';
import { generator } from './generator';
import { ZKP } from './interface';

const test = anyTest as TestInterface<ZKP['generator']>;

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
