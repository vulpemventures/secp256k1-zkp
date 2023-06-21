import anyTest, { TestInterface } from 'ava';

import { loadSecp256k1ZKP } from '../lib/cmodule';
import { Secp256k1ZKP } from '../lib/interface';
import { surjectionproof } from '../lib/surjectionproof';

import fixtures from './fixtures/surjectionproof.json';

const test = anyTest as TestInterface<Secp256k1ZKP['surjectionproof']>;

test.before(async (t) => {
  const cModule = await loadSecp256k1ZKP();
  t.context = surjectionproof(cModule);
});

test('initialize proof', (t) => {
  const { initialize } = t.context;

  fixtures.initialize.forEach((f) => {
    const seed = new Uint8Array(Buffer.from(f.seed, 'hex'));
    const inputTags = f.inputTags.map(
      (t) => new Uint8Array(Buffer.from(t, 'hex'))
    );
    const outputTag = new Uint8Array(Buffer.from(f.outputTag, 'hex'));
    const res = initialize(inputTags, outputTag, f.maxIterations, seed);
    t.is(Buffer.from(res.proof).toString('hex'), f.expected.proof);
    t.is(res.inputIndex, f.expected.inputIndex);
  });
});

test('generate proof', (t) => {
  const { generate } = t.context;

  fixtures.generate.forEach((f) => {
    const proof = new Uint8Array(Buffer.from(f.proof, 'hex'));
    const ephemeralInputTags = f.ephemeralInputTags.map(
      (v) => new Uint8Array(Buffer.from(v, 'hex'))
    );
    const ephemeralOutputTag = new Uint8Array(
      Buffer.from(f.ephemeralOutputTag, 'hex')
    );
    const inputBlindingKey = new Uint8Array(
      Buffer.from(f.inputBlindingKey, 'hex')
    );
    const outputBlindingKey = new Uint8Array(
      Buffer.from(f.outputBlindingKey, 'hex')
    );
    const res = generate(
      proof,
      ephemeralInputTags,
      ephemeralOutputTag,
      f.inputIndex,
      inputBlindingKey,
      outputBlindingKey
    );
    t.is(Buffer.from(res).toString('hex'), f.expectedProof);
  });
});

test('verify proof', (t) => {
  const { verify } = t.context;

  fixtures.verify.forEach((f) => {
    const proof = new Uint8Array(Buffer.from(f.proof, 'hex'));
    const ephemeralInputTags = f.ephemeralInputTags.map(
      (v) => new Uint8Array(Buffer.from(v, 'hex'))
    );
    const ephemeralOutputTag = new Uint8Array(
      Buffer.from(f.ephemeralOutputTag, 'hex')
    );
    t.is(verify(proof, ephemeralInputTags, ephemeralOutputTag), f.expected);
  });
});
