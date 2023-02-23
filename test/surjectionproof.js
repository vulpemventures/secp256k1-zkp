const chai = require('chai');
const assert = chai.assert;

const secp256k1 = require('../lib');
const fixtures = require('./fixtures/surjectionproof.json');

describe('surjection proof', () => {
  let verify, generate, serialize, initialize;

  before(async () => {
    ({ parse, verify, generate, serialize, initialize } = (
      await secp256k1()
    ).surjectionproof);
  });

  it('initialize proof', () => {
    fixtures.initialize.forEach((f) => {
      const seed = new Uint8Array(Buffer.from(f.seed, 'hex'));
      const inputTags = f.inputTags.map(
        (t) => new Uint8Array(Buffer.from(t, 'hex'))
      );
      const outputTag = new Uint8Array(Buffer.from(f.outputTag, 'hex'));
      const res = initialize(inputTags, outputTag, f.maxIterations, seed);
      assert.deepEqual(
        Buffer.from(res.proof).toString('hex'),
        f.expected.proof
      );
      assert.deepEqual(res.inputIndex, f.expected.inputIndex);
    });
  });

  it('generate proof', () => {
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
      assert.deepEqual(Buffer.from(res).toString('hex'), f.expectedProof);
    });
  });

  it('verify proof', () => {
    fixtures.verify.forEach((f) => {
      const proof = new Uint8Array(Buffer.from(f.proof, 'hex'));
      const ephemeralInputTags = f.ephemeralInputTags.map(
        (v) => new Uint8Array(Buffer.from(v, 'hex'))
      );
      const ephemeralOutputTag = new Uint8Array(
        Buffer.from(f.ephemeralOutputTag, 'hex')
      );
      assert.deepEqual(
        verify(proof, ephemeralInputTags, ephemeralOutputTag),
        f.expected
      );
    });
  });
});
