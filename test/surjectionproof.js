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

  it('parse proof', () => {
    fixtures.parse.forEach((f) => {
      const proof = Buffer.from(f.proof, 'hex');
      const res = parse(proof);
      assert.deepStrictEqual(res.nInputs, f.expected.nInputs);
      assert.deepStrictEqual(
        res.usedInputs.toString('hex'),
        f.expected.usedInputs
      );
      assert.deepStrictEqual(res.data.toString('hex'), f.expected.data);
    });
  });

  it('initialize proof', () => {
    fixtures.initialize.forEach((f) => {
      const seed = Buffer.from(f.seed, 'hex');
      const inputTags = f.inputTags.map((t) => Buffer.from(t, 'hex'));
      const outputTag = Buffer.from(f.outputTag, 'hex');
      const res = initialize(
        inputTags,
        f.inputTagsToUse,
        outputTag,
        f.maxIterations,
        seed
      );
      assert.deepEqual(res.proof.nInputs, f.expected.proof.nInputs);
      assert.deepEqual(res.proof.data.toString('hex'), f.expected.proof.data);
      assert.deepEqual(
        res.proof.usedInputs.toString('hex'),
        f.expected.proof.usedInputs
      );
      assert.deepEqual(res.proof.inputIndex, f.expected.proof.inputIndex);
    });
  });

  it('generate proof', () => {
    fixtures.generate.forEach((f) => {
      const proof = {
        nInputs: f.proof.nInputs,
        data: Buffer.from(f.proof.data, 'hex'),
        usedInputs: Buffer.from(f.proof.usedInputs, 'hex'),
      };
      const ephemeralInputTags = f.ephemeralInputTags.map((v) =>
        Buffer.from(v, 'hex')
      );
      const ephemeralOutputTag = Buffer.from(f.ephemeralOutputTag, 'hex');
      const inputBlindingKey = Buffer.from(f.inputBlindingKey, 'hex');
      const outputBlindingKey = Buffer.from(f.outputBlindingKey, 'hex');
      const res = generate(
        proof,
        ephemeralInputTags,
        ephemeralOutputTag,
        f.inputIndex,
        inputBlindingKey,
        outputBlindingKey
      );
      assert.deepEqual(res.nInputs, f.expected.proof.nInputs);
      assert.deepEqual(res.data.toString('hex'), f.expected.proof.data);
      assert.deepEqual(
        res.usedInputs.toString('hex'),
        f.expected.proof.usedInputs
      );
    });
  });

  it('serialize proof', () => {
    fixtures.serialize.forEach((f) => {
      const proof = {
        nInputs: f.proof.nInputs,
        data: Buffer.from(f.proof.data, 'hex'),
        usedInputs: Buffer.from(f.proof.usedInputs, 'hex'),
      };
      assert.deepEqual(serialize(proof).toString('hex'), f.expected);
    });
  });

  it('verify proof', () => {
    fixtures.verify.forEach((f) => {
      const proof = {
        nInputs: f.proof.nInputs,
        data: Buffer.from(f.proof.data, 'hex'),
        usedInputs: Buffer.from(f.proof.usedInputs, 'hex'),
      };
      const ephemeralInputTags = f.ephemeralInputTags.map((v) =>
        Buffer.from(v, 'hex')
      );
      const ephemeralOutputTag = Buffer.from(f.ephemeralOutputTag, 'hex');
      assert.deepEqual(
        verify(proof, ephemeralInputTags, ephemeralOutputTag),
        f.expected
      );
    });
  });
});
