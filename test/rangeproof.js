const chai = require('chai');
const assert = chai.assert;

const secp256k1 = require('../lib');
const fixtures = require('./fixtures/rangeproof.json');

describe('range proof', () => {
  let sign, info, verify, rewind;

  before(async () => {
    ({ sign, info, verify, rewind } = (await secp256k1()).rangeproof);
  });

  it('proof sign', () => {
    fixtures.sign.forEach((f) => {
      const commit = Buffer.from(f.commit, 'hex');
      const nonce = Buffer.from(f.commit, 'hex');
      const blind = Buffer.from(f.blind, 'hex');
      const generator = Buffer.from(f.generator, 'hex');
      const message = Buffer.from(f.message, 'hex');
      const extraCommit = Buffer.from(f.extraCommit, 'hex');
      const proof = sign(
        commit,
        blind,
        nonce,
        f.value,
        generator,
        f.minValue,
        0,
        0,
        message,
        extraCommit
      );
      assert.deepStrictEqual(proof.toString('hex'), f.expected);
    });
  });

  it('proof info', () => {
    fixtures.info.forEach((f) => {
      const proof = Buffer.from(f.proof, 'hex');
      const proofInfo = info(proof);
      assert.deepStrictEqual(proofInfo.exp, f.expected.exp);
      assert.deepStrictEqual(proofInfo.mantissa, f.expected.mantissa);
      assert.deepStrictEqual(proofInfo.minValue, f.expected.minValue);
      assert.deepStrictEqual(proofInfo.maxValue, f.expected.maxValue);
    });
  });

  it('proof verify', () => {
    fixtures.verify.forEach((f) => {
      const proof = Buffer.from(f.proof, 'hex');
      const commit = Buffer.from(f.commit, 'hex');
      const generator = Buffer.from(f.generator, 'hex');
      const extraCommit = Buffer.from(f.extraCommit, 'hex');
      assert.deepStrictEqual(
        verify(commit, proof, generator, extraCommit),
        f.expected
      );
    });
  });

  it('range proof rewind', () => {
    fixtures.rewind.forEach((f) => {
      const proof = Buffer.from(f.proof, 'hex');
      const commit = Buffer.from(f.commit, 'hex');
      const generator = Buffer.from(f.generator, 'hex');
      const extraCommit = Buffer.from(f.extraCommit, 'hex');
      const res = rewind(commit, proof, commit, generator, extraCommit);
      assert.deepStrictEqual(res.value, f.expected.value);
      assert.deepStrictEqual(res.minValue, f.expected.minValue);
      assert.deepStrictEqual(res.maxValue, f.expected.maxValue);
      assert.deepStrictEqual(res.message.toString('hex'), f.expected.message);
      assert.deepStrictEqual(
        res.blindFactor.toString('hex'),
        f.expected.blindFactor
      );
    });
  });
});
