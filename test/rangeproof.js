const assert = require('assert');

const Module = require('../lib');
const { sign, info, verify, rewind } = Module.rangeproof;
const fixtures = require('./fixtures/rangeproof.json');

describe('range proof', () => {
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
      assert.deepEqual(proof.toString('hex'), f.expected);
    });
  });

  it('proof info', () => {
    fixtures.info.forEach((f) => {
      const proof = Buffer.from(f.proof, 'hex');
      const proofInfo = info(proof);
      assert.deepEqual(proofInfo.exp, f.expected.exp);
      assert.deepEqual(proofInfo.mantissa, f.expected.mantissa);
      assert.deepEqual(proofInfo.minValue, f.expected.minValue);
      assert.deepEqual(proofInfo.maxValue, f.expected.maxValue);
    });
  });

  it('proof verify', () => {
    fixtures.verify.forEach((f) => {
      const proof = Buffer.from(f.proof, 'hex');
      const commit = Buffer.from(f.commit, 'hex');
      const generator = Buffer.from(f.generator, 'hex');
      const extraCommit = Buffer.from(f.extraCommit, 'hex');
      assert.deepEqual(
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
      assert.deepEqual(res.value, f.expected.value);
      assert.deepEqual(res.minValue, f.expected.minValue);
      assert.deepEqual(res.maxValue, f.expected.maxValue);
      assert.deepEqual(res.message.toString('hex'), f.expected.message);
      assert.deepEqual(res.blindFactor.toString('hex'), f.expected.blindFactor);
    });
  });
});
