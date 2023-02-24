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
      const valueCommitment = new Uint8Array(
        Buffer.from(f.valueCommitment, 'hex')
      );
      const assetCommitment = new Uint8Array(
        Buffer.from(f.assetCommitment, 'hex')
      );
      const valueBlinder = new Uint8Array(Buffer.from(f.valueBlinder, 'hex'));
      const nonce = new Uint8Array(Buffer.from(f.valueCommitment, 'hex'));
      const message = new Uint8Array(Buffer.from(f.message, 'hex'));
      const extraCommitment = new Uint8Array(
        Buffer.from(f.extraCommitment, 'hex')
      );
      const proof = sign(
        f.value,
        valueCommitment,
        assetCommitment,
        valueBlinder,
        nonce,
        f.minValue,
        '0',
        '0',
        message,
        extraCommitment
      );
      assert.deepStrictEqual(Buffer.from(proof).toString('hex'), f.expected);
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
      const valueCommitment = Buffer.from(f.valueCommitment, 'hex');
      const assetCommitment = Buffer.from(f.assetCommitment, 'hex');
      const extraCommitment = Buffer.from(f.extraCommitment, 'hex');
      assert.deepStrictEqual(
        verify(proof, valueCommitment, assetCommitment, extraCommitment),
        f.expected
      );
    });
  });

  it('range proof rewind', () => {
    fixtures.rewind.forEach((f) => {
      const proof = new Uint8Array(Buffer.from(f.proof, 'hex'));
      const valueCommitment = new Uint8Array(
        Buffer.from(f.valueCommitment, 'hex')
      );
      const assetCommitment = new Uint8Array(
        Buffer.from(f.assetCommitment, 'hex')
      );
      const extraCommitment = new Uint8Array(
        Buffer.from(f.extraCommitment, 'hex')
      );
      const nonce = new Uint8Array(Buffer.from(f.valueCommitment, 'hex'));
      const res = rewind(
        proof,
        valueCommitment,
        assetCommitment,
        nonce,
        extraCommitment
      );
      // assert.deepStrictEqual(res.value, f.expected.value);
      // assert.deepStrictEqual(res.minValue, f.expected.minValue);
      // assert.deepStrictEqual(res.maxValue, f.expected.maxValue);
      // assert.deepStrictEqual(
      //   Buffer.from(res.message).toString('hex'),
      //   f.expected.message
      // );
      assert.deepStrictEqual(
        Buffer.from(res.blinder).toString('hex'),
        f.expected.blinder
      );
    });
  });
});
