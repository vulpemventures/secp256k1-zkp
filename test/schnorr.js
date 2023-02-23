const chai = require('chai');
const assert = chai.assert;
const secp256k1 = require('../lib');
const fixtures = require('./fixtures/schnorr.json');

describe('Schnorr', () => {
  let signSchnorr;
  let verifySchnorr;

  before(async () => {
    const lib = await secp256k1();
    isPrivate = lib.isPrivate;
  });

  describe('isPoint', () => {
    for (const f of fixtures.valid.isPrivate) {
      it(`should return true for ${f.d}`, async () => {
        const point = Buffer.from(f.d, 'hex');
        assert.strictEqual(isPrivate(point), f.expected);
      });
    }
  });
});
