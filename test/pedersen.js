const chai = require('chai');
const assert = chai.assert;

const secp256k1 = require('../lib');
const fixtures = require('./fixtures/pedersen.json');

describe('pedersen', () => {
  let commitment, blindGeneratorBlindSum;

  before(async () => {
    ({ commitment, blindGeneratorBlindSum } = (await secp256k1()).pedersen);
  });

  it('commitment', () => {
    fixtures.commitment.forEach((f) => {
      const blinder = new Uint8Array(Buffer.from(f.blinder, 'hex'));
      const generator = new Uint8Array(Buffer.from(f.generator, 'hex'));
      assert.deepStrictEqual(
        Buffer.from(commitment(f.value, generator, blinder)).toString('hex'),
        f.expected
      );
    });
  });

  it('blind generator blind sum', () => {
    fixtures.blindGeneratorBlindSum.forEach((f) => {
      const assetBlinders = f.assetBlinders.map((b) => Buffer.from(b, 'hex'));
      const valueBlinders = f.valueBlinders.map((b) => Buffer.from(b, 'hex'));
      assert.equal(
        Buffer.from(
          blindGeneratorBlindSum(
            f.values,
            valueBlinders,
            assetBlinders,
            f.nInputs
          )
        ).toString('hex'),
        f.expected
      );
    });
  });
});
