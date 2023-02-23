const chai = require('chai');
const assert = chai.assert;

const secp256k1 = require('../lib');
const fixtures = require('./fixtures/ec.json');

describe('ec', () => {
  let prvkeyNegate, prvkeyTweakAdd, prvkeyTweakMul;

  before(async () => {
    ({ prvkeyNegate, prvkeyTweakAdd, prvkeyTweakMul } = (await secp256k1()).ec);
  });

  it('prvkey_negate', async () => {
    const { ec } = await secp256k1();
    fixtures.prvkeyNegate.forEach((f) => {
      const key = Buffer.from(f.key, 'hex');
      const res = prvkeyNegate(key);
      assert.deepStrictEqual(
        Buffer.from(prvkeyNegate(key)).toString('hex'),
        f.expected
      );
    });
  });

  it('prvkey_tweak_add', async () => {
    const { ec } = await secp256k1();
    fixtures.prvkeyTweakAdd.forEach((f) => {
      const key = Buffer.from(f.key, 'hex');
      const tweak = Buffer.from(f.tweak, 'hex');
      assert.deepStrictEqual(
        Buffer.from(prvkeyTweakAdd(key, tweak)).toString('hex'),
        f.expected
      );
    });
  });

  it('prvkey_tweak_mul', async () => {
    const { ec } = await secp256k1();
    fixtures.prvkeyTweakMul.forEach((f) => {
      const key = Buffer.from(f.key, 'hex');
      const tweak = Buffer.from(f.tweak, 'hex');
      assert.deepStrictEqual(
        Buffer.from(prvkeyTweakMul(key, tweak)).toString('hex'),
        f.expected
      );
    });
  });
});
