const assert = require('assert');

const secp256k1 = require('../lib');
const fixtures = require('./fixtures/ecdh.json');

describe('ecdh', () => {
  it('ecdh', async () => {
    const { ecdh } = await secp256k1();

    fixtures.ecdh.forEach((f) => {
      const pubkey = Buffer.from(f.pubkey, 'hex');
      const scalar = Buffer.from(f.scalar, 'hex');
      assert.strictEqual(ecdh(pubkey, scalar).toString('hex'), f.expected);
    });
  });
});
