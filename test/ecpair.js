const { ECPairFactory } = require('ecpair');
const secp256k1 = require('../lib');
const { expect } = require('chai');

describe('bitcoinjs ECPairFactory', () => {
  it('should instantiate an ECPairInterface', async () => {
    const ecc = (await secp256k1()).ecc;
    expect(() => ECPairFactory(ecc)).to.not.throw();
  });
});
