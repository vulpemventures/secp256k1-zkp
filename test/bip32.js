const { BIP32Factory } = require('bip32');
const secp256k1 = require('../lib');
const { expect } = require('chai');

describe('bitcoinjs BIP32Factory', () => {
  it('should instantiate an BIP32Interface', async () => {
    const ecc = (await secp256k1()).ecc;
    expect(() => BIP32Factory(ecc)).to.not.throw();
  });
});
