import anyTest, { TestInterface } from 'ava';
import { BIP32Factory } from 'bip32';
import { ECPairFactory } from 'ecpair';

import secp256k1 from '../index';
import { Secp256k1ZKP } from '../lib/interface';

const test = anyTest as TestInterface<Secp256k1ZKP>;

test.before(async (t) => {
  t.context = await secp256k1();
});

test('bitcoinjs-lib BIP32Factory', (t) => {
  t.notThrows(() => BIP32Factory(t.context.ecc));
});

test('bitcoinjs-lib ECPairFactory', (t) => {
  t.notThrows(() => ECPairFactory(t.context.ecc));
});
