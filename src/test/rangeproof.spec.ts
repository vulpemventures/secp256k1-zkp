import anyTest, { TestInterface } from 'ava';

import { loadSecp256k1ZKP } from '../lib/cmodule';
import { Secp256k1ZKP } from '../lib/interface';
import { rangeproof } from '../lib/rangeproof';

import fixtures from './fixtures/rangeproof.json';

const test = anyTest as TestInterface<Secp256k1ZKP['rangeproof']>;

test.before(async (t) => {
  const cModule = await loadSecp256k1ZKP();
  t.context = rangeproof(cModule);
});

test('proof sign', (t) => {
  const { sign } = t.context;

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
    t.is(Buffer.from(proof).toString('hex'), f.expected);
  });
});

test('proof info', (t) => {
  const { info } = t.context;

  fixtures.info.forEach((f) => {
    const proof = Buffer.from(f.proof, 'hex');
    const proofInfo = info(proof);
    t.is(proofInfo.exp, f.expected.exp);
    t.is(proofInfo.mantissa, f.expected.mantissa);
    t.is(proofInfo.minValue, f.expected.minValue);
    t.is(proofInfo.maxValue, f.expected.maxValue);
  });
});

test('proof verify', (t) => {
  const { verify } = t.context;

  fixtures.verify.forEach((f) => {
    const proof = Buffer.from(f.proof, 'hex');
    const valueCommitment = Buffer.from(f.valueCommitment, 'hex');
    const assetCommitment = Buffer.from(f.assetCommitment, 'hex');
    const extraCommitment = Buffer.from(f.extraCommitment, 'hex');
    t.is(
      verify(proof, valueCommitment, assetCommitment, extraCommitment),
      f.expected
    );
  });
});

test('range proof rewind', (t) => {
  const { rewind } = t.context;

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
    t.is(res.value, f.expected.value);
    t.is(res.minValue, f.expected.minValue);
    t.is(res.maxValue, f.expected.maxValue);
    t.is(Buffer.from(res.message).toString('hex'), f.expected.message);
    t.is(Buffer.from(res.blinder).toString('hex'), f.expected.blinder);
  });
});
