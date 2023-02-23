const chai = require('chai');
const assert = chai.assert;
const secp256k1 = require('../lib');
const fixtures = require('./fixtures/ecdsa.json');

const fromHex = hex => Buffer.from(hex, 'hex');
const toHex = buf => Buffer.from(buf).toString('hex');

const buf1 = fromHex(
  "0000000000000000000000000000000000000000000000000000000000000000"
);
const buf2 = fromHex(
  "0000000000000000000000000000000000000000000000000000000000000001"
);
const buf3 = fromHex(
  "6e723d3fd94ed5d2b6bdd4f123364b0f3ca52af829988a63f8afe91d29db1c33"
);
const buf4 = fromHex(
  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
);
const buf5 = fromHex(
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
);

function corrupt(x) {
  function randomUInt8() {
    return Math.floor(Math.random() * 0xff);
  }

  x = Uint8Array.from(x);
  const mask = 1 << randomUInt8() % 8;
  x[randomUInt8() % 32] ^= mask;
  return x;
}

describe('ECDSA', () => {
  let sign;
  let verify;
  let pointFromScalar;

  before(async () => {
    const lib = await secp256k1();
    sign = lib.signECDSA;
    verify = lib.verifyECDSA;
    pointFromScalar = lib.pointFromScalar;
  });

  describe('sign', () => {
    for (const f of fixtures.valid) {
      it(`should return signature ${f.signature} for message ${f.m}`, () => {
        const d = new Uint8Array(Buffer.from(f.d, 'hex'));
        const m = new Uint8Array(Buffer.from(f.m, 'hex'));

        assert.strictEqual(
          Buffer.from(sign(m, d)).toString('hex'),
          f.signature,
          `sign(${f.m}, ...) == ${f.signature}`
        );
      });
    }


    for (const f of fixtures.extraEntropy) {
      it(`should return signature ${f.signature} for message ${f.m}`, () => {
        const d = fromHex(f.d);
        const m = fromHex(f.m);
        const expectedSig = fromHex(f.signature);
        const expectedExtraEntropy0 = fromHex(f.extraEntropy0);
        const expectedExtraEntropy1 = fromHex(f.extraEntropy1);
        const expectedExtraEntropyRand = fromHex(f.extraEntropyRand);
        const expectedExtraEntropyN = fromHex(f.extraEntropyN);
        const expectedExtraEntropyMax = fromHex(f.extraEntropyMax);

        const extraEntropyUndefined = sign(m, d);
        const extraEntropy0 = sign(m, d, buf1);
        const extraEntropy1 = sign(m, d, buf2);
        const extraEntropyRand = sign(m, d, buf3);
        const extraEntropyN = sign(m, d, buf4);
        const extraEntropyMax = sign(m, d, buf5);

        assert.strictEqual(
          Buffer.from(extraEntropyUndefined).toString('hex'),
          Buffer.from(expectedSig).toString('hex'),
          `sign(${f.m}, ..., undefined) == ${f.signature}`
        );
        assert.strictEqual(
          Buffer.from(extraEntropy0).toString('hex'),
          Buffer.from(expectedExtraEntropy0).toString('hex'),
          `sign(${f.m}, ..., 0) == ${f.signature}`
        );
        assert.strictEqual(
          Buffer.from(extraEntropy1).toString('hex'),
          Buffer.from(expectedExtraEntropy1).toString('hex'),
          `sign(${f.m}, ..., 1) == ${f.signature}`
        );
        assert.strictEqual(
          Buffer.from(extraEntropyRand).toString('hex'),
          Buffer.from(expectedExtraEntropyRand).toString('hex'),
          `sign(${f.m}, ..., rand) == ${f.signature}`
        );
        assert.strictEqual(
          Buffer.from(extraEntropyN).toString('hex'),
          Buffer.from(expectedExtraEntropyN).toString('hex'),
          `sign(${f.m}, ..., n) == ${f.signature}`
        );
        assert.strictEqual(
          Buffer.from(extraEntropyMax).toString('hex'),
          Buffer.from(expectedExtraEntropyMax).toString('hex'),
          `sign(${f.m}, ..., max256) == ${f.signature}`
        );
      });
    }

    for (const f of fixtures.invalid.sign) {
      it(`should throw for message ${f.m}`, () => {
        const d = fromHex(f.d);
        const m = fromHex(f.m);

        assert.throws(
          () => {
            sign(m, d);
          },
        );
      });
    }
  });

  describe('verify', () => {
    for (const f of fixtures.valid) {
      it(`should verify signature ${f.signature} for message ${f.m}`, () => {
        const d = fromHex(f.d);
        const Q = pointFromScalar(d, true);
        const Qu = pointFromScalar(d, false);
        const m = fromHex(f.m);
        const signature = fromHex(f.signature);
        const bad = corrupt(signature);

        assert.strictEqual(
          verify(m, Q, signature),
          true,
          `verify(${f.signature}) is OK`
        );
        assert.strictEqual(
          verify(m, Q, bad),
          false,
          `verify(${toHex(bad)}) is rejected`
        );
        assert.strictEqual(
          verify(m, Qu, signature),
          true,
          `verify(${f.signature}) is OK`
        );
        assert.strictEqual(
          verify(m, Qu, bad),
          false,
          `verify(${toHex(bad)}) is rejected`
        );
      });
    }

    for (const f of fixtures.invalid.verify) {
      it(`should throw for signature ${f.signature} and point: ${f.Q} (${f.exception})`, () => {
        const Q = fromHex(f.Q);
        const m = fromHex(f.m);
        const signature = fromHex(f.signature);

        if (f.exception) {
          assert.throws(
            () => {
              verify(m, Q, signature);
            },
          );
        } else {
          assert.strictEqual(
            verify(m, Q, signature, f.strict),
            false,
            `verify(${f.signature}) is rejected`
          );
          if (f.strict === true) {
            assert.strictEqual(
              verify(m, Q, signature, false),
              true,
              `verify(${f.signature}) is OK without strict`
            );
          }
        }
      });
    }
  });
});
