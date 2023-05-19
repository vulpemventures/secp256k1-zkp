const chai = require('chai');
const assert = chai.assert;

const secp256k1 = require('../lib');
const fixtures = require('./fixtures/ecc.json');

const fromHex = (hex) => Buffer.from(hex, 'hex');
const toHex = (buf) => Buffer.from(buf).toString('hex');

describe('ecc', () => {
  let privateNegate,
    privateAdd,
    privateSub,
    privateMul,
    sign,
    verify,
    signSchnorr,
    verifySchnorr,
    isPrivate,
    isPoint,
    pointFromScalar,
    pointCompress,
    xOnlyPointAddTweak;

  before(async () => {
    ({
      privateNegate,
      privateAdd,
      privateSub,
      privateMul,
      sign,
      verify,
      isPrivate,
      signSchnorr,
      verifySchnorr,
      isPoint,
      pointFromScalar,
      pointCompress,
      xOnlyPointAddTweak,
    } = (await secp256k1()).ecc);
  });

  it('privateNegate', () => {
    fixtures.privateNegate.forEach((f) => {
      const key = fromHex(f.key);
      assert.deepStrictEqual(toHex(privateNegate(key)), f.expected);
    });
  });

  it('privateAdd', () => {
    fixtures.privateAdd.forEach((f) => {
      const key = fromHex(f.key);
      const tweak = fromHex(f.tweak);
      assert.deepStrictEqual(toHex(privateAdd(key, tweak)), f.expected);
    });
  });

  it('privateSub', () => {
    fixtures.privateSub.valid.forEach((f) => {
      const key = fromHex(f.key);
      const tweak = fromHex(f.tweak);
      assert.deepStrictEqual(toHex(privateSub(key, tweak)), f.expected);
    });
    fixtures.privateSub.invalid.forEach((f) => {
      const key = fromHex(f.key);
      const tweak = fromHex(f.tweak);
      assert.throws(() => privateSub(key, tweak));
    });
  });

  it('privateMul', () => {
    fixtures.privateMul.forEach((f) => {
      const key = fromHex(f.key);
      const tweak = fromHex(f.tweak);
      assert.deepStrictEqual(toHex(privateMul(key, tweak)), f.expected);
    });
  });

  it('isPrivate', () => {
    for (const f of fixtures.isPrivate) {
      const scalar = fromHex(f.scalar);
      assert.deepStrictEqual(isPrivate(scalar), f.expected);
    }
  });

  it('isPoint', () => {
    for (const f of fixtures.isPoint) {
      const point = fromHex(f.point);
      assert.deepStrictEqual(isPoint(point), f.expected);
    }
  });

  it('pointFromScalar', () => {
    for (const f of fixtures.pointFromScalar) {
      const scalar = fromHex(f.scalar);
      assert.strictEqual(toHex(pointFromScalar(scalar)), f.expected);
    }
  });

  it('pointCompress', () => {
    for (const f of fixtures.pointCompress) {
      const point = Buffer.from(f.point, 'hex');
      assert.strictEqual(toHex(pointCompress(point)), f.expected);
    }
  });

  it('xOnlyPointAddTweak', () => {
    fixtures.xOnlyPointAddTweak.forEach((f) => {
      const pubkey = fromHex(f.pubkey);
      const tweak = fromHex(f.tweak);

      const result = xOnlyPointAddTweak(pubkey, tweak);
      if (f.expected === null) {
        assert.strictEqual(result, null);
      } else {
        const { xOnlyPubkey, parity } = result;
        assert.deepStrictEqual(toHex(xOnlyPubkey), f.expected);
        assert.deepStrictEqual(parity, f.parity);
      }
    });
  });

  it('sign', () => {
    const buf1 = fromHex(
      '0000000000000000000000000000000000000000000000000000000000000000'
    );
    const buf2 = fromHex(
      '0000000000000000000000000000000000000000000000000000000000000001'
    );
    const buf3 = fromHex(
      '6e723d3fd94ed5d2b6bdd4f123364b0f3ca52af829988a63f8afe91d29db1c33'
    );
    const buf4 = fromHex(
      'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
    );
    const buf5 = fromHex(
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    );

    for (const f of fixtures.ecdsa.withoutExtraEntropy) {
      const scalar = fromHex(f.scalar);
      const message = fromHex(f.message);
      assert.deepStrictEqual(toHex(sign(message, scalar)), f.signature);
    }

    for (const f of fixtures.ecdsa.withExtraEntropy) {
      const scalar = fromHex(f.scalar);
      const message = fromHex(f.message);
      const expectedSig = fromHex(f.signature);
      const expectedExtraEntropy0 = fromHex(f.extraEntropy0);
      const expectedExtraEntropy1 = fromHex(f.extraEntropy1);
      const expectedExtraEntropyRand = fromHex(f.extraEntropyRand);
      const expectedExtraEntropyN = fromHex(f.extraEntropyN);
      const expectedExtraEntropyMax = fromHex(f.extraEntropyMax);

      const extraEntropyUndefined = sign(message, scalar);
      const extraEntropy0 = sign(message, scalar, buf1);
      const extraEntropy1 = sign(message, scalar, buf2);
      const extraEntropyRand = sign(message, scalar, buf3);
      const extraEntropyN = sign(message, scalar, buf4);
      const extraEntropyMax = sign(message, scalar, buf5);

      assert.strictEqual(toHex(extraEntropyUndefined), toHex(expectedSig));
      assert.strictEqual(toHex(extraEntropy0), toHex(expectedExtraEntropy0));
      assert.strictEqual(toHex(extraEntropy1), toHex(expectedExtraEntropy1));
      assert.strictEqual(
        toHex(extraEntropyRand),
        toHex(expectedExtraEntropyRand)
      );
      assert.strictEqual(toHex(extraEntropyN), toHex(expectedExtraEntropyN));
      assert.strictEqual(
        toHex(extraEntropyMax),
        toHex(expectedExtraEntropyMax)
      );
    }
  });

  it('verify', () => {
    for (const f of fixtures.ecdsa.withoutExtraEntropy) {
      const publicKey = fromHex(f.publicKey);
      const publicKeyUncompressed = fromHex(f.publicKeyUncompressed);
      const message = fromHex(f.message);
      const signature = fromHex(f.signature);
      const corruptedSignature = fromHex(f.corruptedSignature);
      assert.deepStrictEqual(verify(message, publicKey, signature), true);
      assert.deepStrictEqual(
        verify(message, publicKey, corruptedSignature),
        false
      );
      assert.deepStrictEqual(
        verify(message, publicKeyUncompressed, signature),
        true
      );
      assert.deepStrictEqual(
        verify(message, publicKeyUncompressed, corruptedSignature),
        false
      );
    }
  });

  it('signSchnorr', () => {
    for (const {
      message,
      scalar,
      extraEntropy,
      signature,
      exception,
    } of fixtures.schnorr) {
      if (!scalar) continue;
      if (exception) {
        assert.throws(() =>
          signSchnorr(fromHex(message), fromHex(scalar), fromHex(extraEntropy))
        );
        continue;
      }
      assert.deepStrictEqual(
        toHex(
          signSchnorr(fromHex(message), fromHex(scalar), fromHex(extraEntropy))
        ),
        signature
      );
    }
  });

  it('verifySchnorr', () => {
    for (const {
      message,
      publicKey,
      signature,
      exception,
      valid,
    } of fixtures.schnorr) {
      if (exception) continue; // do not verify invalid BIP340 test vectors
      assert.deepStrictEqual(
        verifySchnorr(fromHex(message), fromHex(publicKey), fromHex(signature)),
        valid
      );
    }
  });
});
