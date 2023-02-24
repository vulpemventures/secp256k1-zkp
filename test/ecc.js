const chai = require('chai');
const assert = chai.assert;

const secp256k1 = require('../lib');
const fixtures = require('./fixtures/ecc.json');

const fromHex = (hex) => Buffer.from(hex, 'hex');
const toHex = (buf) => Buffer.from(buf).toString('hex');

describe('ecc', () => {
  let privateNegate,
    privateAdd,
    privateMul,
    sign,
    verify,
    signSchnorr,
    verifySchnorr,
    isPrivate,
    isPoint,
    pointFromScalar,
    pointCompress;

  before(async () => {
    ({
      privateNegate,
      privateAdd,
      privateMul,
      sign,
      verify,
      isPrivate,
      signSchnorr,
      verifySchnorr,
      isPoint,
      pointFromScalar,
      pointCompress,
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

  it('privateMul', () => {
    fixtures.privateMul.forEach((f) => {
      const key = fromHex(f.key);
      const tweak = fromHex(f.tweak);
      assert.deepStrictEqual(toHex(privateMul(key, tweak)), f.expected);
    });
  });

  it('isPrivate', () => {
    for (const f of fixtures.isPrivate) {
      const point = fromHex(f.d);
      assert.deepStrictEqual(isPrivate(point), f.expected);
    }
  });

  it('isPoint', () => {
    for (const f of fixtures.isPoint) {
      const point = fromHex(f.P);
      assert.deepStrictEqual(isPoint(point), f.expected);
    }
  });

  it('pointFromScalar', () => {
    for (const f of fixtures.pointFromScalar) {
      const d = fromHex(f.d);
      const expected = fromHex(f.expected);
      let description = `${f.d} * G = ${f.expected}`;
      if (f.description) description += ` (${f.description})`;
      assert.strictEqual(toHex(pointFromScalar(d)), f.expected, description);
      if (f.expected === null) return;
      assert.strictEqual(
        toHex(pointFromScalar(d, true)),
        toHex(pointCompress(expected, true)),
        description
      );
      assert.strictEqual(
        toHex(pointFromScalar(d, false)),
        toHex(pointCompress(expected, false)),
        description
      );
    }
  });

  it('pointCompress', () => {
    for (const f of fixtures.pointCompress) {
      const p = Buffer.from(f.P, 'hex');
      if (f.noarg) {
        assert.strictEqual(toHex(pointCompress(p)), f.expected);
      } else {
        assert.strictEqual(toHex(pointCompress(p, f.compress)), f.expected);
      }
    }
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
      const d = fromHex(f.d, 'hex');
      const m = fromHex(f.m, 'hex');
      assert.deepStrictEqual(
        toHex(sign(m, d)),
        f.signature,
        `sign(${f.m}, ...) == ${f.signature}`
      );
    }

    for (const f of fixtures.ecdsa.withExtraEntropy) {
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
        toHex(extraEntropyUndefined),
        toHex(expectedSig),
        `sign(${f.m}, ..., undefined) == ${f.signature}`
      );
      assert.strictEqual(
        toHex(extraEntropy0),
        toHex(expectedExtraEntropy0),
        `sign(${f.m}, ..., 0) == ${f.signature}`
      );
      assert.strictEqual(
        toHex(extraEntropy1),
        toHex(expectedExtraEntropy1),
        `sign(${f.m}, ..., 1) == ${f.signature}`
      );
      assert.strictEqual(
        toHex(extraEntropyRand),
        toHex(expectedExtraEntropyRand),
        `sign(${f.m}, ..., rand) == ${f.signature}`
      );
      assert.strictEqual(
        toHex(extraEntropyN),
        toHex(expectedExtraEntropyN),
        `sign(${f.m}, ..., n) == ${f.signature}`
      );
      assert.strictEqual(
        toHex(extraEntropyMax),
        toHex(expectedExtraEntropyMax),
        `sign(${f.m}, ..., max256) == ${f.signature}`
      );
    }
  });

  it('verify', () => {
    for (const f of fixtures.ecdsa.withoutExtraEntropy) {
      const Q = fromHex(f.Q);
      const Qu = fromHex(f.Qu);
      const m = fromHex(f.m);
      const signature = fromHex(f.signature);
      const corruptedSignature = fromHex(f.corruptedSignature);

      assert.deepStrictEqual(
        verify(m, Q, signature),
        true,
        `verify(${f.signature}) is OK`
      );
      assert.deepStrictEqual(
        verify(m, Q, corruptedSignature),
        false,
        `verify(${toHex(corruptedSignature)}) is rejected`
      );
      assert.deepStrictEqual(
        verify(m, Qu, signature),
        true,
        `verify(${f.signature}) is OK`
      );
      assert.deepStrictEqual(
        verify(m, Qu, corruptedSignature),
        false,
        `verify(${toHex(corruptedSignature)}) is rejected`
      );
    }
  });

  it('signSchnorr', () => {
    for (const {
      m,
      d,
      e,
      s,
      comment,
      exception,
    } of fixtures.bip340testvectors) {
      if (!d) continue; // skip test vectors without private key (only Q for verify case)
      if (exception) {
        assert.throws(
          () => signSchnorr(fromHex(m), fromHex(d), fromHex(e)),
          new RegExp(exception),
          comment || `signSchnorr(${m}, ${d}, ${e}) throws ${exception}`
        );
        continue;
      }
      assert.deepStrictEqual(
        toHex(signSchnorr(fromHex(m), fromHex(d), fromHex(e))),
        s,
        comment || `signSchnorr(${m}, ${d}, ${e}) == ${s}`
      );
    }
  });

  it('verifySchnorr', () => {
    for (const {
      m,
      Q,
      e,
      s,
      v,
      comment,
      exception,
    } of fixtures.bip340testvectors) {
      if (exception) continue; // do not verify invalid BIP340 test vectors
      assert.deepStrictEqual(
        verifySchnorr(fromHex(m), fromHex(Q), fromHex(s)),
        v,
        comment || `verifySchnorr(${m}, ${Q}, ${e}, ${s}) == ${v}`
      );
    }
  });
});