import anyTest, { TestInterface } from 'ava';

import { loadSecp256k1ZKP } from '../lib/cmodule';
import { ecc } from '../lib/ecc';
import { Secp256k1ZKP } from '../lib/interface';

import fixtures from './fixtures/ecc.json';

const fromHex = (hex: string) => Buffer.from(hex, 'hex');
const toHex = (buf: Uint8Array) => Buffer.from(buf).toString('hex');

const test = anyTest as TestInterface<Secp256k1ZKP['ecc']>;

test.before(async (t) => {
  const cModule = await loadSecp256k1ZKP();
  t.context = ecc(cModule);
});

test('privateNegate', (t) => {
  const { privateNegate } = t.context;

  fixtures.privateNegate.forEach((f) => {
    const key = fromHex(f.key);
    t.is(toHex(privateNegate(key)), f.expected);
  });
});

test('privateAdd', (t) => {
  const { privateAdd } = t.context;

  fixtures.privateAdd.forEach((f) => {
    const key = fromHex(f.key);
    const tweak = fromHex(f.tweak);
    const result = privateAdd(key, tweak);
    t.is(result ? toHex(result) : result, f.expected);
  });
});

test('privateSub', (t) => {
  const { privateSub } = t.context;

  fixtures.privateSub.valid.forEach((f) => {
    const key = fromHex(f.key);
    const tweak = fromHex(f.tweak);
    const result = privateSub(key, tweak);
    if (f.expected === null) {
      t.is(result, null);
      return;
    }

    if (result === null) {
      t.fail();
      return;
    }

    t.is(toHex(result), f.expected);
  });
  fixtures.privateSub.invalid.forEach((f) => {
    const key = fromHex(f.key);
    const tweak = fromHex(f.tweak);
    t.is(privateSub(key, tweak), null);
  });
});

test('privateMul', (t) => {
  const { privateMul } = t.context;

  fixtures.privateMul.forEach((f) => {
    const key = fromHex(f.key);
    const tweak = fromHex(f.tweak);
    t.is(toHex(privateMul(key, tweak)), f.expected);
  });
});

test('isPrivate', (t) => {
  const { isPrivate } = t.context;

  for (const f of fixtures.isPrivate) {
    const scalar = fromHex(f.scalar);
    t.is(isPrivate(scalar), f.expected);
  }
});

test('isPoint', (t) => {
  const { isPoint } = t.context;

  for (const f of fixtures.isPoint) {
    const point = fromHex(f.point);
    t.is(isPoint(point), f.expected);
  }
});

test('pointFromScalar', (t) => {
  const { pointFromScalar } = t.context;

  for (const f of fixtures.pointFromScalar) {
    const scalar = fromHex(f.scalar);
    if (f.expected === null) {
      t.is(pointFromScalar(scalar), null);
      continue;
    }

    const fromScalar = pointFromScalar(scalar);
    if (fromScalar === null) {
      t.fail();
      return;
    }
    const result = toHex(fromScalar);
    t.is(result, f.expected, `result: ${result} = expected: ${f.expected}`);
  }
});

test('pointCompress', (t) => {
  const { pointCompress } = t.context;

  for (const f of fixtures.pointCompress) {
    const point = Buffer.from(f.point, 'hex');
    const result = toHex(pointCompress(point));
    t.is(
      result,
      f.expected,
      `pointCompress(point): ${result} = expected: ${f.expected}`
    );
  }
});

test('xOnlyPointAddTweak', (t) => {
  const { xOnlyPointAddTweak } = t.context;

  fixtures.xOnlyPointAddTweak.forEach((f) => {
    const pubkey = fromHex(f.pubkey);
    const tweak = fromHex(f.tweak);

    const result = xOnlyPointAddTweak(pubkey, tweak);
    if (f.expected === null) {
      t.is(result, null);
    } else {
      if (result === null) {
        t.fail();
        return;
      }
      const { xOnlyPubkey, parity } = result;
      t.is(toHex(xOnlyPubkey), f.expected);
      t.is(parity, f.parity);
    }
  });
});

test('sign', (t) => {
  const { sign } = t.context;

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
    t.is(toHex(sign(message, scalar)), f.signature);
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

    t.is(toHex(extraEntropyUndefined), toHex(expectedSig));
    t.is(toHex(extraEntropy0), toHex(expectedExtraEntropy0));
    t.is(toHex(extraEntropy1), toHex(expectedExtraEntropy1));
    t.is(toHex(extraEntropyRand), toHex(expectedExtraEntropyRand));
    t.is(toHex(extraEntropyN), toHex(expectedExtraEntropyN));
    t.is(toHex(extraEntropyMax), toHex(expectedExtraEntropyMax));
  }
});

test('verify', (t) => {
  const { verify } = t.context;

  for (const f of fixtures.ecdsa.withoutExtraEntropy) {
    const publicKey = fromHex(f.publicKey);
    const publicKeyUncompressed = fromHex(f.publicKeyUncompressed);
    const message = fromHex(f.message);
    const signature = fromHex(f.signature);
    const corruptedSignature = fromHex(f.corruptedSignature);
    t.is(verify(message, publicKey, signature), true);
    t.is(verify(message, publicKey, corruptedSignature), false);
    t.is(verify(message, publicKeyUncompressed, signature), true);
    t.is(verify(message, publicKeyUncompressed, corruptedSignature), false);
  }
});

test('signSchnorr', (t) => {
  const { signSchnorr } = t.context;

  for (const {
    message,
    scalar,
    extraEntropy,
    signature,
    exception,
  } of fixtures.schnorr) {
    if (!scalar) continue;
    if (exception) {
      t.throws(() =>
        signSchnorr(fromHex(message), fromHex(scalar), fromHex(extraEntropy))
      );
      continue;
    }
    t.is(
      toHex(
        signSchnorr(fromHex(message), fromHex(scalar), fromHex(extraEntropy))
      ),
      signature
    );
  }
});

test('verifySchnorr', (t) => {
  const { verifySchnorr } = t.context;

  for (const {
    message,
    publicKey,
    signature,
    exception,
    valid,
  } of fixtures.schnorr) {
    if (exception) continue; // do not verify invalid BIP340 test vectors
    t.is(
      verifySchnorr(fromHex(message), fromHex(publicKey), fromHex(signature)),
      valid
    );
  }
});

test('pointAddScalar', (t) => {
  const { pointAddScalar, pointCompress } = t.context;

  for (const f of fixtures.pointAddScalar) {
    const p = fromHex(f.P);
    const d = fromHex(f.d);
    const expected = f.expected;
    let description = `${f.P} + ${f.d} = ${f.expected ? f.expected : null}`;
    if (f.description) description += ` (${f.description})`;
    const result = pointAddScalar(p, d);
    t.is(result ? toHex(result) : null, expected, description);
    if (result !== null && expected !== null) {
      const compressed = pointAddScalar(p, d, true);
      if (compressed === null) {
        t.fail();
        return;
      }
      t.is(
        toHex(compressed),
        toHex(pointCompress(fromHex(expected), true)),
        description + ' (compressed)'
      );

      const uncompressed = pointAddScalar(p, d, false);
      if (uncompressed === null) {
        t.fail();
        return;
      }
      t.is(
        toHex(uncompressed),
        toHex(pointCompress(fromHex(expected), false)),
        description + ' (uncompressed)'
      );
    }
  }
});
