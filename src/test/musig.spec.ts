import { randomBytes } from 'crypto';

import anyTest, { TestInterface } from 'ava';
import ECPairFactory, { ECPairAPI } from 'ecpair';

import { loadSecp256k1ZKP } from '../lib/cmodule';
import { ecc } from '../lib/ecc';
import { Secp256k1ZKP } from '../lib/interface';
import { musig } from '../lib/musig';

import fixtures from './fixtures/musig.json';

const fromHex = (hex: string) => Buffer.from(hex, 'hex');
const uintToString = (arr: Uint8Array) => Buffer.from(arr).toString('hex');

const test = anyTest as TestInterface<
  Secp256k1ZKP['musig'] & { ecc: Secp256k1ZKP['ecc']; ec: ECPairAPI }
>;

test.before(async (t) => {
  const cModule = await loadSecp256k1ZKP();
  const eccModule = ecc(cModule);
  t.context = {
    ...musig(cModule),
    ecc: eccModule,
    ec: ECPairFactory(eccModule),
  };
});

test('pubkeyAgg', (t) => {
  const { pubkeyAgg } = t.context;

  fixtures.musigPubkeyAgg.forEach((f) => {
    const publicKeys = f.publicKeys.map((key) => fromHex(key));
    const res = pubkeyAgg(publicKeys);

    t.is(res.aggPubkey.length, 32);
    t.is(uintToString(res.aggPubkey), f.aggregatedPubkey);
    t.is(res.keyaggCache.length, 197);
    t.is(uintToString(res.keyaggCache), f.keyaggCache);
  });
});

test('nonceGen', (t) => {
  const { nonceGen } = t.context;

  fixtures.musigNonceGen.forEach((f) => {
    const pubKey = fromHex(f.publicKey);
    const session = fromHex(f.sessionId);
    const nonces = nonceGen(session, pubKey);

    t.is(nonces.secNonce.length, 132);
    t.is(uintToString(nonces.secNonce), f.secnonce);
    t.is(nonces.pubNonce.length, 66);
    t.is(uintToString(nonces.pubNonce), f.pubnonce);
  });
});

test('nonceAgg', (t) => {
  const { nonceAgg } = t.context;

  fixtures.musigNonceAgg.forEach((f) => {
    const nonces = f.pubnonces.map((nonce) => fromHex(nonce));
    const aggNonce = nonceAgg(nonces);

    t.is(aggNonce.length, 66);
    t.is(uintToString(aggNonce), f.aggnonce);
  });
});

test('nonceProcess', (t) => {
  const { nonceProcess } = t.context;

  fixtures.musigNonceProcess.forEach((f) => {
    const session = nonceProcess(
      fromHex(f.aggnonce),
      fromHex(f.message),
      fromHex(f.keyaggCache)
    );

    t.is(session.length, 133);
    t.is(uintToString(session), f.session);
  });
});

test('partialSign', (t) => {
  const musig = t.context;

  fixtures.musigPartialSign.forEach((f) => {
    const publicKeys = f.publicKeys.map(fromHex);
    const signer = musig.ec.fromPrivateKey(fromHex(f.privateKey));
    publicKeys[f.index] = signer.publicKey;

    const pubNonces: Uint8Array[] = f.pubnonces.map(fromHex);
    const signerNonces = musig.nonceGen(fromHex(f.sessionId), signer.publicKey);
    pubNonces[f.index] = signerNonces.pubNonce;

    const pubkeyAgg = musig.pubkeyAgg(publicKeys);
    const nonceAgg = musig.nonceAgg(pubNonces);
    const session = musig.nonceProcess(
      nonceAgg,
      fromHex(f.msg),
      pubkeyAgg.keyaggCache
    );

    const partialSig = musig.partialSign(
      signerNonces.secNonce,
      fromHex(f.privateKey),
      pubkeyAgg.keyaggCache,
      session
    );
    t.is(partialSig.length, 32);
    t.is(uintToString(partialSig), f.partialSig);
  });
});

test('partialVerify', (t) => {
  const musig = t.context;

  fixtures.musigPatialVerify.forEach((f) => {
    const publicKeys = f.publicKeys.map(fromHex);
    const pubkeyAgg = musig.pubkeyAgg(publicKeys);

    const pubNonces = f.pubnonces.map(fromHex);
    const nonceAgg = musig.nonceAgg(pubNonces);

    const session = musig.nonceProcess(
      nonceAgg,
      fromHex(f.msg),
      pubkeyAgg.keyaggCache
    );

    t.is(
      musig.partialVerify(
        fromHex(f.partialSig),
        pubNonces[f.index],
        publicKeys[f.index],
        pubkeyAgg.keyaggCache,
        session
      ),
      f.result
    );
  });
});

test('partialSigAgg', (t) => {
  const musig = t.context;

  fixtures.musigPartialSigAgg.forEach((f) => {
    const pubkeyAgg = musig.pubkeyAgg(f.publicKeys.map(fromHex));

    const nonceAgg = musig.nonceAgg(f.pubnonces.map(fromHex));
    t.is(uintToString(nonceAgg), f.aggnonce);

    const msg = fromHex(f.msg);
    const session = musig.nonceProcess(nonceAgg, msg, pubkeyAgg.keyaggCache);

    const partialSigs = f.partialSigs.map(fromHex);
    const aggregated = musig.partialSigAgg(session, partialSigs);

    t.is(aggregated.length, 64);
    t.is(uintToString(aggregated), f.aggregatedSignature);
    t.true(musig.ecc.verifySchnorr(msg, pubkeyAgg.aggPubkey, aggregated));
  });
});

test('pubkeyXonlyTweakAdd', (t) => {
  const { pubkeyXonlyTweakAdd } = t.context;

  fixtures.musigPubkeyXonlyTweakAdd.forEach((f) => {
    const tweaked = pubkeyXonlyTweakAdd(
      fromHex(f.keyaggCache),
      fromHex(f.tweak),
      f.compress
    );

    t.is(tweaked.pubkey.length, f.tweakedLength);
    t.is(uintToString(tweaked.pubkey), f.tweaked);
  });
});

test('full example', (t) => {
  const musig = t.context;

  const privateKeys = fixtures.fullExample.privateKeys.map(fromHex);
  const publicKeys = privateKeys.map(
    (key) => musig.ec.fromPrivateKey(key).publicKey
  );
  t.is(publicKeys.length, privateKeys.length);

  const pubkeyAgg = musig.pubkeyAgg(publicKeys);

  const nonces = publicKeys.map((publicKey) =>
    musig.nonceGen(randomBytes(32), publicKey)
  );
  const nonceAgg = musig.nonceAgg(nonces.map((nonce) => nonce.pubNonce));

  const message = randomBytes(32);
  const session = musig.nonceProcess(nonceAgg, message, pubkeyAgg.keyaggCache);

  const partialSigs = privateKeys.map((privateKey, i) =>
    musig.partialSign(
      nonces[i].secNonce,
      privateKey,
      pubkeyAgg.keyaggCache,
      session
    )
  );

  // Verify each partial signature individually, to make sure they are fine on their own
  partialSigs.forEach((sig, i) =>
    t.true(
      musig.partialVerify(
        sig,
        nonces[i].pubNonce,
        publicKeys[i],
        pubkeyAgg.keyaggCache,
        session
      )
    )
  );

  // Combine the partial signatures into one and verify it
  const sig = musig.partialSigAgg(session, partialSigs);
  t.true(musig.ecc.verifySchnorr(message, pubkeyAgg.aggPubkey, sig));
});

test('full example tweaked', (t) => {
  const musig = t.context;

  const privateKeys = fixtures.fullExample.privateKeys.map((key) =>
    fromHex(key)
  );
  const publicKeys = privateKeys.map(
    (key) => musig.ec.fromPrivateKey(key).publicKey
  );
  t.is(publicKeys.length, privateKeys.length);

  const pubkeyAgg = musig.pubkeyAgg(publicKeys);
  const tweak = musig.pubkeyXonlyTweakAdd(
    pubkeyAgg.keyaggCache,
    randomBytes(32),
    true
  );

  const nonces = publicKeys.map((publicKey) =>
    musig.nonceGen(randomBytes(32), publicKey)
  );
  const nonceAgg = musig.nonceAgg(nonces.map((nonce) => nonce.pubNonce));

  const message = randomBytes(32);
  const session = musig.nonceProcess(nonceAgg, message, tweak.keyaggCache);

  const partialSigs = privateKeys.map((privateKey, i) =>
    musig.partialSign(
      nonces[i].secNonce,
      privateKey,
      tweak.keyaggCache,
      session
    )
  );

  // Verify each partial signature individually, to make sure they are fine on their own
  partialSigs.forEach((sig, i) =>
    t.true(
      musig.partialVerify(
        sig,
        nonces[i].pubNonce,
        publicKeys[i],
        tweak.keyaggCache,
        session
      )
    )
  );

  // Combine the partial signatures into one and verify it
  const sig = musig.partialSigAgg(session, partialSigs);
  t.true(musig.ecc.verifySchnorr(message, tweak.pubkey.slice(1), sig));
});
