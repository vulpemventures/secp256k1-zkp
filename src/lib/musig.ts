import { CModule } from './cmodule';
import { Secp256k1ZKP } from './interface';
import Memory from './memory';

function pubkeyAgg(cModule: CModule): Secp256k1ZKP['musig']['pubkeyAgg'] {
  return function pubkeyAgg(pubkeys: Array<Uint8Array>) {
    if (!pubkeys || !pubkeys.length) {
      throw TypeError('pubkeys must be an Array');
    }

    if (pubkeys.some((pubkey) => !(pubkey instanceof Uint8Array))) {
      throw TypeError('all elements of pubkeys must be Uint8Array');
    }

    const memory = new Memory(cModule);
    const aggPubkey = memory.malloc(32);
    const keyaggCache = memory.malloc(165);

    const ret = cModule.ccall(
      'musig_pubkey_agg',
      'number',
      ['number', 'number', 'number', 'number'],
      [aggPubkey, keyaggCache, memory.charStarArray(pubkeys), pubkeys.length]
    );

    if (ret !== 1) {
      memory.free();
      throw new Error('musig_pubkey_agg');
    }

    const res = {
      aggPubkey: memory.charStarToUint8(aggPubkey, 32),
      keyaggCache: memory.charStarToUint8(keyaggCache, 165),
    };
    memory.free();
    return res;
  };
}

function nonceGen(cModule: CModule): Secp256k1ZKP['musig']['nonceGen'] {
  return function nonceGen(sessionId: Uint8Array) {
    if (!(sessionId instanceof Uint8Array)) {
      throw new TypeError('sessionId must be Uint8Array');
    }

    const memory = new Memory(cModule);
    const secnonce = memory.malloc(68);
    const pubnonce = memory.malloc(66);

    const ret = cModule.ccall(
      'musig_nonce_gen',
      'number',
      ['number', 'number', 'number'],
      [secnonce, pubnonce, memory.charStar(sessionId)]
    );

    if (ret !== 1) {
      memory.free();
      throw new Error('musig_nonce_gen');
    }

    const res = {
      secNonce: memory.charStarToUint8(secnonce, 68),
      pubNonce: memory.charStarToUint8(pubnonce, 66),
    };
    memory.free();
    return res;
  };
}

function nonceAgg(cModule: CModule): Secp256k1ZKP['musig']['nonceAgg'] {
  return function nonceAgg(pubNonces: Array<Uint8Array>) {
    if (!pubNonces || !pubNonces.length) {
      throw TypeError('pubNonces must be an Array');
    }

    if (pubNonces.some((nonce) => !(nonce instanceof Uint8Array))) {
      throw TypeError('all elements of pubNonces must be Uint8Array');
    }

    const memory = new Memory(cModule);
    const aggNonce = memory.malloc(66);

    const ret = cModule.ccall(
      'musig_nonce_agg',
      'number',
      ['number', 'number', 'number'],
      [aggNonce, memory.charStarArray(pubNonces), pubNonces.length]
    );

    if (ret !== 1) {
      memory.free();
      throw new Error('musig_nonce_agg');
    }

    const res = memory.charStarToUint8(aggNonce, 66);
    memory.free();
    return res;
  };
}

function nonceProcess(cModule: CModule): Secp256k1ZKP['musig']['nonceProcess'] {
  return function nonceProcess(
    nonceAgg: Uint8Array,
    msg: Uint8Array,
    keyaggCache: Uint8Array
  ) {
    if (!(nonceAgg instanceof Uint8Array)) {
      throw new TypeError('nonceAgg must be Uint8Array');
    }
    if (!(msg instanceof Uint8Array)) {
      throw new TypeError('msg must be Uint8Array');
    }
    if (!(keyaggCache instanceof Uint8Array)) {
      throw new TypeError('keyaggCache must be Uint8Array');
    }

    const memory = new Memory(cModule);
    const session = memory.malloc(133);

    const ret = cModule.ccall(
      'musig_nonce_process',
      'number',
      ['number', 'number', 'number', 'number'],
      [
        session,
        memory.charStar(nonceAgg),
        memory.charStar(msg),
        memory.charStar(keyaggCache),
      ]
    );

    if (ret !== 1) {
      memory.free();
      throw new Error('musig_nonce_process');
    }

    const res = memory.charStarToUint8(session, 133);
    memory.free();
    return res;
  };
}

function partialSign(cModule: CModule): Secp256k1ZKP['musig']['partialSign'] {
  return function partialSign(
    secNonce: Uint8Array,
    secKey: Uint8Array,
    keyaggCache: Uint8Array,
    session: Uint8Array
  ) {
    if (!(secNonce instanceof Uint8Array)) {
      throw new TypeError('secNonce must be Uint8Array');
    }
    if (!(secKey instanceof Uint8Array)) {
      throw new TypeError('secKey must be Uint8Array');
    }
    if (!(keyaggCache instanceof Uint8Array)) {
      throw new TypeError('keyaggCache must be Uint8Array');
    }
    if (!(session instanceof Uint8Array)) {
      throw new TypeError('session must be Uint8Array');
    }

    const memory = new Memory(cModule);
    const partialSig = memory.malloc(32);

    const ret = cModule.ccall(
      'musig_partial_sign',
      'number',
      ['number', 'number', 'number', 'number', 'number'],
      [
        partialSig,
        memory.charStar(secNonce),
        memory.charStar(secKey),
        memory.charStar(keyaggCache),
        memory.charStar(session),
      ]
    );

    if (ret !== 1) {
      memory.free();
      throw new Error('musig_partial_sign');
    }

    const res = memory.charStarToUint8(partialSig, 32);
    memory.free();
    return res;
  };
}

function partialVerify(
  cModule: CModule
): Secp256k1ZKP['musig']['partialVerify'] {
  return function partialVerify(
    partialSig: Uint8Array,
    pubNonce: Uint8Array,
    pubKey: Uint8Array,
    keyaggCache: Uint8Array,
    session: Uint8Array
  ) {
    if (!(partialSig instanceof Uint8Array)) {
      throw new TypeError('partialSig must be Uint8Array');
    }
    if (!(pubNonce instanceof Uint8Array)) {
      throw new TypeError('pubNonce must be Uint8Array');
    }
    if (!(pubKey instanceof Uint8Array)) {
      throw new TypeError('pubKey must be Uint8Array');
    }
    if (!(keyaggCache instanceof Uint8Array)) {
      throw new TypeError('keyaggCache must be Uint8Array');
    }
    if (!(session instanceof Uint8Array)) {
      throw new TypeError('session must be Uint8Array');
    }

    const memory = new Memory(cModule);
    const ret = cModule.ccall(
      'musig_partial_sig_verify',
      'number',
      ['number', 'number', 'number', 'number', 'number'],
      [
        memory.charStar(partialSig),
        memory.charStar(pubNonce),
        memory.charStar(pubKey),
        memory.charStar(keyaggCache),
        memory.charStar(session),
      ]
    );

    memory.free();

    // Return true when the signature was verified successfully
    return ret === 1;
  };
}

function partialSigAgg(
  cModule: CModule
): Secp256k1ZKP['musig']['partialSigAgg'] {
  return function partialSigAgg(
    session: Uint8Array,
    partialSigs: Array<Uint8Array>
  ) {
    if (!(session instanceof Uint8Array)) {
      throw new TypeError('session must be Uint8Array');
    }
    if (!partialSigs || !partialSigs.length) {
      throw new TypeError('partialSigs must be an Array');
    }

    if (partialSigs.some((sig) => !(sig instanceof Uint8Array))) {
      throw TypeError('all elements of partialSigs must be Uint8Array');
    }

    const memory = new Memory(cModule);
    const sig = memory.malloc(64);

    const ret = cModule.ccall(
      'musig_partial_sig_agg',
      'number',
      ['number', 'number', 'number', 'number'],
      [
        sig,
        memory.charStar(session),
        memory.charStarArray(partialSigs),
        partialSigs.length,
      ]
    );

    if (ret !== 1) {
      memory.free();
      throw new Error('musig_partial_sig_agg');
    }

    const res = memory.charStarToUint8(sig, 64);
    memory.free();
    return res;
  };
}

function pubkeyXonlyTweakAdd(
  cModule: CModule
): Secp256k1ZKP['musig']['pubkeyXonlyTweakAdd'] {
  return function pubkeyXonlyTweakAdd(
    keyaggCache: Uint8Array,
    tweak: Uint8Array,
    compress = true
  ) {
    if (!(keyaggCache instanceof Uint8Array)) {
      throw new TypeError('keyaggCache must be Uint8Array');
    }
    if (!(tweak instanceof Uint8Array)) {
      throw new TypeError('tweak must be Uint8Array');
    }
    if (typeof compress !== 'boolean') {
      throw new TypeError('compress must be boolean');
    }

    const memory = new Memory(cModule);

    const output = memory.malloc(65);
    const outputLen = memory.malloc(8);
    cModule.setValue(outputLen, 65, 'i64');

    const keyaggCacheTweaked = memory.charStar(keyaggCache);

    const ret = cModule.ccall(
      'musig_pubkey_xonly_tweak_add',
      'number',
      ['number', 'number', 'number', 'number', 'number'],
      [
        output,
        outputLen,
        compress ? 1 : 0,
        keyaggCacheTweaked,
        memory.charStar(tweak),
      ]
    );

    if (ret !== 1) {
      memory.free();
      throw new Error('musig_pubkey_xonly_tweak_add');
    }

    const pubkey = memory.charStarToUint8(
      output,
      cModule.getValue(outputLen, 'i64')
    );
    const keyaggCacheTweakedRes = memory.charStarToUint8(
      keyaggCacheTweaked,
      165
    );

    memory.free();
    return {
      pubkey,
      keyaggCache: keyaggCacheTweakedRes,
    };
  };
}

export function musig(cModule: CModule): Secp256k1ZKP['musig'] {
  return {
    pubkeyAgg: pubkeyAgg(cModule),
    nonceGen: nonceGen(cModule),
    nonceAgg: nonceAgg(cModule),
    nonceProcess: nonceProcess(cModule),
    partialSign: partialSign(cModule),
    partialVerify: partialVerify(cModule),
    partialSigAgg: partialSigAgg(cModule),
    pubkeyXonlyTweakAdd: pubkeyXonlyTweakAdd(cModule),
  };
}
