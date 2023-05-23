import { CModule } from './cmodule';
import { ZKP } from './interface';
import Memory from './memory';

function privateNegate(cModule: CModule): ZKP['ecc']['privateNegate'] {
  return function (key: Uint8Array): Uint8Array {
    if (!key || !(key instanceof Uint8Array) || key.length !== 32) {
      throw new TypeError('key must be a non-empty Uint8Array of 32 bytes');
    }
    const memory = new Memory(cModule);
    const keyPtr = memory.charStar(key);
    const ret = cModule.ccall(
      'ec_seckey_negate',
      'number',
      ['number'],
      [keyPtr]
    );

    if (ret === 1) {
      const out = new Uint8Array(cModule.HEAPU8.subarray(keyPtr, keyPtr + 32));
      memory.free();
      return out;
    }
    memory.free();
    throw new Error('ec_seckey_negate');
  };
}

function privateAdd(cModule: CModule): ZKP['ecc']['privateAdd'] {
  return function (key: Uint8Array, tweak: Uint8Array): Uint8Array {
    if (!key || !(key instanceof Uint8Array) || key.length !== 32) {
      throw new TypeError('key must be a non-empty Uint8Array of 32 bytes');
    }
    if (!tweak || !(tweak instanceof Uint8Array) || tweak.length !== 32) {
      throw new TypeError('tweak must be a non-empty Uint8Array of 32 bytes');
    }
    const memory = new Memory(cModule);

    const keyPtr = memory.charStar(key);
    const ret = cModule.ccall(
      'ec_seckey_tweak_add',
      'number',
      ['number', 'number'],
      [keyPtr, memory.charStar(tweak)]
    );

    let out = new Uint8Array();
    if (ret === 1) {
      out = new Uint8Array(cModule.HEAPU8.subarray(keyPtr, keyPtr + 32));
    }
    memory.free();
    return out;
  };
}

function privateSub(cModule: CModule): ZKP['ecc']['privateSub'] {
  return function (key: Uint8Array, tweak: Uint8Array) {
    if (!key || !(key instanceof Uint8Array) || key.length !== 32) {
      throw new TypeError('key must be a non-empty Uint8Array of 32 bytes');
    }
    if (!tweak || !(tweak instanceof Uint8Array) || tweak.length !== 32) {
      throw new TypeError('tweak must be a non-empty Uint8Array of 32 bytes');
    }
    const memory = new Memory(cModule);

    const keyPtr = memory.charStar(key);
    const ret = cModule.ccall(
      'ec_seckey_tweak_sub',
      'number',
      ['number', 'number'],
      [keyPtr, memory.charStar(tweak)]
    );

    if (ret === 1) {
      const out = new Uint8Array(cModule.HEAPU8.subarray(keyPtr, keyPtr + 32));
      memory.free();
      return out;
    }
    memory.free();
    throw new Error('ec_seckey_tweak_sub');
  };
}

function privateMul(cModule: CModule): ZKP['ecc']['privateMul'] {
  return function (key: Uint8Array, tweak: Uint8Array) {
    if (!key || !(key instanceof Uint8Array) || key.length !== 32) {
      throw new TypeError('key must be a non-empty Uint8Array of 32 bytes');
    }
    if (!tweak || !(tweak instanceof Uint8Array) || tweak.length !== 32) {
      throw new TypeError('tweak must be a non-empty Uint8Array of 32 bytes');
    }
    const memory = new Memory(cModule);

    const keyPtr = memory.charStar(key);
    const ret = cModule.ccall(
      'ec_seckey_tweak_mul',
      'number',
      ['number', 'number'],
      [keyPtr, memory.charStar(tweak)]
    );

    if (ret === 1) {
      const out = new Uint8Array(cModule.HEAPU8.subarray(keyPtr, keyPtr + 32));
      memory.free();
      return out;
    }
    memory.free();
    throw new Error('ec_seckey_tweak_mul');
  };
}

function isPoint(cModule: CModule): ZKP['ecc']['isPoint'] {
  return function (point: Uint8Array) {
    if (!point || !(point instanceof Uint8Array)) {
      throw new TypeError('point must be a Uint8Array');
    }
    const memory = new Memory(cModule);

    const pointPtr = memory.charStar(point);
    const res = cModule.ccall(
      'ec_is_point',
      'number',
      ['number', 'number'],
      [pointPtr, point.length]
    );
    memory.free();
    return res === 1;
  };
}

function pointCompress(cModule: CModule): ZKP['ecc']['pointCompress'] {
  return function (point: Uint8Array, compress = true) {
    if (!point || !(point instanceof Uint8Array)) {
      throw new TypeError('point must be a Uint8Array');
    }
    const memory = new Memory(cModule);

    const len = compress ? 33 : 65;
    const output = memory.malloc(len);
    const outputlen = memory.malloc(8);
    cModule.setValue(outputlen, len, 'i64');

    const ret = cModule.ccall(
      'ec_point_compress',
      'number',
      ['number', 'number', 'number', 'number', 'number'],
      [
        output,
        outputlen,
        memory.charStar(point),
        point.length,
        compress ? 1 : 0,
      ]
    );

    if (ret === 1) {
      const res = new Uint8Array(cModule.HEAPU8.subarray(output, output + len));
      memory.free();
      return res;
    }
    memory.free();
    throw new Error('point_compress');
  };
}

function isPrivate(cModule: CModule): ZKP['ecc']['isPrivate'] {
  return function (point: Uint8Array) {
    if (!point || !(point instanceof Uint8Array)) {
      throw new TypeError('point must be a Uint8Array');
    }
    const memory = new Memory(cModule);

    const dPtr = memory.charStar(point);
    const ret = cModule.ccall('ec_seckey_verify', 'number', ['number'], [dPtr]);
    memory.free();
    return ret === 1;
  };
}

function pointFromScalar(cModule: CModule): ZKP['ecc']['pointFromScalar'] {
  return function (scalar: Uint8Array, compress = true) {
    if (!scalar || !(scalar instanceof Uint8Array)) {
      throw new TypeError('scalar must be a Uint8Array');
    }
    const memory = new Memory(cModule);

    const len = compress ? 33 : 65;
    const output = memory.malloc(len);
    const outputlen = memory.malloc(8);
    cModule.setValue(outputlen, len, 'i64');

    const ret = cModule.ccall(
      'ec_point_from_scalar',
      'number',
      ['number', 'number', 'number', 'number'],
      [output, outputlen, memory.charStar(scalar), compress ? 1 : 0]
    );
    if (ret === 1) {
      const res = new Uint8Array(cModule.HEAPU8.subarray(output, output + len));
      memory.free();
      return res;
    }
    memory.free();
    throw new Error('point_from_scalar');
  };
}

function validateParity(n: number): n is 1 | 0 {
  return n === 1 || n === 0;
}

function xOnlyPointAddTweak(
  cModule: CModule
): ZKP['ecc']['xOnlyPointAddTweak'] {
  return function (point: Uint8Array, tweak: Uint8Array) {
    if (!point || !(point instanceof Uint8Array) || point.length !== 32) {
      throw new TypeError('point must be a Uint8Array of 32 bytes');
    }
    if (!tweak || !(tweak instanceof Uint8Array) || tweak.length !== 32) {
      throw new TypeError('tweak must be a Uint8Array of 32 bytes');
    }
    const memory = new Memory(cModule);

    const output = memory.malloc(32);
    const parityBit = memory.malloc(4);
    cModule.setValue(parityBit, 0, 'i32');
    const res = cModule.ccall(
      'ec_x_only_point_tweak_add',
      'number',
      ['number', 'number', 'number', 'number'],
      [output, parityBit, memory.charStar(point), memory.charStar(tweak)]
    );
    if (res === 1) {
      const xOnlyPubkey = new Uint8Array(
        cModule.HEAPU8.subarray(output, output + 32)
      );
      const parity = cModule.getValue(parityBit, 'i32');
      if (!validateParity(parity)) {
        throw new Error('parity is not valid');
      }
      memory.free();
      return { xOnlyPubkey, parity };
    }
    memory.free();
    return null;
  };
}

function signECDSA(cModule: CModule): ZKP['ecc']['sign'] {
  return function (
    message: Uint8Array,
    privateKey: Uint8Array,
    extraEntropy?: Uint8Array
  ) {
    if (!message || !(message instanceof Uint8Array)) {
      throw new TypeError('message must be a Uint8Array');
    }
    if (!privateKey || !(privateKey instanceof Uint8Array)) {
      throw new TypeError('privateKey must be a Uint8Array');
    }
    if (extraEntropy && !(extraEntropy instanceof Uint8Array)) {
      throw new TypeError('extraEntropy must be a Uint8Array');
    }
    const memory = new Memory(cModule);

    const output = memory.malloc(64);
    const hPtr = memory.charStar(message);
    const dPtr = memory.charStar(privateKey);
    const ret = cModule.ccall(
      'ec_sign_ecdsa',
      'number',
      ['number', 'number', 'number', 'number', 'number'],
      [
        output,
        dPtr,
        hPtr,
        extraEntropy ? 1 : 0,
        extraEntropy ? memory.charStar(extraEntropy) : 0,
      ]
    );
    if (ret === 1) {
      const res = new Uint8Array(cModule.HEAPU8.subarray(output, output + 64));
      memory.free();
      return res;
    }
    memory.free();
    throw new Error('sign_ecdsa');
  };
}

function verifyECDSA(cModule: CModule): ZKP['ecc']['verify'] {
  return function (
    message: Uint8Array,
    publicKey: Uint8Array,
    signature: Uint8Array,
    strict = false
  ) {
    if (!message || !(message instanceof Uint8Array)) {
      throw new TypeError('message must be a Uint8Array');
    }
    if (!publicKey || !(publicKey instanceof Uint8Array)) {
      throw new TypeError('publicKey must be a Uint8Array');
    }
    if (!signature || !(signature instanceof Uint8Array)) {
      throw new TypeError('signature must be a Uint8Array');
    }
    if (typeof strict !== 'boolean') {
      throw new TypeError('strict must be a boolean');
    }
    const memory = new Memory(cModule);

    const ret = cModule.ccall(
      'ec_verify_ecdsa',
      'number',
      ['number', 'number', 'number', 'number', 'number'],
      [
        memory.charStar(publicKey),
        publicKey.length,
        memory.charStar(message),
        memory.charStar(signature),
        strict ? 1 : 0,
      ]
    );
    memory.free();
    return ret === 1;
  };
}

function signSchnorr(cModule: CModule): ZKP['ecc']['signSchnorr'] {
  return function (
    message: Uint8Array,
    privateKey: Uint8Array,
    extraEntropy?: Uint8Array
  ) {
    if (!message || !(message instanceof Uint8Array)) {
      throw new TypeError('message must be a Uint8Array');
    }
    if (!privateKey || !(privateKey instanceof Uint8Array)) {
      throw new TypeError('privateKey must be a Uint8Array');
    }
    if (
      extraEntropy &&
      (!(extraEntropy instanceof Uint8Array) || extraEntropy.length !== 32)
    ) {
      throw new TypeError('extraEntropy must be a 32-byte Uint8Array');
    }
    const memory = new Memory(cModule);

    const output = memory.malloc(64);
    const ret = cModule.ccall(
      'ec_sign_schnorr',
      'number',
      ['number', 'number', 'number', 'number', 'number'],
      [
        output,
        memory.charStar(privateKey),
        memory.charStar(message),
        extraEntropy ? 1 : 0,
        extraEntropy ? memory.charStar(extraEntropy) : 0,
      ]
    );
    if (ret === 1) {
      const res = new Uint8Array(cModule.HEAPU8.subarray(output, output + 64));
      memory.free();
      return res;
    }
    memory.free();
    throw new Error('schnorr_sign');
  };
}

function verifySchnorr(cModule: CModule): ZKP['ecc']['verifySchnorr'] {
  return function (
    message: Uint8Array,
    publicKey: Uint8Array,
    signature: Uint8Array
  ) {
    if (!message || !(message instanceof Uint8Array)) {
      throw new TypeError('message must be a Uint8Array');
    }
    if (!publicKey || !(publicKey instanceof Uint8Array)) {
      throw new TypeError('publicKey must be a Uint8Array');
    }
    if (!signature || !(signature instanceof Uint8Array)) {
      throw new TypeError('signature must be a Uint8Array');
    }
    const memory = new Memory(cModule);

    const ret = cModule.ccall(
      'ec_verify_schnorr',
      'number',
      ['number', 'number', 'number', 'number'],
      [
        memory.charStar(publicKey),
        memory.charStar(message),
        message.length,
        memory.charStar(signature),
      ]
    );
    memory.free();
    return ret === 1;
  };
}

function pointAddScalar(cModule: CModule): ZKP['ecc']['pointAddScalar'] {
  return function (point: Uint8Array, tweak: Uint8Array, compressed = true) {
    if (!point || !(point instanceof Uint8Array) || point.length !== 33) {
      throw new TypeError('point must be a Uint8Array of length 33');
    }
    if (!tweak || !(tweak instanceof Uint8Array) || tweak.length !== 32) {
      throw new TypeError('tweak must be a Uint8Array of length 32');
    }
    const memory = new Memory(cModule);

    const lenghtPtr = memory.malloc(8);
    const outputLen = compressed ? 33 : 65;
    cModule.setValue(lenghtPtr, outputLen, 'i64');
    const output = memory.malloc(outputLen);

    const ret = cModule.ccall(
      'ec_point_add_scalar',
      'number',
      ['number', 'number', 'number', 'number', 'number'],
      [
        output,
        lenghtPtr,
        memory.charStar(point),
        memory.charStar(tweak),
        compressed ? 1 : 0,
      ]
    );
    if (ret === 1) {
      const res = new Uint8Array(
        cModule.HEAPU8.subarray(output, output + outputLen)
      );
      memory.free();
      return res;
    }
    memory.free();
    return null;
  };
}

export function ecc(cModule: CModule): ZKP['ecc'] {
  return {
    isPoint: isPoint(cModule),
    pointAddScalar: pointAddScalar(cModule),
    isPrivate: isPrivate(cModule),
    pointCompress: pointCompress(cModule),
    pointFromScalar: pointFromScalar(cModule),
    privateAdd: privateAdd(cModule),
    privateMul: privateMul(cModule),
    privateSub: privateSub(cModule),
    privateNegate: privateNegate(cModule),
    sign: signECDSA(cModule),
    verify: verifyECDSA(cModule),
    signSchnorr: signSchnorr(cModule),
    verifySchnorr: verifySchnorr(cModule),
    xOnlyPointAddTweak: xOnlyPointAddTweak(cModule),
  };
}
