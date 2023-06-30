import Long from 'long';

import { CModule } from './cmodule';
import { Secp256k1ZKP } from './interface';
import Memory from './memory';

function sign(cModule: CModule): Secp256k1ZKP['rangeproof']['sign'] {
  return function rangeProofSign(
    value: string,
    valueCommitment: Uint8Array,
    assetCommitment: Uint8Array,
    valueBlinder: Uint8Array,
    nonce: Uint8Array,
    minValue = '0',
    base10Exp = '0',
    minBits = '0',
    message = new Uint8Array(),
    extraCommitment = new Uint8Array()
  ) {
    if (
      !valueCommitment ||
      !(valueCommitment instanceof Uint8Array) ||
      !valueCommitment.length
    )
      throw new TypeError('value commitment must be a Uint8Array of 33 bytes');
    if (
      !assetCommitment ||
      !(assetCommitment instanceof Uint8Array) ||
      assetCommitment.length !== 33
    )
      throw new TypeError('asset commitment must be a Uint8Array of 33 bytes');
    if (
      !valueBlinder ||
      !(valueBlinder instanceof Uint8Array) ||
      valueBlinder.length !== 32
    )
      throw new TypeError('value blinder must be a Uint8Array of 32 bytes');
    if (!nonce || !(nonce instanceof Uint8Array) || !nonce.length)
      throw new TypeError('nonce must be a Uint8Array of 32 bytes');
    if (!(message instanceof Uint8Array))
      throw new TypeError('message must be a Uint8Array');
    if (!(extraCommitment instanceof Uint8Array))
      throw new TypeError('extra commitment must be a Uint8Array');

    const memory = new Memory(cModule);

    const proof = memory.malloc(5134);
    const plen = memory.malloc(8);
    cModule.setValue(plen, 5134, 'i64');
    const minValueLong = Long.fromString(minValue, true);
    const valueLong = Long.fromString(value, true);
    const exp = Number.parseInt(base10Exp, 10);
    const bits = Number.parseInt(minBits, 10);

    const ret = cModule.ccall(
      'rangeproof_sign',
      'number',
      [
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
      ],
      [
        proof,
        plen,
        memory.uint64Long(valueLong),
        memory.charStar(valueCommitment),
        memory.charStar(assetCommitment),
        memory.charStar(valueBlinder),
        memory.charStar(nonce),
        exp,
        bits,
        memory.uint64Long(minValueLong),
        memory.charStar(message),
        message.length,
        memory.charStar(extraCommitment),
        extraCommitment.length,
      ]
    );
    if (ret === 1) {
      const out = new Uint8Array(
        cModule.HEAPU8.subarray(proof, proof + cModule.getValue(plen, 'i64'))
      );
      memory.free();
      return out;
    } else {
      memory.free();
      throw new Error('secp256k1_rangeproof_sign');
    }
  };
}

function info(cModule: CModule): Secp256k1ZKP['rangeproof']['info'] {
  return function rangeProofInfo(proof: Uint8Array) {
    if (!proof || !(proof instanceof Uint8Array) || !proof.length)
      throw new TypeError('proof must be a non empty Uint8Array');

    const memory = new Memory(cModule);

    const exp = memory.malloc(4);
    const mantissa = memory.malloc(4);
    const min = memory.malloc(8);
    const max = memory.malloc(8);
    const ret = cModule.ccall(
      'rangeproof_info',
      'number',
      ['number', 'number', 'number', 'number', 'number', 'number'],
      [exp, mantissa, min, max, memory.charStar(proof), proof.length]
    );

    if (ret === 1) {
      const res = {
        exp: cModule.getValue(exp, 'i32').toString(),
        mantissa: cModule.getValue(mantissa, 'i32').toString(),
        minValue: memory.readUint64Long(min).toString(),
        maxValue: memory.readUint64Long(max).toString(),
      };
      memory.free();
      return res;
    } else {
      memory.free();
      throw new Error('secp256k1_rangeproof_info decode failed');
    }
  };
}

function verify(cModule: CModule): Secp256k1ZKP['rangeproof']['verify'] {
  return function rangeProofVerify(
    proof: Uint8Array,
    valueCommitment: Uint8Array,
    assetCommitment: Uint8Array,
    extraCommitment = new Uint8Array()
  ) {
    if (!proof || !(proof instanceof Uint8Array) || !proof.length)
      throw new TypeError('proof must be a non empty Uint8Array');
    if (
      !valueCommitment ||
      !(valueCommitment instanceof Uint8Array) ||
      valueCommitment.length !== 33
    )
      throw new TypeError('value commitment must be a Uint8Array of 33 bytes');
    if (
      !assetCommitment ||
      !(assetCommitment instanceof Uint8Array) ||
      assetCommitment.length !== 33
    )
      throw new TypeError('asset commitment must be a Uint8Array of 33 bytes');
    if (!extraCommitment || !(extraCommitment instanceof Uint8Array))
      throw new TypeError('extra commitment must be a Uint8Array');

    const memory = new Memory(cModule);

    const min = memory.malloc(8);
    const max = memory.malloc(8);
    const ret = cModule.ccall(
      'rangeproof_verify',
      'number',
      [
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
      ],
      [
        min,
        max,
        memory.charStar(proof),
        proof.length,
        memory.charStar(valueCommitment),
        memory.charStar(assetCommitment),
        memory.charStar(extraCommitment),
        extraCommitment.length,
      ]
    );

    memory.free();
    return ret === 1;
  };
}

function rewind(cModule: CModule) {
  return function rangeProofRewind(
    proof: Uint8Array,
    valueCommitment: Uint8Array,
    assetCommitment: Uint8Array,
    nonce: Uint8Array,
    extraCommitment = new Uint8Array()
  ) {
    if (!proof || !(proof instanceof Uint8Array) || !proof.length)
      throw new TypeError('proof must be a non-empty Uint8Array');
    if (
      !valueCommitment ||
      !(valueCommitment instanceof Uint8Array) ||
      valueCommitment.length !== 33
    )
      throw new TypeError('value commitment must be a Uint8Array of 33 bytes');
    if (
      !assetCommitment ||
      !(assetCommitment instanceof Uint8Array) ||
      assetCommitment.length !== 33
    )
      throw new TypeError('asset commitment must be a Uint8Array of 33 bytes');
    if (!nonce || !(nonce instanceof Uint8Array) || !nonce.length)
      throw new TypeError('nonce must be a non empty Uint8Array');
    if (!extraCommitment || !(extraCommitment instanceof Uint8Array))
      throw new TypeError('extra commitment must be a Uint8Array');

    const memory = new Memory(cModule);

    const blind = memory.malloc(32);
    const value = memory.malloc(8);
    const msg = memory.malloc(64);
    const msgLength = memory.malloc(8);
    const minValue = memory.malloc(8);
    const maxValue = memory.malloc(8);
    cModule.setValue(msgLength, 64, 'i64');

    const ret = cModule.ccall(
      'rangeproof_rewind',
      'number',
      [
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
      ],
      [
        blind,
        value,
        minValue,
        maxValue,
        msg,
        msgLength,
        memory.charStar(proof),
        proof.length,
        memory.charStar(valueCommitment),
        memory.charStar(assetCommitment),
        memory.charStar(nonce),
        memory.charStar(extraCommitment),
        extraCommitment.length,
      ]
    );

    if (ret === 1) {
      const blinder = new Uint8Array(
        cModule.HEAPU8.subarray(blind, blind + 32)
      );
      const message = new Uint8Array(
        cModule.HEAPU8.subarray(msg, msg + cModule.getValue(msgLength, 'i64'))
      );
      const out = {
        value: memory.readUint64Long(value).toString(),
        minValue: memory.readUint64Long(minValue).toString(),
        maxValue: memory.readUint64Long(maxValue).toString(),
        blinder,
        message,
      };
      memory.free();
      return out;
    } else {
      memory.free();
      throw new Error('secp256k1_rangeproof_rewind');
    }
  };
}

export function rangeproof(cModule: CModule): Secp256k1ZKP['rangeproof'] {
  return {
    info: info(cModule),
    rewind: rewind(cModule),
    sign: sign(cModule),
    verify: verify(cModule),
  };
}
