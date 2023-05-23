import Long from 'long';

import { CModule } from './cmodule';
import { ZKP } from './interface';
import Memory from './memory';

function commitment(cModule: CModule): ZKP['pedersen']['commitment'] {
  return function (value: string, generator: Uint8Array, blinder: Uint8Array) {
    if (
      !generator ||
      !(generator instanceof Uint8Array) ||
      generator.length !== 33
    )
      throw new TypeError('generator must be a Uint8Array of 33 bytes');
    if (!blinder || !(blinder instanceof Uint8Array) || blinder.length !== 32)
      throw new TypeError('blinder must be a Uint8Array of 32 bytes');

    const memory = new Memory(cModule);

    const output = memory.malloc(33);
    const valueLong = Long.fromString(value, true);

    const ret = cModule.ccall(
      'pedersen_commitment',
      'number',
      ['number', 'number', 'number', 'number'],
      [
        output,
        memory.uint64Long(valueLong),
        memory.charStar(generator),
        memory.charStar(blinder),
      ]
    );
    if (ret === 1) {
      const out = new Uint8Array(cModule.HEAPU8.subarray(output, output + 33));
      memory.free();
      return out;
    } else {
      memory.free();
      throw new Error('secp256k1_pedersen_commit');
    }
  };
}

function blindGeneratorBlindSum(
  cModule: CModule
): ZKP['pedersen']['blindGeneratorBlindSum'] {
  return function (
    values: string[],
    assetBlinders: Uint8Array[],
    valueBlinders: Uint8Array[],
    nInputs: number
  ) {
    if (
      !assetBlinders ||
      !Array.isArray(assetBlinders) ||
      !assetBlinders.length ||
      !assetBlinders.every((v) => v instanceof Uint8Array)
    )
      throw new TypeError(
        'asset blinders must be a non-empty list of Uint8Array'
      );
    if (!valueBlinders || !Array.isArray(valueBlinders))
      throw new TypeError('value blinders must be a list of Uint8Array');

    const memory = new Memory(cModule);

    const longValues = values.map((v) => Long.fromString(v, true));
    const blindOut = memory.malloc(32);
    const ret = cModule.ccall(
      'pedersen_blind_generator_blind_sum',
      'number',
      ['number', 'number', 'number', 'number', 'number', 'number'],
      [
        memory.longIntStarArray(longValues),
        memory.charStarArray(assetBlinders),
        memory.charStarArray(valueBlinders),
        assetBlinders.length,
        nInputs,
        blindOut,
      ]
    );
    if (ret === 1) {
      const output = new Uint8Array(
        cModule.HEAPU8.subarray(blindOut, blindOut + 32)
      );
      memory.free();
      return output;
    } else {
      memory.free();
      throw new Error('secp256k1_pedersen_blind_generator_blind_sum');
    }
  };
}

export function pedersen(cModule: CModule): ZKP['pedersen'] {
  return {
    commitment: commitment(cModule),
    blindGeneratorBlindSum: blindGeneratorBlindSum(cModule),
  };
}
