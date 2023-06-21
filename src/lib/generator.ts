import { CModule } from './cmodule';
import { Secp256k1ZKP } from './interface';
import Memory from './memory';

function generate(cModule: CModule): Secp256k1ZKP['generator']['generate'] {
  return function (seed: Uint8Array) {
    if (!seed || !(seed instanceof Uint8Array) || seed.length !== 32) {
      throw new TypeError('seed must be a Uint8Array of 32 bytes');
    }
    const memory = new Memory(cModule);

    const output = memory.malloc(33);

    const ret = cModule.ccall(
      'generator_generate',
      'number',
      ['number', 'number'],
      [output, memory.charStar(seed)]
    );
    if (ret === 1) {
      const out = new Uint8Array(cModule.HEAPU8.subarray(output, output + 33));
      memory.free();
      return out;
    }
    memory.free();
    throw new Error('secp256k1_generator_generate');
  };
}

function generateBlinded(
  cModule: CModule
): Secp256k1ZKP['generator']['generateBlinded'] {
  return function (key, blinder) {
    if (!key || !(key instanceof Uint8Array) || key.length !== 32)
      throw new TypeError('key must be a Uint8Array of 32 bytes');
    if (!blinder || !(blinder instanceof Uint8Array) || blinder.length !== 32)
      throw new TypeError('blind must be a Uint8Array of 32 bytes');

    const memory = new Memory(cModule);

    const output = memory.malloc(33);

    const ret = cModule.ccall(
      'generator_generate_blinded',
      'number',
      ['number', 'number', 'number'],
      [output, memory.charStar(key), memory.charStar(blinder)]
    );
    if (ret === 1) {
      const out = new Uint8Array(cModule.HEAPU8.subarray(output, output + 33));
      memory.free();
      return out;
    } else {
      memory.free();
      throw new Error('secp256k1_generator_generate_blinded');
    }
  };
}

export function generator(cModule: CModule): Secp256k1ZKP['generator'] {
  return {
    generate: generate(cModule),
    generateBlinded: generateBlinded(cModule),
  };
}
