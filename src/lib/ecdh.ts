import { CModule } from './cmodule';
import { ZKP } from './interface';
import Memory from './memory';

export function ecdh(cModule: CModule): ZKP['ecdh'] {
  return function (pubkey: Uint8Array, scalar: Uint8Array): Uint8Array {
    const memory = new Memory(cModule);
    const output = memory.malloc(32);
    const ret = cModule.ccall(
      'ecdh',
      'number',
      ['number', 'number', 'number'],
      [output, memory.charStar(pubkey), memory.charStar(scalar)]
    );

    if (ret === 1) {
      const out = new Uint8Array(cModule.HEAPU8.subarray(output, output + 32));
      memory.free();
      return out;
    } else {
      memory.free();
      throw new Error('secp256k1_ecdh');
    }
  };
}
