import { CModule } from './cmodule';
import { Secp256k1ZKP } from './interface';
import Memory from './memory';

function initialize(
  cModule: CModule
): Secp256k1ZKP['surjectionproof']['initialize'] {
  return function surjectionProofInitialize(
    inputTags: Uint8Array[],
    outputTag: Uint8Array,
    maxIterations: number,
    seed: Uint8Array
  ) {
    if (
      !inputTags ||
      !Array.isArray(inputTags) ||
      !inputTags.length ||
      !inputTags.every((t) => t.length === 32)
    )
      throw new TypeError(
        'input tags must be a non-empty array of Uint8Arrays of 32 bytes'
      );
    if (
      !outputTag ||
      !(outputTag instanceof Uint8Array) ||
      outputTag.length !== 32
    )
      throw new TypeError('output tag must be a Uint8Array of 32 bytes');
    if (!seed || !(seed instanceof Uint8Array) || seed.length !== 32)
      throw new TypeError('seed must be a Uint8Array of 32 bytes');

    const memory = new Memory(cModule);

    const inputTagsToUse = inputTags.length > 3 ? 3 : inputTags.length;
    const output = memory.malloc(8258);
    const outputLength = memory.malloc(8);
    cModule.setValue(outputLength, 8258, 'i64');
    const inIndex = memory.malloc(4);
    cModule.setValue(inIndex, 0, 'i32');
    const ret = cModule.ccall(
      'surjectionproof_initialize',
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
      ],
      [
        output,
        outputLength,
        inIndex,
        memory.charStarArray(inputTags),
        inputTags.length,
        inputTagsToUse,
        memory.charStar(outputTag),
        maxIterations,
        memory.charStar(seed),
      ]
    );
    if (ret > 0) {
      const proof = new Uint8Array(
        cModule.HEAPU8.subarray(
          output,
          output + cModule.getValue(outputLength, 'i64')
        )
      );
      const inputIndex = cModule.getValue(inIndex, 'i32');
      memory.free();
      return { proof, inputIndex };
    } else {
      memory.free();
      throw new Error('secp256k1_surjectionproof_initialize');
    }
  };
}

function generate(
  cModule: CModule
): Secp256k1ZKP['surjectionproof']['generate'] {
  return function surjectionProofGenerate(
    proofData: Uint8Array,
    inputTags: Uint8Array[],
    outputTag: Uint8Array,
    inputIndex: number,
    inputBlindingKey: Uint8Array,
    outputBlindingKey: Uint8Array
  ) {
    if (!proofData || !(proofData instanceof Uint8Array))
      throw new TypeError('proof must be a non-empty Uint8Array');
    if (
      !inputTags ||
      !Array.isArray(inputTags) ||
      !inputTags.length ||
      !inputTags.every((t) => t.length === 33)
    )
      throw new TypeError(
        'input tags must be a non-empty array of Uint8Arrays of 33 bytes'
      );
    if (
      !outputTag ||
      !(outputTag instanceof Uint8Array) ||
      outputTag.length !== 33
    )
      throw new TypeError('ouput tag must be a Uint8Array of 33 bytes');
    if (
      !inputBlindingKey ||
      !(inputBlindingKey instanceof Uint8Array) ||
      inputBlindingKey.length !== 32
    )
      throw new TypeError(
        'input blinding key must be a Uint8Array of 32 bytes'
      );
    if (
      !outputBlindingKey ||
      !(outputBlindingKey instanceof Uint8Array) ||
      outputBlindingKey.length !== 32
    )
      throw new TypeError(
        'output blinding key must be a Uint8Array of 32 bytes'
      );
    if (inputIndex < 0 || inputIndex > inputTags.length)
      throw new TypeError(
        `input index must be a number into range [0, ${inputTags.length}]`
      );

    const memory = new Memory(cModule);

    const output = memory.malloc(8258);
    const outputLength = memory.malloc(8);

    const ret = cModule.ccall(
      'surjectionproof_generate',
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
      ],
      [
        output,
        outputLength,
        memory.charStar(proofData),
        proofData.length,
        memory.charStarArray(inputTags),
        inputTags.length,
        memory.charStar(outputTag),
        inputIndex,
        memory.charStar(inputBlindingKey),
        memory.charStar(outputBlindingKey),
      ]
    );
    if (ret === 1) {
      const proof = new Uint8Array(
        cModule.HEAPU8.subarray(
          output,
          output + cModule.getValue(outputLength, 'i64')
        )
      );
      memory.free();
      return proof;
    } else {
      memory.free();
      throw new Error('secp256k1_surjectionproof_generate');
    }
  };
}

function verify(cModule: CModule): Secp256k1ZKP['surjectionproof']['verify'] {
  return function surjectionProofVerify(
    proof: Uint8Array,
    inputTags: Uint8Array[],
    outputTag: Uint8Array
  ) {
    if (!proof || !(proof instanceof Uint8Array) || !proof.length)
      throw new TypeError('proof must be a non-empty Uint8Array');
    if (
      !inputTags ||
      !Array.isArray(inputTags) ||
      !inputTags.length ||
      !inputTags.every((t) => t.length === 33)
    )
      throw new TypeError(
        'input tags must be a non-empty array of Uint8Arrays of 33 bytes'
      );
    if (
      !outputTag ||
      !(outputTag instanceof Uint8Array) ||
      outputTag.length !== 33
    )
      throw new TypeError('ouput tag must be a Uint8Array of 33 bytes');

    const memory = new Memory(cModule);

    const ret = cModule.ccall(
      'surjectionproof_verify',
      'number',
      ['number', 'number', 'number', 'number', 'number'],
      [
        memory.charStar(proof),
        proof.length,
        memory.charStarArray(inputTags),
        inputTags.length,
        memory.charStar(outputTag),
      ]
    );
    memory.free();
    return ret === 1;
  };
}

export function surjectionproof(
  cModule: CModule
): Secp256k1ZKP['surjectionproof'] {
  return {
    initialize: initialize(cModule),
    generate: generate(cModule),
    verify: verify(cModule),
  };
}
