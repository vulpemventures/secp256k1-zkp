const Module = require('../src/libsecp256k1')();
const Long = require('long');

module.exports = {
  ecdh: { ecdh },
  pedersen: {
    commit,
    commitSerialize,
    commitParse,
    blindGeneratorBlindSum,
    blindSum,
    verifySum,
  },
  generator: {
    generateBlinded,
    parse,
    serialize,
  },
  rangeproof: {
    sign,
    info,
    verify,
    rewind,
  },
  surjectionproof: {
    serialize: proofSerialize,
    initialize: proofInitialize,
    generate: proofGenerate,
    verify: proofVerify,
  },
};

/**
 *  @summary Calculates a ECDH point.
 *  @return {Array} 32-bytes ecdh point.
 *  @throws {Error} Decode error.
 *  @arg {Array} pubkey - 33-byte pubkey.
 *  @arg {Array} scalar - 32-byte scalar.
 *  @exports
 */
function ecdh(pubkey, scalar) {
  const output = malloc(32);
  const ret = Module.ccall(
    'ecdh',
    'number',
    ['number', 'number', 'number'],
    [output, charStar(pubkey), charStar(scalar)]
  );

  if (ret === 1) {
    const out = new Uint8Array(Module.HEAPU8.subarray(output, output + 32));
    freeMalloc();
    return Buffer.from(out);
  } else {
    freeMalloc();
    throw new Error('secp256k1_ecdh', ret);
  }
}

/**
 *  @summary Generates a blinding generator with a blinding factor.
 *  @return {Array} 64-byte generator successfully computed.
 *  @throws {Error} Decode error.
 *  @arg {Array} key - 32-byte array key.
 *  @arg {Array} blind - 32-byte array blinding factor.
 *  @exports
 */
function generateBlinded(key, blind) {
  if (!key || !Buffer.isBuffer(key) || key.length !== 32)
    throw new TypeError('key must be a Buffer of 32 bytes');
  if (!blind || !Buffer.isBuffer(blind) || blind.length !== 32)
    throw new TypeError('blind must be a Buffer of 32 bytes');

  const output = malloc(64);

  const ret = Module.ccall(
    'generator_generate_blinded',
    'number',
    ['number', 'number', 'number'],
    [output, charStar(key), charStar(blind)]
  );
  if (ret === 1) {
    const out = new Uint8Array(Module.HEAPU8.subarray(output, output + 64));
    freeMalloc();
    return Buffer.from(out);
  } else {
    freeMalloc();
    throw new Error('secp256k1_generator_generate_blinded', ret);
  }
}

/**
 *  @summary Parses a serialized generator.
 *  @return {Array} 64-bytes generator.
 *  @throws {Error} Decode error.
 *  @arg {Array} input - 33-byte serialized generator.
 *  @exports
 */
function parse(input) {
  if (!input || !Buffer.isBuffer(input) || input.length !== 33)
    throw new TypeError('input must be a Buffer of 32 bytes');

  const gen = malloc(64);

  const ret = Module.ccall(
    'generator_parse',
    'number',
    ['number', 'number'],
    [gen, charStar(input)]
  );
  if (ret === 1) {
    const out = new Uint8Array(Module.HEAPU8.subarray(gen, gen + 64));
    freeMalloc();
    return Buffer.from(out);
  } else {
    freeMalloc();
    throw new Error('secp256k1_generator_parse', ret);
  }
}

/**
 *  @summary Serializes a generator.
 *  @return {Array} 33-bytes serialized generator.
 *  @throws {Error} Decode error.
 *  @arg {Array} generator - 64-byte generator.
 *  @exports
 */
function serialize(generator) {
  if (!generator || !Buffer.isBuffer(generator) || generator.length !== 64)
    throw new TypeError('generator must be a Buffer of 32 bytes');

  const output = malloc(33);
  const ret = Module.ccall(
    'generator_serialize',
    'number',
    ['number', 'number'],
    [output, charStar(generator)]
  );
  if (ret === 1) {
    const out = new Uint8Array(Module.HEAPU8.subarray(output, output + 33));
    freeMalloc();
    return Buffer.from(out);
  } else {
    freeMalloc();
    throw new Error('secp256k1_generator_parse', ret);
  }
}

/**
 *  @summary Generates a pedersen commitment.
 *  @return {Array} 33-bytes commitment successfully created.
 *  @throws {Error} - Decode error.
 *  @arg {Array} blindFactor - 32-byte blinding factor.
 *  @arg {string} value - unsigned 64-bit integer value to commit to as string.
 *  @arg {Array} generator - 64-byte generator.
 *  @exports
 */
function commit(blindFactor, value, generator) {
  if (
    !blindFactor ||
    !Buffer.isBuffer(blindFactor) ||
    blindFactor.length !== 32
  )
    throw new TypeError('blindFactor must be a Buffer of 32 bytes');
  if (!generator || !Buffer.isBuffer(generator) || generator.length !== 64)
    throw new TypeError('generator must be a Buffer of 64 bytes');

  const commitment = malloc(64);
  const valueLong = Long.fromString(value, true);

  const ret = Module.ccall(
    'pedersen_commit',
    'number',
    ['number', 'number', 'number', 'number'],
    [
      commitment,
      charStar(blindFactor),
      valueLong.low,
      valueLong.high,
      charStar(generator),
    ]
  );
  if (ret === 1) {
    const out = new Uint8Array(
      Module.HEAPU8.subarray(commitment, commitment + 64)
    );
    freeMalloc();
    return Buffer.from(out);
  } else {
    freeMalloc();
    throw new Error('secp256k1_pedersen_commit', ret);
  }
}

/**
 *  @summary Serializes a pedersen commitment.
 *  @return {Array} 33-bytes serialized pedersen commitment.
 *  @throws {Error} - Decode error.
 *  @arg {Array} commitment - 64-byte pedersen commitment (cannot be NULL).
 *  @exports
 */
function commitSerialize(commitment) {
  if (!commitment || !Buffer.isBuffer(commitment) || commitment.length !== 64)
    throw new TypeError('commitment must be a Buffer of 64 bytes');

  const out = malloc(33);

  const ret = Module.ccall(
    'pedersen_commitment_serialize',
    'number',
    ['number', 'number'],
    [out, charStar(commitment)]
  );
  if (ret === 1) {
    const cmt = new Uint8Array(Module.HEAPU8.subarray(out, out + 33));
    freeMalloc();
    return Buffer.from(cmt);
  } else {
    freeMalloc();
    throw new Error('secp256k1_pedersen_commitment_serialize', ret);
  }
}

/**
 *  @summary Parses a pedersen commitment.
 *  @return {Array} 64-bytes pedersen commitment.
 *  @throws {Error} - Decode error.
 *  @arg {Array} input - 33-byte commitment to parse (cannot be NULL).
 *  @exports
 */
function commitParse(input) {
  if (!input || !Buffer.isBuffer(input) || input.length !== 33)
    throw new TypeError('input must be a Buffer of 33 bytes');

  const commitment = malloc(64);
  const ret = Module.ccall(
    'pedersen_commitment_parse',
    'number',
    ['number', 'number'],
    [commitment, charStar(input)]
  );
  if (ret === 1) {
    const cmt = new Uint8Array(
      Module.HEAPU8.subarray(commitment, commitment + 64)
    );
    freeMalloc();
    return Buffer.from(cmt);
  } else {
    freeMalloc();
    throw new Error('secp256k1_pedersen_commitment_parse', ret);
  }
}

/**
 *  @summary Sets the final blinding factor correctly when the generators themselves have blinding factors.
 *  @return {Array} 32-bytes final blinding factor.
 *  @throws {Error} - Decode error.
 *  @arg {Array} values - array of asset values as string.
 *  @arg {number} nInputs - How many of the initial array elements represent commitments that will be negated in the final sum.
 *  @arg {Array} blindGenerators - array of asset blinding factors.
 *  @arg {Array} blindFactors - array of commitment blinding factors.
 *  @exports
 */
function blindGeneratorBlindSum(
  values,
  nInputs,
  blindGenerators,
  blindFactors
) {
  if (
    !blindGenerators ||
    !Array.isArray(blindGenerators) ||
    !blindGenerators.length
  )
    throw new TypeError('blindGenerators must be a non empty array of Buffers');
  if (!blindFactors || !Array.isArray(blindFactors))
    throw new TypeError('blindFactors must be an array of Buffers');

  const longValues = values.map((v) => Long.fromString(v, true));
  const blindOut = malloc(32);
  const ret = Module.ccall(
    'pedersen_blind_generator_blind_sum',
    'number',
    ['number', 'number', 'number', 'number', 'number', 'number'],
    [
      longIntStarArray(longValues),
      charStarArray(blindGenerators),
      charStarArray(blindFactors),
      blindGenerators.length,
      nInputs,
      blindOut,
    ]
  );
  if (ret === 1) {
    const output = new Uint8Array(
      Module.HEAPU8.subarray(blindOut, blindOut + 32)
    );
    freeMalloc();
    return Buffer.from(output);
  } else {
    freeMalloc();
    throw new Error('secp256k1_pedersen_blind_generator_blind_sum', ret);
  }
}

/**
 *  @summary Computes the sum of multiple positive and negative blinding factors.
 *  @return {Array} 32-bytes sum successfully computed.
 *  @throws {Error} Decode error.
 *  @arg {Array} blinds - 32-byte character arrays for blinding factors.
 *  @arg {number} [nneg = 0] - how many of the initial factors should be treated with a negative sign.
 *  @exports
 */
function blindSum(blinds, nneg = 0) {
  if (!blinds || !Array.isArray(blinds) || !blinds.length)
    throw new TypeError('blinds must be a non empty array of Buffers');

  const sum = malloc(32);
  const ret = Module.ccall(
    'pedersen_blind_sum',
    'number',
    ['number', 'number', 'number', 'number'],
    [sum, charStarArray(blinds), blinds.length, blinds.length - nneg]
  );
  if (ret === 1) {
    const s = new Uint8Array(Module.HEAPU8.subarray(sum, sum + 32));
    freeMalloc();
    return Buffer.from(s);
  } else {
    freeMalloc();
    throw new Error('secp256k1_pedersen_blind_sum', ret);
  }
}

/**
 * @summary Verifies pedersen commitments - negativeCommits - excess === 0
 * @return {boolean} commitments successfully sum to zero.
 * @throws {Error} Commitments do not sum to zero or other error.
 * @arg {Array} commits: pointer to pointers to 33-byte character arrays for the commitments.
 * @arg {Array} ncommits: pointer to pointers to 33-byte character arrays for negative commitments.
 * @exports
 */
function verifySum(commits, negativeCommits) {
  if (
    !commits ||
    !Array.isArray(commits) ||
    !commits.every((c) => c.length === 33)
  )
    throw new TypeError(
      'commits must be a non empty array of Buffers of 33 bytes'
    );
  if (
    !negativeCommits ||
    !Array.isArray(negativeCommits) ||
    !negativeCommits.every((c) => c.length === 33)
  )
    throw new TypeError(
      'negativeCommits must be a non empty array of Buffers of 33 bytes'
    );
  const ret = Module.ccall(
    'pedersen_verify_tally',
    'number',
    ['number', 'number', 'number', 'number'],
    [
      charStarArray(commits),
      commits.length,
      charStarArray(negativeCommits),
      negativeCommits.length,
    ]
  );
  freeMalloc();
  return ret === 1;
}

/**
 *  @summary Authors a proof that a committed value is within a range.
 *  @return {Array} Proof successfully created.
 *  @throws {Error} Decode failed.
 *  @arg {Array} commitment: 33-byte array with the commitment being proved.
 *  @arg {Array} blind: 32-byte blinding factor used by commit.
 *  @arg {Array} nonce: 32-byte secret nonce used to initialize the proof (value can be reverse-engineered out of the proof if this secret is known.).
 *  @arg {string} value: unblinded value.
 *  @arg {Array} generator: 64-byte secret generator for the proof.
 *  @arg {string} minValue: constructs a proof where the verifer can tell the minimum value is at least the specified amount.
 *  @arg {number} base10Exp: Base-10 exponent. Digits below above will be made public, but the proof will be made smaller. Allowed range is -1 to 18.
 *      (-1 is a special case that makes the value public. 0 is the most private.).
 *  @arg {number} minBits: Number of bits of the value to keep private. (0 = auto/minimal, - 64).
 *  @arg {Array} message: optional message.
 *  @arg {Array} extraCommit: optional extra commit.
 *  @exports
 */
function sign(
  commitment,
  blind,
  nonce,
  value,
  generator,
  minValue = '0',
  base10Exp = 0,
  minBits = 0,
  message = [],
  extraCommit = []
) {
  if (!commitment || !Buffer.isBuffer(commit) || !commitment.length)
    throw new TypeError('commit must be a non empty Buffer');
  if (!blind || !Buffer.isBuffer(blind) || blind.length !== 32)
    throw new TypeError('blind must be a Buffer of 32 bytes');
  if (!nonce || !Buffer.isBuffer(nonce) || !nonce.length)
    throw new TypeError('nonce must be a non empty Buffer');
  if (!generator || !Buffer.isBuffer(generator) || generator.length !== 64)
    throw new TypeError('generator must be a Buffer of 64 bytes');
  if (!message || !Buffer.isBuffer(message))
    throw new TypeError('message must be a Buffer');
  if (!extraCommit || !Buffer.isBuffer(extraCommit))
    throw new TypeError('extraCommit must be a Buffer');

  const proof = malloc(5134);
  const plen = malloc(8);
  Module.setValue(plen, 5134, 'i64');
  const minValueLong = Long.fromString(minValue, true);
  const valueLong = Long.fromString(value, true);

  const ret = Module.ccall(
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
      minValueLong.low,
      minValueLong.high,
      charStar(commitment),
      charStar(blind),
      charStar(nonce),
      base10Exp,
      minBits,
      valueLong.low,
      valueLong.high,
      charStar(message),
      message.length,
      charStar(extraCommit),
      extraCommit.length,
      charStar(generator),
    ]
  );
  if (ret === 1) {
    const p = new Uint8Array(
      Module.HEAPU8.subarray(proof, proof + Module.getValue(plen, 'i64'))
    );
    freeMalloc();
    return Buffer.from(p);
  } else {
    freeMalloc();
    throw new Error('secp256k1_rangeproof_sign', ret);
  }
}

/**
 *  @typedef {ProofInfo}
 *  @property {number} exp - Exponent used in the proof (-1 means the value isn't private).
 *  @property {string} mantissa - Number of bits covered by the proof.
 *  @property {string} minValue - minimum value that commit could have.
 *  @property {string} maxValue - maximum value that commit could have.
 */
/**
 *  @summary Returns value info from a range-proof.
 *  @return {ProofInfo} Information successfully extracted.
 *  @throws {Error} Decode failed.
 *  @arg {Array} proof - range-proof.
 *  @exports
 */
function info(proof) {
  if (!proof || !Buffer.isBuffer(proof) || !proof.length)
    throw new TypeError('proof must be a non empty Buffer');

  const exp = charStar(4);
  const mantissa = charStar(4);
  const min = charStar(8);
  const max = charStar(8);
  const ret = Module.ccall(
    'rangeproof_info',
    'number',
    ['number', 'number', 'number', 'number', 'number', 'number'],
    [exp, mantissa, min, max, charStar(proof), proof.length]
  );

  if (ret === 1) {
    const res = {
      exp: Module.getValue(exp, 'i32'),
      mantissa: Module.getValue(mantissa, 'i32'),
      minValue: Uint64Long(min).toString(),
      maxValue: Uint64Long(max).toString(),
    };
    freeMalloc();
    return res;
  } else {
    freeMalloc();
    throw new Error('secp256k1_rangeproof_info decode failed', ret);
  }
}

/**
 *  @summary Verifies a range-proof.
 *  @return {boolean} Proof successfully verified.
 *  @arg {Array} commitment - 33-byte commitment.
 *  @arg {Array} proof - range proof to verify.
 *  @arg {Array} generator - 64-byte generator used for the proof.
 *  @arg {Array} extraCommit - extra data used for the proof.
 */
function verify(commitment, proof, generator, extraCommit = []) {
  if (!commit || !Buffer.isBuffer(commitment) || commitment.length !== 33)
    throw new TypeError('commit must be a Buffer of 33 bytes');
  if (!proof || !Buffer.isBuffer(proof) || !proof.length)
    throw new TypeError('proof must be a non empty Buffer');
  if (!generator || !Buffer.isBuffer(generator) || generator.length !== 64)
    throw new TypeError('generator must be a Buffer of 64 bytes');
  if (!extraCommit || !Buffer.isBuffer(extraCommit))
    throw new TypeError('extraCommit must be a Buffer');

  const min = charStar(8);
  const max = charStar(8);
  const ret = Module.ccall(
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
      charStar(commitment),
      charStar(proof),
      proof.length,
      charStar(extraCommit),
      extraCommit.length,
      charStar(generator),
    ]
  );
  freeMalloc();
  return ret === 1;
}

/**
 *  @typedef {ProofRewind}
 *  @property {Array} blind - 32-byte blinding factor used by commit.
 *  @property {string} value - unblinded value.
 *  @property {string} minValue - minimum value that commit could have.
 *  @property {string} maxValue - maximum value that commit could have.
 *  @property {Array} message - 32-byte unblinded message.
 */
/**
 *  @summary Extracts information from a range-proof.
 *  @return {ProofRewind} Information successfully extracted.
 *  @throws {Error} Decode failed.
 *  @arg {Array} commitment - 33-byte array with the commitment being proved.
 *  @arg {Array} proof - range-proof.
 *  @arg {Array} nonce - 32-byte secret nonce used to initialize the proof.
 *  @arg {Array} generator - 64-byte generator for the proof.
 *  @arg {Array} extraCommit - extra data for range-proof.
 */
function rewind(commitment, proof, nonce, generator, extraCommit = []) {
  if (!commitment || !Buffer.isBuffer(commitment) || !commitment.length)
    throw new TypeError('commit must be a non empty Buffer');
  if (!proof || !Buffer.isBuffer(proof) || !proof.length)
    throw new TypeError('proof must be a non empty Buffer');
  if (!nonce || !Buffer.isBuffer(nonce) || !nonce.length)
    throw new TypeError('nonce must be a non empty Buffer');
  if (!generator || !Buffer.isBuffer(generator) || generator.length !== 64)
    throw new TypeError('generator must be a Buffer of 64 bytes');
  if (!extraCommit || !Buffer.isBuffer(extraCommit))
    throw new TypeError('extraCommit must be a Buffer');
  const blind = malloc(32);
  const value = malloc(8);
  const message = malloc(64);
  const messageLength = malloc(8);
  const minValue = malloc(8);
  const maxValue = malloc(8);
  Module.setValue(messageLength, 64, 'i64');

  const ret = Module.ccall(
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
      message,
      messageLength,
      charStar(nonce),
      minValue,
      maxValue,
      charStar(commitment),
      charStar(proof),
      proof.length,
      charStar(extraCommit),
      extraCommit.length,
      charStar(generator),
    ]
  );

  if (ret === 1) {
    const bf = new Uint8Array(Module.HEAPU8.subarray(blind, blind + 32));
    const msg = new Uint8Array(
      Module.HEAPU8.subarray(
        message,
        message + Module.getValue(messageLength, 'i64')
      )
    );
    const out = {
      value: Uint64Long(value).toString(),
      minValue: Uint64Long(minValue).toString(),
      maxValue: Uint64Long(maxValue).toString(),
      blindFactor: Buffer.from(bf),
      message: Buffer.from(msg),
    };
    freeMalloc();
    return out;
  } else {
    freeMalloc();
    throw new Error('secp256k1_rangeproof_rewind', ret);
  }
}

/**
 *  @typedef {SurjectionProof}
 *  @property {number} nInputs - number of input tags used to generate the proof.
 *  @property {Array} usedInputs - 32-byte inputs bitmap.
 *  @property {Array} data - 8224-byte proof data.
 */
/**
 *  @summary Serializes a surjection proof.
 *  @return {Array} Serialized surjection proof without leading zeros.
 *  @throws {Error} Decode failed.
 *  @arg {SurjectionProof} proof - proof to serialize.
 */
function proofSerialize(proof) {
  if (
    !proof ||
    proof.nInputs === undefined ||
    proof.nInputs === null ||
    !proof.usedInputs ||
    !Buffer.isBuffer(proof.usedInputs) ||
    proof.usedInputs.length != 32 ||
    !proof.data ||
    !Buffer.isBuffer(proof.data)
  )
    throw new TypeError(
      'proof must be an object with nInputs of type number and data,' +
        'usedInputs of type Buffer'
    );
  const output = malloc(8258);
  const outputLength = malloc(8);
  Module.setValue(outputLength, 8258, 'i64');
  const ret = Module.ccall(
    'surjectionproof_serialize',
    'number',
    ['number', 'number', 'number', 'number', 'number'],
    [
      output,
      outputLength,
      intStar(proof.nInputs),
      charStar(proof.usedInputs),
      charStar(proof.data),
    ]
  );
  if (ret === 1) {
    const out = new Uint8Array(
      Module.HEAPU8.subarray(
        output,
        output + Module.getValue(outputLength, 'i64')
      )
    );
    freeMalloc();
    return Buffer.from(out);
  } else {
    freeMalloc();
    throw new Error('secp256k1_surjectionproof_serialize', ret);
  }
}

/**
 *  @summary Returns an initialized surjection proof.
 *  @return {SurjectionProof} Proof successfully computed.
 *  @throws {Error} Decode failed.
 *  @arg {Array} inputTags - Array of 32-byte input tags.
 *  @arg {number} inputTagsToUse - The number of inputs to include in the surjection proof.
 *  @arg {Array} outputTag - 32-byte output tag.
 *  @arg {number} maxIterations - Max number of attemoots to compute the proof.
 *  @arg {Array} seed - 32-byte random seed.
 */
function proofInitialize(
  inputTags,
  inputTagsToUse,
  outputTag,
  maxIterations,
  seed
) {
  if (
    !inputTags ||
    !Array.isArray(inputTags) ||
    !inputTags.length ||
    !inputTags.every((t) => t.length === 32)
  )
    throw new TypeError(
      'inputTags must be a non empty array of Buffers of 32 bytes'
    );
  if (!outputTag || !Buffer.isBuffer(outputTag) || outputTag.length !== 32)
    throw new TypeError('outputTag must be a Buffer of 32 bytes');
  if (!seed || !Buffer.isBuffer(seed) || seed.length !== 32)
    throw new TypeError('seed must be a Buffer of 32 bytes');

  const nInputs = malloc(4);
  const usedInputs = malloc(32);
  const data = malloc(8224);
  const inputIndex = malloc(4);
  const ret = Module.ccall(
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
      'number',
    ],
    [
      nInputs,
      usedInputs,
      data,
      inputIndex,
      charStarArray(inputTags),
      inputTags.length,
      inputTagsToUse,
      charStar(outputTag),
      maxIterations,
      charStar(seed),
    ]
  );
  if (ret > 0) {
    const usedIns = new Uint8Array(
      Module.HEAPU8.subarray(usedInputs, usedInputs + 32)
    );
    const d = new Uint8Array(Module.HEAPU8.subarray(data, data + 8224));
    const out = {
      proof: {
        nInputs: Module.getValue(nInputs, 'i32'),
        usedInputs: Buffer.from(usedIns),
        data: Buffer.from(d),
      },
      inputIndex: Module.getValue(inputIndex, 'i32'),
    };
    freeMalloc();
    return out;
  } else {
    freeMalloc();
    throw new Error('secp256k1_surjectionproof_initialize', ret);
  }
}

/**
 *  @summary Generates a surjection proof.
 *  @return {SurjectionProof} Proof successfully computed.
 *  @throws {Error} Decode failed.
 *  @arg {SurjectionProof} proof - Initialized surjection proof.
 *  @arg {Array} inputTags - Array of 64-byte ephemeral input tags.
 *  @arg {Array} outputTag - 64-byte ephemeral output tag.
 *  @arg {number} inputIndex - Proof input index.
 *  @arg {Array} inputBlindingKey - 32-byte blinding key for the input tags.
 *  @arg {Array} outputBlindingKey - 32-byte blinding key for the output tag.
 */
function proofGenerate(
  proof,
  inputTags,
  outputTag,
  inputIndex,
  inputBlindingKey,
  outputBlindingKey
) {
  if (
    !proof ||
    proof.nInputs === undefined ||
    proof.nInputs === null ||
    !proof.usedInputs ||
    !Buffer.isBuffer(proof.usedInputs) ||
    proof.usedInputs.length != 32 ||
    !proof.data ||
    !Buffer.isBuffer(proof.data)
  )
    throw new TypeError(
      'proof must be an object with nInputs of type number and data,' +
        'usedInputs of type Buffer'
    );
  if (
    !inputTags ||
    !Array.isArray(inputTags) ||
    !inputTags.length ||
    !inputTags.every((t) => t.length === 64)
  )
    throw new TypeError(
      'inputTags must be a non empty array of Buffers of 64 bytes'
    );
  if (!outputTag || !Buffer.isBuffer(outputTag) || outputTag.length !== 64)
    throw new TypeError('ouputTag must be a Buffer of 64 bytes');
  if (
    !inputBlindingKey ||
    !Buffer.isBuffer(inputBlindingKey) ||
    inputBlindingKey.length !== 32
  )
    throw new TypeError('inputBlindingKey must be a Buffer of 32 bytes');
  if (
    !outputBlindingKey ||
    !Buffer.isBuffer(outputBlindingKey) ||
    outputBlindingKey.length !== 32
  )
    throw new TypeError('outputBlindingKey must be a Buffer of 32 bytes');
  if (inputIndex < 0 || inputIndex > inputTags.length)
    throw new TypeError(
      'inputIndex must be a number into range [0, ' + inputTags.length + ']'
    );
  const nInputs = intStar(proof.nInputs);
  const usedInputs = charStar(proof.usedInputs);
  const data = charStar(proof.data);
  const ret = Module.ccall(
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
    ],
    [
      nInputs,
      usedInputs,
      data,
      charStarArray(inputTags),
      inputTags.length,
      charStar(outputTag),
      inputIndex,
      charStar(inputBlindingKey),
      charStar(outputBlindingKey),
    ]
  );
  if (ret === 1) {
    const usedIns = new Uint8Array(
      Module.HEAPU8.subarray(usedInputs, usedInputs + 32)
    );
    const d = new Uint8Array(Module.HEAPU8.subarray(data, data + 8224));
    const p = {
      nInputs: inputTags.length,
      usedInputs: Buffer.from(usedIns),
      data: Buffer.from(d),
    };
    freeMalloc();
    return p;
  } else {
    freeMalloc();
    throw new Error('secp256k1_surjectionproof_generate', ret);
  }
}

/**
 *  @summary Verifies a surjection proof.
 *  @return {boolean} Proof successfully verified.
 *  @throws {Error} Decode failed.
 *  @arg {SurjectionProof} proof - proof to verify.
 *  @arg {Array} inputTags - Array of 64-byte ephemeral input tags.
 *  @arg {Array} outputTags - 64-byte ephemeral output tags.
 */
function proofVerify(proof, inputTags, outputTag) {
  if (
    !inputTags ||
    !Array.isArray(inputTags) ||
    !inputTags.length ||
    !inputTags.every((t) => t.length === 64)
  )
    throw new TypeError(
      'inputTags must be a non empty array of Buffers of 64 bytes'
    );
  if (!outputTag || !Buffer.isBuffer(outputTag) || outputTag.length !== 64)
    throw new TypeError('ouputTag must be a Buffer of 64 bytes');
  const ret = Module.ccall(
    'surjectionproof_verify',
    'number',
    ['number', 'number', 'number', 'number', 'number', 'number'],
    [
      intStar(proof.nInputs),
      charStar(proof.usedInputs),
      charStar(proof.data),
      charStarArray(inputTags),
      inputTags.length,
      charStar(outputTag),
    ]
  );
  freeMalloc();
  return ret === 1;
}

function Uint64Long(ptr) {
  return new Long(
    Module.getValue(ptr, 'i32'),
    Module.getValue(ptr + 4, 'i32'),
    true
  );
}

function intStar(num) {
  const ptr = malloc(4);
  Module.setValue(ptr, num, 'i32');
  return ptr;
}

function charStar(buf) {
  const ptr = malloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    Module.setValue(ptr + i, buf[i], 'i8');
  }
  return ptr;
}

function charStarArray(array) {
  const arrayPtrs = malloc(4 * array.length);
  for (let i = 0; i < array.length; i++) {
    const ptr = charStar(array[i]);
    Module.setValue(arrayPtrs + i * 4, ptr, 'i32');
  }
  return arrayPtrs;
}

function longIntStarArray(array) {
  const ptr = malloc(8 * array.length);
  for (let i = 0; i < array.length; i++) {
    Module.setValue(ptr + i * 8, array[i].low, 'i32');
    Module.setValue(ptr + i * 8 + 4, array[i].high, 'i32');
  }
  return ptr;
}

let free = [];

function malloc(size) {
  const ptr = Module._malloc(size);
  free.push(ptr);
  return ptr;
}

function freeMalloc() {
  for (const ptr of free) {
    Module._free(ptr);
  }
  free = [];
}
