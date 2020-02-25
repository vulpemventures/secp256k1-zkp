/** @module secp256k1.pedersen */
const Long = require("long");
const Module = require("../../src");
const {
  malloc,
  freeMalloc,
  charStar,
  charStarArray,
} = require("../MemUtils");

module.exports = {
  commit,
  commitSerialize,
  commitParse,
  blindSum,
  verifySum,
  blindGeneratorBlindSum
};

/**
 *  @summary Generate a pedersen commitment.
 *  @return {Array} 33-bytes commitment successfully created.
 *  @throws {Error} - Decode error.
 *  @arg {Array} blindFactor - 32-byte blinding factor (cannot be NULL).
 *  @arg {uint64} value - unsigned 64-bit integer value to commit to.
 *  @exports
 */
function commit(blindFactor, value) {
  if (
    !blindFactor ||
    !Buffer.isBuffer(blindFactor) ||
    blindFactor.length !== 32
  )
    throw new TypeError("blindFactor must be a Buffer of 32 bytes");

  const commitment = malloc(33);
  const valueLong = Long.fromString(String(value), true);

  const ret = Module.ccall(
    "pedersen_commit",
    "number",
    ["number", "number", "number"],
    [commitment, charStar(blindFactor), valueLong.low, valueLong.high]
  );
  if (ret === 1) {
    const out = new Uint8Array(
      Module.HEAPU8.subarray(commitment, commitment + 33)
    );
    freeMalloc();
    return Buffer.from(out);
  } else {
    freeMalloc();
    throw new Error("secp256k1_pedersen_commit", ret);
  }
}

/**
 *  @summary Serialize a pedersen commitment.
 *  @return {Array} 33-bytes serialized pedersen commitment.
 *  @throws {Error} - Decode error.
 *  @arg {Array} commitment - 33-byte pedersen commitment (cannot be NULL).
 *  @exports
 */
function commitSerialize(commitment) {
  if (!commitment || !Buffer.isBuffer(commitment) || commitment.length !== 33)
    throw new TypeError("commitment must be a Buffer of 33 bytes");

  const out = malloc(33);

  const ret = Module.ccall(
    "pedersen_commitment_serialize",
    "number",
    ["number", "number"],
    [out, charStar(commitment)]
  );
  if (ret === 1) {
    const cmt = new Uint8Array(Module.HEAPU8.subarray(out, out + 33));
    freeMalloc();
    return Buffer.from(cmt);
  } else {
    freeMalloc();
    throw new Error("secp256k1_pedersen_commitment_serialize", ret);
  }
}

/**
 *  @summary Parse a pedersen commitment.
 *  @return {Array} 33-bytes pedersen commitment.
 *  @throws {Error} - Decode error.
 *  @arg {Array} input - 33-byte commitment to parse (cannot be NULL).
 *  @exports
 */
function commitParse(input) {
  if (!input || !Buffer.isBuffer(input) || input.length !== 33)
    throw new TypeError("input must be a Buffer of 33 bytes");

  const commitment = malloc(33);
  const ret = Module.ccall(
    "pedersen_commitment_parse",
    "number",
    ["number", "number"],
    [commitment, charStar(input)]
  );
  if (ret === 1) {
    const cmt = new Uint8Array(
      Module.HEAPU8.subarray(commitment, commitment + 33)
    );
    freeMalloc();
    return Buffer.from(cmt);
  } else {
    freeMalloc();
    throw new Error("secp256k1_pedersen_commitment_parse", ret);
  }
}

function blindGeneratorBlindSum(value, nInputs, blindGenerators, blindFactors) {
  if (!blindGenerators || !Array.isArray(blindGenerators) || !blindGenerators.length)
    throw new TypeError("blindGenerators must be a non empty array of Buffers");
  if (!blindFactors || !Array.isArray(blindFactors))
    throw new TypeError("blindFactors must be an array of Buffers");

  const blindOut = malloc(32);
  const val = Long.fromString(String(value), true);
  const ret = Module.ccall(
    "pedersen_blind_generator_blind_sum",
    "number",
    ["number", "number", "number", "number", "number", "number"],
    [
      val.low,
      val.high,
      charStarArray(blindGenerators),
      charStar(blindFactors),
      blindGenerators.length,
      nInputs,
      blindOut
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
    throw new Error("secp256k1_pedersen_blind_generator_blind_sum", ret);
  }
}

/**
 *  @summary Computes the sum of multiple positive and negative blinding factors.
 *  @return {Array} 32-bytes sum successfully computed.
 *  @throws {Error} Decode error.
 *  @arg {Array.<Array>} blinds - 32-byte character arrays for blinding factors.
 *  @arg {number} [nneg = 0] - how many of the initial factors should be treated with a negative sign.
 *  @exports
 */
function blindSum(blinds, nneg = 0) {
  if (!blinds || !Array.isArray(blinds) || !blinds.length)
    throw new TypeError("blinds must be a non empty array of Buffers");

  const sum = malloc(32);
  const ret = Module.ccall(
    "pedersen_blind_sum",
    "number",
    ["number", "number", "number", "number"],
    [sum, charStarArray(blinds), blinds.length, blinds.length - nneg]
  );
  if (ret === 1) {
    const s = new Uint8Array(Module.HEAPU8.subarray(sum, sum + 32));
    freeMalloc();
    return Buffer.from(s);
  } else {
    freeMalloc();
    throw new Error("secp256k1_pedersen_blind_sum", ret);
  }
}

/**
 * @summary Verify pedersen commitments - negativeCommits - excess === 0
 * @return {boolean} commitments successfully sum to zero.
 * @throws {Error} Commitments do not sum to zero or other error.
 * @arg {Array} commits: pointer to pointers to 33-byte character arrays for the commitments.
 * @arg {Array} ncommits: pointer to pointers to 33-byte character arrays for negative commitments.
 * @exports
 */
function verifySum(commits, negativeCommits) {
  if (!commits || !Array.isArray(commits) || !commits.every(c => c.length === 33))
    throw new TypeError("commits must be a non empty array of Buffers of 33 bytes");
  if (!negativeCommits || !Array.isArray(negativeCommits) || !negativeCommits.every(c => c.length === 33))
    throw new TypeError("negativeCommits must be a non empty array of Buffers of 33 bytes");
  const ret = Module.ccall(
    "pedersen_verify_tally",
    "number",
    ["number", "number", "number", "number"],
    [
      charStarArray(commits),
      commits.length,
      charStarArray(negativeCommits),
      negativeCommits.length
    ]
  );
  freeMalloc();
  return ret === 1;
}
