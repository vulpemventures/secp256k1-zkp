/** @module secp256k1.pedersen */
const Long = require("long");
const Module = require("../libsecp256k1");
const { malloc, freeMalloc, charStar, charStarArray } = require("../MemUtils");

module.exports = {
  commit,
  commitSerialize,
  commitParse,
  blindSum,
  verifySum
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
  if (!blindFactor || blindFactor.length !== 32)
    throw new TypeError("blindFactor is a required 32 byte array");

  const commitment = malloc(33);
  const valueLong = Long.fromString(String(value), true);

  const ret = Module.ccall(
    "pedersen_commit",
    "number",
    ["number", "number", "number"],
    [commitment, charStar(blindFactor), valueLong]
  );
  if (ret === 1) {
    const cmt = new Uint8Array(
      Module.HEAPU8.subarray(commitment, commitment + 33)
    );
    freeMalloc();
    return cmt;
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
    return cmt;
  } else {
    freeMalloc();
    throw new Error("secp256k1_pedersen_commit", ret);
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
    return cmt;
  } else {
    freeMalloc();
    throw new Error("secp256k1_pedersen_commit", ret);
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
  const sum = malloc(32);
  const ret = Module.ccall(
    "pedersen_blind_sum",
    "number",
    ["number", "number", "number", "number"],
    [sum, charStarArray(blinds), blinds.length, nneg]
  );
  if (ret === 1) {
    const s = new Uint8Array(Module.HEAPU8.subarray(sum, sum + 32));
    freeMalloc();
    return s;
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
