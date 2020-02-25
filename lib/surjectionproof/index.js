/** @module secp256k1.surjectionproof */
const Module = require("../../src");
const {
  malloc,
  freeMalloc,
  intStar,
  charStar,
  charStarArray
} = require("../MemUtils");

module.exports = {
  verify,
  generate,
  serialize,
  initialize
};

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
function serialize(proof) {
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
      "proof must be an object with nInputs of type number and data, usedInputs of type Buffer"
    );
  const output = malloc(8258);
  const outputLength = malloc(8);
  Module.setValue(outputLength, 8258, "i64");
  const ret = Module.ccall(
    "surjectionproof_serialize",
    "number",
    ["number", "number", "number", "number", "number"],
    [
      output,
      outputLength,
      intStar(proof.nInputs),
      charStar(proof.usedInputs),
      charStar(proof.data)
    ]
  );
  if (ret === 1) {
    const out = new Uint8Array(
      Module.HEAPU8.subarray(
        output,
        output + Module.getValue(outputLength, "i64")
      )
    );
    freeMalloc();
    return Buffer.from(out);
  } else {
    freeMalloc();
    throw new Error("secp256k1_surjectionproof_serialize", ret);
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
function initialize(inputTags, inputTagsToUse, outputTag, maxIterations, seed) {
  if (
    !inputTags ||
    !Array.isArray(inputTags) ||
    !inputTags.length ||
    !inputTags.every(t => t.length === 32)
  )
    throw new TypeError(
      "inputTags must be a non empty array of Buffers of 32 bytes"
    );
  if (!outputTag || !Buffer.isBuffer(outputTag) || outputTag.length !== 32)
    throw new TypeError("outputTag must be a Buffer of 32 bytes");
  if (!seed || !Buffer.isBuffer(seed) || seed.length !== 32)
    throw new TypeError("seed must be a Buffer of 32 bytes");

  const nInputs = malloc(4);
  const usedInputs = malloc(32);
  const data = malloc(8224);
  const inputIndex = malloc(4);
  const ret = Module.ccall(
    "surjectionproof_initialize",
    "number",
    [
      "number",
      "number",
      "number",
      "number",
      "number",
      "number",
      "number",
      "number",
      "number",
      "number"
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
      charStar(seed)
    ]
  );
  if (ret > 0) {
    const usedIns = new Uint8Array(
      Module.HEAPU8.subarray(usedInputs, usedInputs + 32)
    );
    const d = new Uint8Array(Module.HEAPU8.subarray(data, data + 8224));
    const out = {
      proof: {
        nInputs: Module.getValue(nInputs, "i32"),
        usedInputs: Buffer.from(usedIns),
        data: Buffer.from(d)
      },
      inputIndex: Module.getValue(inputIndex, "i32")
    };
    freeMalloc();
    return out;
  } else {
    freeMalloc();
    throw new Error("secp256k1_surjectionproof_initialize", ret);
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
function generate(
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
      "proof must be an object with nInputs of type number and data, usedInputs of type Buffer"
    );
  if (
    !inputTags ||
    !Array.isArray(inputTags) ||
    !inputTags.length ||
    !inputTags.every(t => t.length === 64)
  )
    throw new TypeError(
      "inputTags must be a non empty array of Buffers of 64 bytes"
    );
  if (!outputTag || !Buffer.isBuffer(outputTag) || outputTag.length !== 64)
    throw new TypeError("ouputTag must be a Buffer of 64 bytes");
  if (
    !inputBlindingKey ||
    !Buffer.isBuffer(inputBlindingKey) ||
    inputBlindingKey.length !== 32
  )
    throw new TypeError("inputBlindingKey must be a Buffer of 32 bytes");
  if (
    !outputBlindingKey ||
    !Buffer.isBuffer(outputBlindingKey) ||
    outputBlindingKey.length !== 32
  )
    throw new TypeError("outputBlindingKey must be a Buffer of 32 bytes");
  if (inputIndex < 0 || inputIndex > inputTags.length)
    throw new TypeError(
      "inputIndex must be a number into range [0, " + inputTags.length + "]"
    );
  const nInputs = intStar(proof.nInputs);
  const usedInputs = charStar(proof.usedInputs);
  const data = charStar(proof.data);
  const ret = Module.ccall(
    "surjectionproof_generate",
    "number",
    [
      "number",
      "number",
      "number",
      "number",
      "number",
      "number",
      "number",
      "number",
      "number"
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
      charStar(outputBlindingKey)
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
      data: Buffer.from(d)
    };
    freeMalloc();
    return p;
  } else {
    freeMalloc();
    throw new Error("secp256k1_surjectionproof_generate", ret);
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
function verify(proof, inputTags, outputTag) {
  if (
    !inputTags ||
    !Array.isArray(inputTags) ||
    !inputTags.length ||
    !inputTags.every(t => t.length === 64)
  )
    throw new TypeError(
      "inputTags must be a non empty array of Buffers of 64 bytes"
    );
  if (!outputTag || !Buffer.isBuffer(outputTag) || outputTag.length !== 64)
    throw new TypeError("ouputTag must be a Buffer of 64 bytes");
  const ret = Module.ccall(
    "surjectionproof_verify",
    "number",
    ["number", "number", "number", "number", "number", "number"],
    [
      intStar(proof.nInputs),
      charStar(proof.usedInputs),
      charStar(proof.data),
      charStarArray(inputTags),
      inputTags.length,
      charStar(outputTag)
    ]
  );
  freeMalloc();
  return ret === 1;
}
