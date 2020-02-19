/** @module secp256k1.rangeproof */
const Long = require("long");
const Module = require("../libsecp256k1");
const {
  malloc,
  freeMalloc,
  charStar,
  Uint64Long
} = require("../MemUtils");

module.exports = {
  sign,
  info,
  verify,
  rewind
};

/** 
 *  @summary Author a proof that a committed value is within a range.
 *  @return {Array} Proof successfully created.
 *  @throws {Error} Decode failed.
 *  @arg {Array} commit: 33-byte array with the commitment being proved.
 *  @arg {Array} blind: 32-byte blinding factor used by commit.
 *  @arg {Array} nonce: 32-byte secret nonce used to initialize the proof (value can be reverse-engineered out of the proof if this secret is known.).
 *  @arg {number} actualValue:  Actual value of the commitment.
 *  @arg {number} minValue: constructs a proof where the verifer can tell the minimum value is at least the specified amount.
 *  @arg {number} base10Exp: Base-10 exponent. Digits below above will be made public, but the proof will be made smaller. Allowed range is -1 to 18.
 *      (-1 is a special case that makes the value public. 0 is the most private.).
 *  @arg {number} minBits: Number of bits of the value to keep private. (0 = auto/minimal, - 64).
 *  @exports
 */
function sign(
  commit,
  blind,
  nonce,
  actualValue,
  minValue = 0,
  base10Exp = 0,
  minBits = 0,
  message = null,
  extraData = null
) {
  // In/out: proof - array to receive the proof, can be up to 5134 bytes. (cannot be NULL)
  const proof = malloc(5134);
  // In/out: plen - point to an integer with the size of the proof buffer and the size of the constructed proof.
  const plen = charStar(8);
  Module.setValue(plen, 5134, "i64");

  const minValueLong = Long.fromString(String(minValue), true);
  const actualValueLong = Long.fromString(String(actualValue), true);
  const msg = message ? charStar(message) : charStar([]);
  const msgLength = message ? message.length : 0;
  const data = extraData ? charStar(extraData) : charStar([]);
  const dataLength = extraData ? extraData.length : 0;

  const ret = Module.ccall(
    "rangeproof_sign",
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
      "number",
      "number",
      "number",
      "number"
    ],
    [
      proof,
      plen,
      minValueLong.low,
      minValueLong.high,
      charStar(commit),
      charStar(blind),
      charStar(nonce),
      base10Exp,
      minBits,
      actualValueLong.low,
      actualValueLong.high,
      msg,
      msgLength,
      data,
      dataLength
    ]
  );
  if (ret === 1) {
    const p = new Uint8Array(
      Module.HEAPU8.subarray(proof, proof + Module.getValue(plen, "i64"))
    );
    freeMalloc();
    return p;
  } else {
    freeMalloc();
    throw new Error("secp256k1_rangeproof_sign", ret);
  }
}

/**
 *  @typedef {ProofInfo}
 *  @property {number} exp - Exponent used in the proof (-1 means the value isn't private).
 *  @property {number} mantissa - Number of bits covered by the proof.
 *  @property {number} min - minimum value that commit could have.
 *  @property {number} max - maximum value that commit could have.
 */
/** 
 *  @summary Return value info from a range-proof.
 *  @return {ProofInfo} 1: Information successfully extracted.
 *  @throws {Error} Decode failed.
 *  @arg {Array} proof - range-proof.
 *  @exports
 */
function info(proof) {
  const exp = charStar(4);
  const mantissa = charStar(4);
  const min = charStar(8);
  const max = charStar(8);
  const ret = Module.ccall(
    "rangeproof_info",
    "number",
    ["number", "number", "number", "number", "number", "number"],
    [exp, mantissa, min, max, charStar(proof), proof.length]
  );

  if (ret === 1) {
    const res = {
      exp: Module.getValue(exp, "i32"),
      mantissa: Module.getValue(mantissa, "i32"),
      min: Uint64Long(min).toString(),
      max: Uint64Long(max).toString()
    };
    freeMalloc();
    return res;
  } else {
    freeMalloc();
    throw new Error("secp256k1_rangeproof_info decode failed", ret);
  }
}

/** 
 *  @summary Verify a range-proof.
 *  @return {boolean} 1: Proof successfully verified.
 *  @arg {Array} commitment
 *  @arg {Array} proof
 *  @arg {Array} extraData
 */
function verify(commitment, proof, extraData = []) {
  const min = charStar(8);
  const max = charStar(8);
  const ret = Module.ccall(
    "rangeproof_verify",
    "number",
    ["number", "number", "number", "number", "number", "number", "number"],
    [
      min,
      max,
      charStar(commitment),
      charStar(proof),
      proof.length,
      charStar(extraData),
      extraData.length
    ]
  );
  freeMalloc();
  return ret === 1;
}

/**
 *  @typedef {ProofRewind}
 *  @property {Array} blind - 32-byte blinding factor used by commit.
 *  @property {number} value - unblinded value
 *  @property {number} minValue - minimum value that commit could have
 *  @property {number} maxValue - maximum value that commit could have
 *  @property {Array} message - 32-byte unblinded message
*/
/** 
 *  @summary Extract information from a range-proof.
 *  @return {ProofRewind} 1: Information successfully extracted.
 *  @throws {Error} Decode failed.
 *  @arg {Array} commit - 33-byte array with the commitment being proved.
 *  @arg {Array} proof - range-proof.
 *  @arg {Array} nonce - 32-byte secret nonce used to initialize the proof.
 *  @arg {Array} extraData - extra data for range-proof.
 */
function rewind(commit, proof, nonce, extraData = []) {
  const blind = malloc(32);
  const value = charStar(8);
  const message = malloc(4096);
  const messageLength = charStar(8);
  const minValue = charStar(8);
  const maxValue = charStar(8);

  const ret = Module.ccall(
    "rangeproof_rewind",
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
      "number",
      "number",
      "number"
    ],
    [
      blind,
      value,
      message,
      messageLength,
      charStar(nonce),
      minValue,
      maxValue,
      charStar(commit),
      charStar(proof),
      proof.length,
      charStar(extraData),
      extraData.length
    ]
  );

  if (ret === 1) {
    const out = {
      value: Uint64Long(value).toString(),
      minValue: Uint64Long(minValue).toString(),
      maxValue: Uint64Long(maxValue).toString(),
      blind: new Uint8Array(Module.HEAPU8.subarray(blind, blind + 32)),
      message: new Uint8Array(
        Module.HEAPU8.subarray(
          message,
          message + Module.getValue(messageLength, "i32")
        )
      )
    };
    freeMalloc();
    return out;
  } else {
    freeMalloc();
    throw new Error("secp256k1_rangeproof_rewind", ret);
  }
}
