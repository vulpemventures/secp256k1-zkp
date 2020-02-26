/** @module secp256k1.rangeproof */
const Long = require("long");
const Module = require("../../src");
const { malloc, freeMalloc, charStar, Uint64Long } = require("../MemUtils");

module.exports = {
  sign,
  info,
  verify,
  rewind
};

/**
 *  @summary Authors a proof that a committed value is within a range.
 *  @return {Array} Proof successfully created.
 *  @throws {Error} Decode failed.
 *  @arg {Array} commit: 33-byte array with the commitment being proved.
 *  @arg {Array} blind: 32-byte blinding factor used by commit.
 *  @arg {Array} nonce: 32-byte secret nonce used to initialize the proof (value can be reverse-engineered out of the proof if this secret is known.).
 *  @arg {string} value: unblinded value.
 *  @arg {string} minValue: constructs a proof where the verifer can tell the minimum value is at least the specified amount.
 *  @arg {number} base10Exp: Base-10 exponent. Digits below above will be made public, but the proof will be made smaller. Allowed range is -1 to 18.
 *      (-1 is a special case that makes the value public. 0 is the most private.).
 *  @arg {number} minBits: Number of bits of the value to keep private. (0 = auto/minimal, - 64).
 *  @arg {Array} message: optional message.
 *  @arg {Array} extraCommit: optional extra commit.
 *  @exports
 */
function sign(
  commit,
  blind,
  nonce,
  value,
  minValue = "0",
  base10Exp = 0,
  minBits = 0,
  message = [],
  extraCommit = []
) {
  if (!commit || !Buffer.isBuffer(commit) || commit.length !== 33)
    throw new TypeError("commit must be a Buffer of 33 bytes");
  if (!blind || !Buffer.isBuffer(blind) || blind.length !== 32)
    throw new TypeError("blind must be a Buffer of 32 bytes");
  if (!nonce || !Buffer.isBuffer(nonce) || nonce.length !== 33)
    throw new TypeError("nonce must be a Buffer of 33 bytes");
  if (!message || !Buffer.isBuffer(message))
    throw new TypeError("message must be a Buffer");
  if (!extraCommit || !Buffer.isBuffer(extraCommit))
    throw new TypeError("extraCommit must be a Buffer");

  const proof = malloc(5134);
  const plen = malloc(8);
  Module.setValue(plen, 5134, "i64");
  const minValueLong = Long.fromString(minValue, true);
  const valueLong = Long.fromString(value, true);

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
      valueLong.low,
      valueLong.high,
      charStar(message),
      message.length,
      charStar(extraCommit),
      extraCommit.length
    ]
  );
  if (ret === 1) {
    const p = new Uint8Array(
      Module.HEAPU8.subarray(proof, proof + Module.getValue(plen, "i64"))
    );
    freeMalloc();
    return Buffer.from(p);
  } else {
    freeMalloc();
    throw new Error("secp256k1_rangeproof_sign", ret);
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
    throw new TypeError("proof must be a non empty Buffer");

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
      minValue: Uint64Long(min).toString(),
      maxValue: Uint64Long(max).toString()
    };
    freeMalloc();
    return res;
  } else {
    freeMalloc();
    throw new Error("secp256k1_rangeproof_info decode failed", ret);
  }
}

/**
 *  @summary Verifies a range-proof.
 *  @return {boolean} Proof successfully verified.
 *  @arg {Array} commit.
 *  @arg {Array} proof.
 *  @arg {Array} extraData.
 */
function verify(commit, proof, extraCommit = []) {
  if (!commit || !Buffer.isBuffer(commit) || commit.length !== 33)
    throw new TypeError("commit must be a Buffer of 33 bytes");
  if (!proof || !Buffer.isBuffer(proof) || !proof.length)
    throw new TypeError("proof must be a non empty Buffer");
  if (!extraCommit || !Buffer.isBuffer(extraCommit))
    throw new TypeError("extraCommit must be a Buffer");
  
  const min = charStar(8);
  const max = charStar(8);
  const ret = Module.ccall(
    "rangeproof_verify",
    "number",
    ["number", "number", "number", "number", "number", "number", "number"],
    [
      min,
      max,
      charStar(commit),
      charStar(proof),
      proof.length,
      charStar(extraCommit),
      extraCommit.length
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
 *  @arg {Array} commit - 33-byte array with the commitment being proved.
 *  @arg {Array} proof - range-proof.
 *  @arg {Array} nonce - 32-byte secret nonce used to initialize the proof.
 *  @arg {Array} extraCommit - extra data for range-proof.
 */
function rewind(commit, proof, nonce, extraCommit = []) {
  if (!commit || !Buffer.isBuffer(commit) || commit.length !== 33)
    throw new TypeError("commit must be a Buffer of 33 bytes");
  if (!proof || !Buffer.isBuffer(proof) || !proof.length)
    throw new TypeError("proof must be a non empty Buffer");
  if (!nonce || !Buffer.isBuffer(nonce) || nonce.length !== 33)
    throw new TypeError("nonce must be a Buffer of 33 bytes");
  if (!extraCommit || !Buffer.isBuffer(extraCommit))
    throw new TypeError("extraCommit must be a Buffer");
  const blind = malloc(32);
  const value = malloc(8);
  const message = malloc(64);
  const messageLength = malloc(8);
  const minValue = malloc(8);
  const maxValue = malloc(8);
  Module.setValue(messageLength, 64, "i64");

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
      charStar(extraCommit),
      extraCommit.length
    ]
  );

  if (ret === 1) {
    const bf = new Uint8Array(Module.HEAPU8.subarray(blind, blind + 32));
    const msg = new Uint8Array(
      Module.HEAPU8.subarray(
        message,
        message + Module.getValue(messageLength, "i64")
      )
    );
    const out = {
      value: Uint64Long(value).toString(),
      minValue: Uint64Long(minValue).toString(),
      maxValue: Uint64Long(maxValue).toString(),
      blindFactor: Buffer.from(bf),
      message: Buffer.from(msg)
    };
    freeMalloc();
    return out;
  } else {
    freeMalloc();
    throw new Error("secp256k1_rangeproof_rewind", ret);
  }
}
