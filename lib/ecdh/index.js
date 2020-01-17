/** @module secp256k1.ecdh */
const Module = require("../../src");
const { malloc, freeMalloc, charStar } = require("../MemUtils");

module.exports = {
  ecdh
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
    "ecdh",
    "number",
    ["number", "number", "number"],
    [output, charStar(pubkey), charStar(scalar)]
  );
  if (ret === 1) {
    const out = new Uint8Array(Module.HEAPU8.subarray(output, output + 32));
    freeMalloc();
    return Buffer.from(out);
  } else {
    freeMalloc();
    throw new Error("secp256k1_ecdh", ret);
  }
}
