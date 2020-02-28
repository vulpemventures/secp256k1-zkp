/** @module secp256k1.generator */
const Module = require("../../src");
const { malloc, freeMalloc, charStar } = require("../MemUtils");

module.exports = {
  generateBlinded,
  parse,
  serialize
};

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
    throw new TypeError("key must be a Buffer of 32 bytes");
  if (!blind || !Buffer.isBuffer(blind) || blind.length !== 32)
    throw new TypeError("blind must be a Buffer of 32 bytes");

  const output = malloc(64);

  const ret = Module.ccall(
    "generator_generate_blinded",
    "number",
    ["number", "number", "number"],
    [output, charStar(key), charStar(blind)]
  );
  if (ret === 1) {
    const out = new Uint8Array(Module.HEAPU8.subarray(output, output + 64));
    freeMalloc();
    return Buffer.from(out);
  } else {
    freeMalloc();
    throw new Error("secp256k1_generator_generate_blinded", ret);
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
    throw new TypeError("input must be a Buffer of 32 bytes");
  
  const gen = malloc(64);

  const ret = Module.ccall(
    "generator_parse",
    "number",
    ["number", "number"],
    [gen, charStar(input)]
  );
  if (ret === 1) {
    const out = new Uint8Array(Module.HEAPU8.subarray(gen, gen + 64));
    freeMalloc();
    return Buffer.from(out);
  } else {
    freeMalloc();
    throw new Error("secp256k1_generator_parse", ret);
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
    throw new TypeError("generator must be a Buffer of 32 bytes");

  const output = malloc(33);
  const ret = Module.ccall(
    "generator_serialize",
    "number",
    ["number", "number"],
    [output, charStar(generator)]
  );
  if (ret === 1) {
    const out = new Uint8Array(Module.HEAPU8.subarray(output, output + 33));
    freeMalloc();
    return Buffer.from(out);
  } else {
    freeMalloc();
    throw new Error("secp256k1_generator_parse", ret);
  }
}
