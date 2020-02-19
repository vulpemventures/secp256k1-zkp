/** @module secp256k1.generator */
const Module = require("../libsecp256k1");
const { malloc, freeMalloc, charStar } = require("../MemUtils");

module.exports = {
  generateBlinded
};

function generateBlinded(input, blindingKey) {
  const output = malloc(64);

  const ret = Module.ccall(
    "generator_generate_blinded",
    "number",
    ["number", "number", "number"],
    [output, charStar(input), charStar(blindingKey)]
  );
  if (ret === 1) {
    const out = new Uint8Array(Module.HEAPU8.subarray(output, output + 64));
    freeMalloc();
    return out;
  } else {
    freeMalloc();
    throw new Error("secp256k1_generator_generate_blinded", ret);
  }
}
