/** @module secp256k1.surjectionproof */
const Module = require("../libsecp256k1");
const {
  malloc,
  freeMalloc,
  intStar,
  charStar,
  charStarArray
} = require("../MemUtils");

module.exports = {
  parse,
  verify,
  generate,
  serialize,
  initialize,
};

function parse(input) {
  const nInputs = 0;
  const usedInputs = malloc(32);
  const data = malloc(8224);
  const ret = Module.call(
    "surjectionproof_parse",
    "number",
    ["number", "number", "number", "number", "number"],
    [nInputs, usedInputs, data, charStar(input), input.length]
  );
  if (ret === 1) {
    const proof = {
      nInputs: Module.getValue(nInputs, "i32"),
      usedInputs: Uint8Array(
        Module.HEAPU8.subarray(usedInputs, usedInputs + 32)
      ),
      data: Uint8Array(Module.HEAPU8.subarray(data, data + 32))
    };
    freeMalloc();
    return proof;
  } else {
    freeMalloc();
    throw new Error("secp256k1_surjectionproof_parse", ret);
  }
}

function serialize(proof) {
  const output = malloc(8258);
  const outputlen = malloc(4);
  const ret = Module.ccall(
    "surjectionproof_serialize",
    "number",
    ["number", "number", "number", "number", "number"],
    [
      output,
      outputlen,
      intStar(proof.nInputs),
      charStar(proof.usedInputs),
      charStar(proof.data)
    ]
  );
  if (ret === 1) {
    const out = Uint8Array(
      Module.HEAPU8.subarray(
        outputlen,
        outputlen + Module.getValue(outputlen, "i32")
      )
    );
    freeMalloc();
    return out;
  } else {
    freeMalloc();
    throw new Error("secp256k1_surjectionproof_serialize", ret);
  }
}

function initialize(
  inTags,
  inTagsToUse,
  outTag,
  maxIterations,
  seed
) {
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
      charStarArray(inTags),
      inTags.length,
      inTagsToUse,
      charStar(outTag),
      maxIterations,
      charStar(seed)
    ]
  );
  if (ret === 1) {
    const out = {
      proof: {
        nInputs: Module.getValue(nInputs, "i32"),
        usedInputs: new Uint8Array(
          Module.HEAPU8.subarray(usedInputs, usedInputs + 32)
        ),
        data: new Uint8Array(Module.HEAPU8.subarray(data, data + 8224))
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

function generate(
  proof,
  inTags,
  outTag,
  inIndex,
  inBlindingKey,
  outBlindingKey
) {
  const cProof = {};
  Object.assign(cProof, proof);
  const nInputs = intStar(cProof.nInputs);
  const usedInputs = charStar(cProof.usedInputs);
  const data = charStar(cProof.data);
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
      charStarArray(inTags),
      inTags.length,
      charStar(outTag),
      inIndex,
      charStar(inBlindingKey),
      charStar(outBlindingKey)
    ]
  );
  if (ret === 1) {
    const p = {
      nInputs: inTags.length,
      usedInputs: new Uint8Array(
        Module.HEAPU8.subarray(usedInputs, usedInputs + 32)
      ),
      data: new Uint8Array(Module.HEAPU8.subarray(data, data + 8224))
    };
    freeMalloc();
    return p;
  } else {
    freeMalloc();
    throw new Error("secp256k1_surjectionproof_generate", ret);
  }
}

function verify(proof, inTags, outTag) {
  const ret = Module.ccall(
    "surjectionproof_verify",
    "number",
    ["number", "number", "number", "number", "number", "number"],
    [
      intStar(proof.nInputs),
      charStar(proof.usedInputs),
      charStar(proof.data),
      charStarArray(inTags),
      inTags.length,
      charStar(outTag)
    ]
  );
  freeMalloc();
  return ret === 1;
}
