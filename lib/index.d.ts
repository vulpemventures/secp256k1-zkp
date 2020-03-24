function ecdh(pubkey: Buffer, scalar: Buffer): Buffer;
function generateBlinded(key: Buffer, blind: Buffer): Buffer;
function parse(input: Buffer): Buffer;
function serialize(generator: Buffer): Buffer;
function commit(blindFactor: Buffer, value: string, generator: Buffer): Buffer;
function commitSerialize(commitment: Buffer): Buffer;
function commitParse(input: Buffer): Buffer;
function blindSum(blinds: Array<Buffer>, nneg?: number): Buffer;
function verifySum(
  commits: Array<Buffer>,
  negativeCommits: Array<Buffer>,
): boolean;
function blindGeneratorBlindSum(
  values: Array<string>,
  nInputs: number,
  blindGenerators: Array<Buffer>,
  blindFactors: Array<Buffer>,
): Buffer;
function info(
  proof: Buffer,
): { exp: number; mantissa: string; minValue: string; maxValue: string };
function verify(
  commit: Buffer,
  proof: Buffer,
  generator: Buffer,
  extraCommit?: Buffer,
): boolean;
function sign(
  commit: Buffer,
  blind: Buffer,
  nonce: Buffer,
  value: string,
  generator: Buffer,
  minValue?: string,
  base10Exp?: number,
  minBits?: number,
  message?: Buffer,
  extraCommit?: Buffer,
): Buffer;
function rewind(
  commit: Buffer,
  proof: Buffer,
  nonce: Buffer,
  generator: Buffer,
  extraCommit?: Buffer,
): {
  value: string;
  minValue: string;
  maxValue: string;
  blindFactor: Buffer;
  message: Buffer;
};
function proofSerialize(proof: {
  nInputs: number;
  usedInputs: Buffer;
  data: Buffer;
}): Buffer;
function proofInitialize(
  inputTags: Array<Buffer>,
  inputTagsToUse: number,
  outputTag: Buffer,
  maxIterations: number,
  seed: Buffer,
): {
  proof: { nInputs: number; usedInputs: Buffer; data: Buffer };
  inputIndex: number;
};
function proofGenerate(
  proof: { nInputs: number; usedInputs: Buffer; data: Buffer },
  inputTags: Array<Buffer>,
  outputTag: Buffer,
  inputIndex: number,
  inputBlindingKey: Buffer,
  outputBlindingKey: Buffer,
): { nInputs: number; usedInputs: Buffer; data: Buffer };
function proofVerify(
  proof: { nInputs: number; usedInputs: Buffer; data: Buffer },
  inputTags: Array<Buffer>,
  outputTag: Buffer,
): boolean;

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
