type Ecdh = (pubkey: Buffer, scalar: Buffer) => Buffer;

interface Ec {
  prvkeyNegate: (key: Buffer) => Buffer;
  prvkeyTweakAdd: (key: Buffer, tweak: Buffer) => Buffer;
  prvkeyTweakMul: (key: Buffer, tweak: Buffer) => Buffer;
}

interface Generator {
  generate: (seed: Buffer) => Buffer;
  generateBlinded(key: Buffer, blind: Buffer): Buffer;
  parse(input: Buffer): Buffer;
  serialize(generator: Buffer): Buffer;
}

interface Pedersen {
  commit(blindFactor: Buffer, value: string, generator: Buffer): Buffer;
  commitSerialize(commitment: Buffer): Buffer;
  commitParse(input: Buffer): Buffer;
  blindSum(blinds: Array<Buffer>, nneg?: number): Buffer;
  verifySum(
    commits: Array<Buffer>,
    negativeCommits: Array<Buffer>
  ): boolean;
  blindGeneratorBlindSum(values: Array<string>, nInputs: number, blindGenerators: Array<Buffer>, blindFactors: Array<Buffer>): Buffer;
}

interface RangeProof {
  info(
    proof: Buffer
  ): { exp: number; mantissa: string; minValue: string; maxValue: string };
  verify(
    commit: Buffer,
    proof: Buffer,
    generator: Buffer,
    extraCommit?: Buffer
  ): boolean;
  sign(
    commit: Buffer,
    blind: Buffer,
    nonce: Buffer,
    value: string,
    generator: Buffer,
    minValue?: string,
    base10Exp?: number,
    minBits?: number,
    message?: Buffer,
    extraCommit?: Buffer
  ): Buffer;
  rewind(
    commit: Buffer,
    proof: Buffer,
    nonce: Buffer,
    generator: Buffer,
    extraCommit?: Buffer
  ): {
    value: string;
    minValue: string;
    maxValue: string;
    blindFactor: Buffer;
    message: Buffer;
  };
}

interface SurjectionProof {
  serialize: (proof: {
    nInputs: number;
    usedInputs: Buffer;
    data: Buffer;
  }) => Buffer;
  parse: (proof: Buffer) => {
    nInputs: number;
    usedInputs: Buffer;
    data: Buffer;
  };
  initialize: (
    inputTags: Array<Buffer>,
    inputTagsToUse: number,
    outputTag: Buffer,
    maxIterations: number,
    seed: Buffer
  ) => {
    proof: { nInputs: number; usedInputs: Buffer; data: Buffer };
    inputIndex: number;
  };
  generate: (
    proof: { nInputs: number; usedInputs: Buffer; data: Buffer },
    inputTags: Array<Buffer>,
    outputTag: Buffer,
    inputIndex: number,
    inputBlindingKey: Buffer,
    outputBlindingKey: Buffer
  ) => { nInputs: number; usedInputs: Buffer; data: Buffer };
  verify: (
    proof: { nInputs: number; usedInputs: Buffer; data: Buffer },
    inputTags: Array<Buffer>,
    outputTag: Buffer
  ) => boolean;
}

interface ZKP { 
  ecdh: Ecdh, 
  ec: Ec, 
  surjectionproof: SurjectionProof, 
  rangeproof: RangeProof, 
  pedersen: Pedersen, 
  generator: Generator 
}

declare function secp256k1(): Promise<{ ecdh: Ecdh, ec: Ec, surjectionproof: SurjectionProof, rangeproof: RangeProof, pedersen: Pedersen, generator: Generator }>;

export {
  ZKP,
  Ec,
  Ecdh,
  SurjectionProof,
  RangeProof,
  Pedersen,
  Generator
}
export default secp256k1;

