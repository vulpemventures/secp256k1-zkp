type Ecdh = (pubkey: Uint8Array, scalar: Uint8Array) => Uint8Array;

interface Ec {
  prvkeyNegate: (key: Uint8Array) => Uint8Array;
  prvkeyTweakAdd: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
  prvkeyTweakMul: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
}

interface Generator {
  generate: (seed: Uint8Array) => Uint8Array;
  generateBlinded(key: Uint8Array, blind: Uint8Array): Uint8Array;
  parse(input: Uint8Array): Uint8Array;
  serialize(generator: Uint8Array): Uint8Array;
}

interface Pedersen {
  commit(blindFactor: Uint8Array, value: string, generator: Uint8Array): Uint8Array;
  commitSerialize(commitment: Uint8Array): Uint8Array;
  commitParse(input: Uint8Array): Uint8Array;
  blindSum(blinds: Array<Uint8Array>, nneg?: number): Uint8Array;
  verifySum(
    commits: Array<Uint8Array>,
    negativeCommits: Array<Uint8Array>
  ): boolean;
  blindGeneratorBlindSum(values: Array<string>, nInputs: number, blindGenerators: Array<Uint8Array>, blindFactors: Array<Uint8Array>): Uint8Array;
}

interface RangeProof {
  info(
    proof: Uint8Array
  ): { exp: number; mantissa: string; minValue: string; maxValue: string };
  verify(
    commit: Uint8Array,
    proof: Uint8Array,
    generator: Uint8Array,
    extraCommit?: Uint8Array
  ): boolean;
  sign(
    commit: Uint8Array,
    blind: Uint8Array,
    nonce: Uint8Array,
    value: string,
    generator: Uint8Array,
    minValue?: string,
    base10Exp?: number,
    minBits?: number,
    message?: Uint8Array,
    extraCommit?: Uint8Array
  ): Uint8Array;
  rewind(
    commit: Uint8Array,
    proof: Uint8Array,
    nonce: Uint8Array,
    generator: Uint8Array,
    extraCommit?: Uint8Array
  ): {
    value: string;
    minValue: string;
    maxValue: string;
    blindFactor: Uint8Array;
    message: Uint8Array;
  };
}

interface SurjectionProof {
  serialize: (proof: {
    nInputs: number;
    usedInputs: Uint8Array;
    data: Uint8Array;
  }) => Uint8Array;
  parse: (proof: Uint8Array) => {
    nInputs: number;
    usedInputs: Uint8Array;
    data: Uint8Array;
  };
  initialize: (
    inputTags: Array<Uint8Array>,
    inputTagsToUse: number,
    outputTag: Uint8Array,
    maxIterations: number,
    seed: Uint8Array
  ) => {
    proof: { nInputs: number; usedInputs: Uint8Array; data: Uint8Array };
    inputIndex: number;
  };
  generate: (
    proof: { nInputs: number; usedInputs: Uint8Array; data: Uint8Array },
    inputTags: Array<Uint8Array>,
    outputTag: Uint8Array,
    inputIndex: number,
    inputBlindingKey: Uint8Array,
    outputBlindingKey: Uint8Array
  ) => { nInputs: number; usedInputs: Uint8Array; data: Uint8Array };
  verify: (
    proof: { nInputs: number; usedInputs: Uint8Array; data: Uint8Array },
    inputTags: Array<Uint8Array>,
    outputTag: Uint8Array
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

