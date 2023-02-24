type Ecdh = (pubkey: Buffer, scalar: Buffer) => Buffer;

interface Ecc {
  privateNegate: (key: Uint8Array) => Uint8Array;
  privateAdd: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
  privateMul: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
  isPoint: (point: Uint8Array) => boolean;
  isPrivate: (privatePoint: Uint8Array) => boolean;
  pointFromScalar: (scalar: Uint8Array, compressed?: boolean) => Uint8Array;
  pointCompress: (point: Uint8Array, compressed?: boolean) => Uint8Array;
  xOnlyPointAddTweak: (point: Uint8Array, tweak: Uint8Array) => Uint8Array;
  sign: (message: Uint8Array, privateKey: Uint8Array, extraEntropy: Uint8Array) => Uint8Array;
  verify: (message: Uint8Array, publicKey: Uint8Array, signature: Uint8Array, strict?: boolean) => boolean;
  signSchnorr: (message: Uint8Array, privateKey: Uint8Array) => Uint8Array;
  verifySchnorr: (message: Uint8Array, publicKey: Uint8Array, signature: Uint8Array) => boolean;
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
  ecc: Ecc, 
  surjectionproof: SurjectionProof, 
  rangeproof: RangeProof, 
  pedersen: Pedersen, 
  generator: Generator 
}

declare function secp256k1(): Promise<{ isPoint: any, ecdh: Ecdh, ec: Ecc, surjectionproof: SurjectionProof, rangeproof: RangeProof, pedersen: Pedersen, generator: Generator }>;

export {
  ZKP,
  Ecc,
  Ecdh,
  SurjectionProof,
  RangeProof,
  Pedersen,
  Generator
}
export default secp256k1;

