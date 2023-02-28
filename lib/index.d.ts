type Ecdh = (pubkey: Uint8Array, scalar: Uint8Array) => Uint8Array;

interface Ecc {
  privateNegate: (key: Uint8Array) => Uint8Array;
  privateAdd: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
  privateMul: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
  isPoint: (point: Uint8Array) => boolean;
  isPrivate: (privatePoint: Uint8Array) => boolean;
  pointFromScalar: (scalar: Uint8Array, compressed?: boolean) => Uint8Array;
  pointCompress: (point: Uint8Array, compressed?: boolean) => Uint8Array;
  xOnlyPointAddTweak: (point: Uint8Array, tweak: Uint8Array) => { parity: 1 | 0, xOnlyPubkey: Uint8Array };
  sign: (message: Uint8Array, privateKey: Uint8Array, extraEntropy?: Uint8Array) => Uint8Array;
  verify: (message: Uint8Array, publicKey: Uint8Array, signature: Uint8Array, strict?: boolean) => boolean;
  signSchnorr: (message: Uint8Array, privateKey: Uint8Array, extraEntropy?: Uint8Array) => Uint8Array;
  verifySchnorr: (message: Uint8Array, publicKey: Uint8Array, signature: Uint8Array) => boolean;
}

interface Generator {
  generate: (seed: Uint8Array) => Uint8Array;
  generateBlinded(key: Uint8Array, blinder: Uint8Array): Uint8Array;
}

interface Pedersen {
  commitment(
    value: string,
    generator: Uint8Array,
    blinder: Uint8Array
  ): Uint8Array;
  blindGeneratorBlindSum(
    values: Array<string>,
    assetBlinders: Array<Uint8Array>,
    valueBlinders: Array<Uint8Array>,
    nInputs: number,
  ): Uint8Array;
}

interface RangeProof {
  info(proof: Uint8Array): {
    exp: string;
    mantissa: string;
    minValue: string;
    maxValue: string;
  };
  verify(
    proof: Uint8Array,
    valueCommitment: Uint8Array,
    assetCommitment: Uint8Array,
    extraCommit?: Uint8Array
  ): boolean;
  sign(
    value: string,
    valueCommitment: Uint8Array,
    assetCommitment: Uint8Array,
    valueBlinder: Uint8Array,
    nonce: Uint8Array,
    minValue?: string,
    base10Exp?: string,
    minBits?: string,
    message?: Uint8Array,
    extraCommit?: Uint8Array
  ): Uint8Array;
  rewind(
    proof: Uint8Array,
    valueCommitment: Uint8Array,
    assetCommitment: Uint8Array,
    nonce: Uint8Array,
    extraCommit?: Uint8Array
  ): {
    value: string;
    minValue: string;
    maxValue: string;
    blinder: Uint8Array;
    message: Uint8Array;
  };
}

interface SurjectionProof {
  initialize: (
    inputTags: Array<Uint8Array>,
    outputTag: Uint8Array,
    maxIterations: number,
    seed: Uint8Array
  ) => {
    proof: Uint8Array;
    inputIndex: number;
  };
  generate: (
    proof: Uint8Array,
    inputTags: Array<Uint8Array>,
    outputTag: Uint8Array,
    inputIndex: number,
    inputBlindingKey: Uint8Array,
    outputBlindingKey: Uint8Array
  ) => Uint8Array;
  verify: (
    proof: Uint8Array,
    inputTags: Array<Uint8Array>,
    outputTag: Uint8Array
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

declare function secp256k1(): Promise<{
  ecdh: Ecdh,
  ecc: Ecc,
  generator: Generator
  pedersen: Pedersen,
  rangeproof: RangeProof,
  surjectionproof: SurjectionProof,
}>;

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

