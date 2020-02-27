export function commit(blindFactor: Buffer, value: string): Buffer;
export function commitSerialize(commitment: Buffer): Buffer;
export function commitParse(input: Buffer): Buffer;
export function blindSum(blinds: Array, nneg?: number): Buffer;
export function verifySum(commits: Array, negativeCommits: Array): boolean;
export function blindGeneratorBlindSum(
  values: Array,
  nInputs: number,
  blindGenerators: Array,
  blindFactors: Array
): Buffer;
