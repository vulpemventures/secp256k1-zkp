export function commit(
  blindFactor: Buffer,
  value: string,
  generator: Buffer
): Buffer;
export function commitSerialize(commitment: Buffer): Buffer;
export function commitParse(input: Buffer): Buffer;
export function blindSum(blinds: Array<Buffer>, nneg?: number): Buffer;
export function verifySum(
  commits: Array<Buffer>,
  negativeCommits: Array<Buffer>
): boolean;
export function blindGeneratorBlindSum(
  values: Array<string>,
  nInputs: number,
  blindGenerators: Array<Buffer>,
  blindFactors: Array<Buffer>
): Buffer;
