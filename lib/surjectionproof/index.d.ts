export function serialize(proof: {
  nInputs: number;
  usedInputs: Buffer;
  data: Buffer;
}): Buffer;
export function initialize(
  inputTags: Array,
  inputTagsToUse: number,
  outputTag: Buffer,
  maxIterations: number,
  seed: Buffer
): { nInputs: number; usedInputs: Buffer; data: Buffer };
export function generate(
  proof: { nInputs: number; usedInputs: Buffer; data: Buffer },
  inputTags: Array,
  outputTag: Buffer,
  inputIndex: number,
  inputBlindingKey: Buffer,
  outputBlindingKey: Buffer
): { nInputs: number; usedInputs: Buffer; data: Buffer };
export function verify(
  proof: { nInputs: number; usedInputs: Buffer; data: Buffer },
  inputTags: Array,
  outputTag: Buffer
): boolean;
