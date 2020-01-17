export function serialize(proof: {
  nInputs: number;
  usedInputs: Buffer;
  data: Buffer;
}): Buffer;
export function initialize(
  inputTags: Array<Buffer>,
  inputTagsToUse: number,
  outputTag: Buffer,
  maxIterations: number,
  seed: Buffer
): {
  proof: { nInputs: number; usedInputs: Buffer; data: Buffer };
  inputIndex: number;
};
export function generate(
  proof: { nInputs: number; usedInputs: Buffer; data: Buffer },
  inputTags: Array<Buffer>,
  outputTag: Buffer,
  inputIndex: number,
  inputBlindingKey: Buffer,
  outputBlindingKey: Buffer
): { nInputs: number; usedInputs: Buffer; data: Buffer };
export function verify(
  proof: { nInputs: number; usedInputs: Buffer; data: Buffer },
  inputTags: Array<Buffer>,
  outputTag: Buffer
): boolean;
