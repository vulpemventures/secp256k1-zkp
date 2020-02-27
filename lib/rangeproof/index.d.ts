export function info(
  proof: Buffer
): { exp: number; mantissa: string; minValue: string; maxValue: string };
export function verify(
  commit: Buffer,
  proof: Buffer,
  extraCommit?: Buffer
): boolean;
export function sign(
  commit: Buffer,
  blind: Buffer,
  nonce: Buffer,
  value: string,
  minValue?: string,
  base10Exp?: number,
  minBits?: number,
  message?: Buffer,
  extraCommit?: Buffer
): Buffer;
export function rewind(
  commit: Buffer,
  proof: Buffer,
  nonce: Buffer,
  extraCommit?: Buffer
): {
  value: string;
  minValue: string;
  maxValue: string;
  blindFactor: Buffer;
  message: Buffer;
};
