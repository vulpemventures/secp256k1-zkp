const lib = require('../dist/secp256k1-zkp.js');
const Long = require('long');

const PRIVATE_KEY_SIZE = 32;
const PUBLIC_KEY_COMPRESSED_SIZE = 33;
const PUBLIC_KEY_UNCOMPRESSED_SIZE = 65;
const X_ONLY_PUBLIC_KEY_SIZE = 32;
const TWEAK_SIZE = 32;
const HASH_SIZE = 32;
const EXTRA_DATA_SIZE = 32;

const ERROR_BAD_PRIVATE = 0;
const ERROR_BAD_POINT = 1;
const ERROR_BAD_TWEAK = 2;
const ERROR_BAD_HASH = 3;
const ERROR_BAD_SIGNATURE = 4;
const ERROR_BAD_EXTRA_DATA = 5;
const ERROR_BAD_PARITY = 6;
const ERROR_BAD_RECOVERY_ID = 7;

const ERRORS_MESSAGES = {
  [ERROR_BAD_PRIVATE.toString()]: 'Expected Private',
  [ERROR_BAD_POINT.toString()]: 'Expected Point',
  [ERROR_BAD_TWEAK.toString()]: 'Expected Tweak',
  [ERROR_BAD_HASH.toString()]: 'Expected Hash',
  [ERROR_BAD_SIGNATURE.toString()]: 'Expected Signature',
  [ERROR_BAD_EXTRA_DATA.toString()]: 'Expected Extra Data (32 bytes)',
  [ERROR_BAD_PARITY.toString()]: 'Expected Parity (1 | 0)',
  [ERROR_BAD_RECOVERY_ID.toString()]: 'Bad Recovery Id',
};

function throwError(errcode) {
  const message =
    ERRORS_MESSAGES[errcode.toString()] || `Unknow error code: ${errcode}`;
  throw new TypeError(message);
}

const BN32_ZERO = new Uint8Array(32);

const BN32_N = new Uint8Array([
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  254, 186, 174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65,
]);

function isUint8Array(value) {
  return value instanceof Uint8Array;
}
function cmpBN32(data1, data2) {
  for (let i = 0; i < 32; ++i) {
    if (data1[i] !== data2[i]) {
      return data1[i] < data2[i] ? -1 : 1;
    }
  }
  return 0;
}

function isPrivatePoint(x) {
  return (
    isUint8Array(x) &&
    x.length === PRIVATE_KEY_SIZE &&
    cmpBN32(x, BN32_ZERO) > 0 &&
    cmpBN32(x, BN32_N) < 0
  );
}

function isEccPoint(p) {
  return (
    isUint8Array(p) &&
    (p.length === PUBLIC_KEY_COMPRESSED_SIZE ||
      p.length === PUBLIC_KEY_UNCOMPRESSED_SIZE ||
      p.length === X_ONLY_PUBLIC_KEY_SIZE)
  );
}
function isXOnlyPoint(p) {
  return isUint8Array(p) && p.length === X_ONLY_PUBLIC_KEY_SIZE;
}

function isTweak(tweak) {
  return (
    isUint8Array(tweak) &&
    tweak.length === TWEAK_SIZE &&
    cmpBN32(tweak, BN32_N) < 0
  );
}
function isHash(h) {
  return isUint8Array(h) && h.length === HASH_SIZE;
}
function isExtraData(e) {
  return e === undefined || (isUint8Array(e) && e.length === EXTRA_DATA_SIZE);
}
function isSignature(signature) {
  return (
    isUint8Array(signature) &&
    signature.length === 64 &&
    cmpBN32(signature.subarray(0, 32), BN32_N) < 0 &&
    cmpBN32(signature.subarray(32, 64), BN32_N) < 0
  );
}

function validatePrivate(d) {
  if (!isPrivatePoint(d)) throwError(ERROR_BAD_PRIVATE);
}
function validatePoint(p) {
  if (!isEccPoint(p)) throwError(ERROR_BAD_POINT);
}
function validateXOnlyPoint(p) {
  if (!isXOnlyPoint(p)) throwError(ERROR_BAD_POINT);
}
function validateTweak(tweak) {
  if (!isTweak(tweak)) throwError(ERROR_BAD_TWEAK);
}
function validateHash(h) {
  if (!isHash(h)) throwError(ERROR_BAD_HASH);
}
function validateExtraData(e) {
  if (!isExtraData(e)) throwError(ERROR_BAD_EXTRA_DATA);
}
function validateSignature(signature) {
  if (!isSignature(signature)) throwError(ERROR_BAD_SIGNATURE);
}

function assumeCompression(compressed, p) {
  if (compressed === undefined) {
    return p !== undefined ? p.length : PUBLIC_KEY_COMPRESSED_SIZE;
  }
  return compressed ? PUBLIC_KEY_COMPRESSED_SIZE : PUBLIC_KEY_UNCOMPRESSED_SIZE;
}

module.exports = () => {
  return new Promise((resolve) => {
    lib().then((Module) => {
      let free = [];

      function malloc(size) {
        const ptr = Module._malloc(size);
        free.push(ptr);
        return ptr;
      }

      function freeMalloc() {
        for (const ptr of free) {
          Module._free(ptr);
        }
        free = [];
      }

      /**
       *  @summary Calculates a ECDH point.
       *  @return {Array} 32-bytes ecdh point.
       *  @throws {Error} Decode error.
       *  @arg {Array} pubkey - 33-byte pubkey.
       *  @arg {Array} scalar - 32-byte scalar.
       *  @exports
       */
      function ecdh(pubkey, scalar) {
        const output = malloc(32);
        const ret = Module.ccall(
          'ecdh',
          'number',
          ['number', 'number', 'number'],
          [output, charStar(pubkey), charStar(scalar)]
        );

        if (ret === 1) {
          const out = new Uint8Array(
            Module.HEAPU8.subarray(output, output + 32)
          );
          freeMalloc();
          return Buffer.from(out);
        } else {
          freeMalloc();
          throw new Error('secp256k1_ecdh', ret);
        }
      }

      /**
       *  @summary Generates a blinding generator.
       *  @return {Array} 64-byte generator successfully computed.
       *  @throws {Error} Decode error.
       *  @arg {Array} seed - 32-byte random seed.
       *  @exports
       */
      function generate(seed) {
        if (!seed || !Buffer.isBuffer(seed) || seed.length !== 32) {
          throw new TypeError('seed must be a Buffer of 32 bytes');
        }
        const output = malloc(64);

        const ret = Module.ccall(
          'generator_generate',
          'number',
          ['number', 'number'],
          [output, charStar(seed)]
        );
        if (ret === 1) {
          const out = new Uint8Array(
            Module.HEAPU8.subarray(output, output + 64)
          );
          freeMalloc();
          return Buffer.from(out);
        }
        freeMalloc();
        throw new Error('secp256k1_generator_generate', ret);
      }

      /**
       *  @summary Generates a blinding generator with a blinding factor.
       *  @return {Array} 64-byte generator successfully computed.
       *  @throws {Error} Decode error.
       *  @arg {Array} key - 32-byte array key.
       *  @arg {Array} blind - 32-byte array blinding factor.
       *  @exports
       */
      function generateBlinded(key, blind) {
        if (!key || !Buffer.isBuffer(key) || key.length !== 32)
          throw new TypeError('key must be a Buffer of 32 bytes');
        if (!blind || !Buffer.isBuffer(blind) || blind.length !== 32)
          throw new TypeError('blind must be a Buffer of 32 bytes');

        const output = malloc(64);

        const ret = Module.ccall(
          'generator_generate_blinded',
          'number',
          ['number', 'number', 'number'],
          [output, charStar(key), charStar(blind)]
        );
        if (ret === 1) {
          const out = new Uint8Array(
            Module.HEAPU8.subarray(output, output + 64)
          );
          freeMalloc();
          return Buffer.from(out);
        } else {
          freeMalloc();
          throw new Error('secp256k1_generator_generate_blinded', ret);
        }
      }

      /**
       *  @summary Parses a serialized generator.
       *  @return {Array} 64-bytes generator.
       *  @throws {Error} Decode error.
       *  @arg {Array} input - 33-byte serialized generator.
       *  @exports
       */
      function parse(input) {
        if (!input || !Buffer.isBuffer(input) || input.length !== 33)
          throw new TypeError('input must be a Buffer of 32 bytes');

        const gen = malloc(64);

        const ret = Module.ccall(
          'generator_parse',
          'number',
          ['number', 'number'],
          [gen, charStar(input)]
        );
        if (ret === 1) {
          const out = new Uint8Array(Module.HEAPU8.subarray(gen, gen + 64));
          freeMalloc();
          return Buffer.from(out);
        } else {
          freeMalloc();
          throw new Error('secp256k1_generator_parse', ret);
        }
      }

      /**
       *  @summary Serializes a generator.
       *  @return {Array} 33-bytes serialized generator.
       *  @throws {Error} Decode error.
       *  @arg {Array} generator - 64-byte generator.
       *  @exports
       */
      function serialize(generator) {
        if (
          !generator ||
          !Buffer.isBuffer(generator) ||
          generator.length !== 64
        )
          throw new TypeError('generator must be a Buffer of 32 bytes');

        const output = malloc(33);
        const ret = Module.ccall(
          'generator_serialize',
          'number',
          ['number', 'number'],
          [output, charStar(generator)]
        );
        if (ret === 1) {
          const out = new Uint8Array(
            Module.HEAPU8.subarray(output, output + 33)
          );
          freeMalloc();
          return Buffer.from(out);
        } else {
          freeMalloc();
          throw new Error('secp256k1_generator_parse', ret);
        }
      }

      /**
       *  @summary Generates a pedersen commitment.
       *  @return {Array} 33-bytes commitment successfully created.
       *  @throws {Error} - Decode error.
       *  @arg {Array} blindFactor - 32-byte blinding factor.
       *  @arg {string} value - unsigned 64-bit integer value to commit to as string.
       *  @arg {Array} generator - 64-byte generator.
       *  @exports
       */
      function commit(blindFactor, value, generator) {
        if (
          !blindFactor ||
          !Buffer.isBuffer(blindFactor) ||
          blindFactor.length !== 32
        )
          throw new TypeError('blindFactor must be a Buffer of 32 bytes');
        if (
          !generator ||
          !Buffer.isBuffer(generator) ||
          generator.length !== 64
        )
          throw new TypeError('generator must be a Buffer of 64 bytes');

        const commitment = malloc(64);
        const valueLong = Long.fromString(value, true);

        const ret = Module.ccall(
          'pedersen_commit',
          'number',
          ['number', 'number', 'number', 'number'],
          [
            commitment,
            charStar(blindFactor),
            valueLong.low,
            valueLong.high,
            charStar(generator),
          ]
        );
        if (ret === 1) {
          const out = new Uint8Array(
            Module.HEAPU8.subarray(commitment, commitment + 64)
          );
          freeMalloc();
          return Buffer.from(out);
        } else {
          freeMalloc();
          throw new Error('secp256k1_pedersen_commit', ret);
        }
      }

      /**
       *  @summary Serializes a pedersen commitment.
       *  @return {Array} 33-bytes serialized pedersen commitment.
       *  @throws {Error} - Decode error.
       *  @arg {Array} commitment - 64-byte pedersen commitment (cannot be NULL).
       *  @exports
       */
      function commitSerialize(commitment) {
        if (
          !commitment ||
          !Buffer.isBuffer(commitment) ||
          commitment.length !== 64
        )
          throw new TypeError('commitment must be a Buffer of 64 bytes');

        const out = malloc(33);

        const ret = Module.ccall(
          'pedersen_commitment_serialize',
          'number',
          ['number', 'number'],
          [out, charStar(commitment)]
        );
        if (ret === 1) {
          const cmt = new Uint8Array(Module.HEAPU8.subarray(out, out + 33));
          freeMalloc();
          return Buffer.from(cmt);
        } else {
          freeMalloc();
          throw new Error('secp256k1_pedersen_commitment_serialize', ret);
        }
      }

      /**
       *  @summary Parses a pedersen commitment.
       *  @return {Array} 64-bytes pedersen commitment.
       *  @throws {Error} - Decode error.
       *  @arg {Array} input - 33-byte commitment to parse (cannot be NULL).
       *  @exports
       */
      function commitParse(input) {
        if (!input || !Buffer.isBuffer(input) || input.length !== 33)
          throw new TypeError('input must be a Buffer of 33 bytes');

        const commitment = malloc(64);
        const ret = Module.ccall(
          'pedersen_commitment_parse',
          'number',
          ['number', 'number'],
          [commitment, charStar(input)]
        );
        if (ret === 1) {
          const cmt = new Uint8Array(
            Module.HEAPU8.subarray(commitment, commitment + 64)
          );
          freeMalloc();
          return Buffer.from(cmt);
        } else {
          freeMalloc();
          throw new Error('secp256k1_pedersen_commitment_parse', ret);
        }
      }

      /**
       *  @summary Sets the final blinding factor correctly when the generators themselves have blinding factors.
       *  @return {Array} 32-bytes final blinding factor.
       *  @throws {Error} - Decode error.
       *  @arg {Array} values - array of asset values as string.
       *  @arg {number} nInputs - How many of the initial array elements represent commitments that will be negated in the final sum.
       *  @arg {Array} blindGenerators - array of asset blinding factors.
       *  @arg {Array} blindFactors - array of commitment blinding factors.
       *  @exports
       */
      function blindGeneratorBlindSum(
        values,
        nInputs,
        blindGenerators,
        blindFactors
      ) {
        if (
          !blindGenerators ||
          !Array.isArray(blindGenerators) ||
          !blindGenerators.length
        )
          throw new TypeError(
            'blindGenerators must be a non empty array of Buffers'
          );
        if (!blindFactors || !Array.isArray(blindFactors))
          throw new TypeError('blindFactors must be an array of Buffers');

        const longValues = values.map((v) => Long.fromString(v, true));
        const blindOut = malloc(32);
        const ret = Module.ccall(
          'pedersen_blind_generator_blind_sum',
          'number',
          ['number', 'number', 'number', 'number', 'number', 'number'],
          [
            longIntStarArray(longValues),
            charStarArray(blindGenerators),
            charStarArray(blindFactors),
            blindGenerators.length,
            nInputs,
            blindOut,
          ]
        );
        if (ret === 1) {
          const output = new Uint8Array(
            Module.HEAPU8.subarray(blindOut, blindOut + 32)
          );
          freeMalloc();
          return Buffer.from(output);
        } else {
          freeMalloc();
          throw new Error('secp256k1_pedersen_blind_generator_blind_sum', ret);
        }
      }

      /**
       *  @summary Computes the sum of multiple positive and negative blinding factors.
       *  @return {Array} 32-bytes sum successfully computed.
       *  @throws {Error} Decode error.
       *  @arg {Array} blinds - 32-byte character arrays for blinding factors.
       *  @arg {number} [nneg = 0] - how many of the initial factors should be treated with a negative sign.
       *  @exports
       */
      function blindSum(blinds, nneg = 0) {
        if (!blinds || !Array.isArray(blinds) || !blinds.length)
          throw new TypeError('blinds must be a non empty array of Buffers');

        const sum = malloc(32);
        const ret = Module.ccall(
          'pedersen_blind_sum',
          'number',
          ['number', 'number', 'number', 'number'],
          [sum, charStarArray(blinds), blinds.length, blinds.length - nneg]
        );
        if (ret === 1) {
          const s = new Uint8Array(Module.HEAPU8.subarray(sum, sum + 32));
          freeMalloc();
          return Buffer.from(s);
        } else {
          freeMalloc();
          throw new Error('secp256k1_pedersen_blind_sum', ret);
        }
      }

      /**
       * @summary Verifies pedersen commitments - negativeCommits - excess === 0
       * @return {boolean} commitments successfully sum to zero.
       * @throws {Error} Commitments do not sum to zero or other error.
       * @arg {Array} commits: pointer to pointers to 33-byte character arrays for the commitments.
       * @arg {Array} ncommits: pointer to pointers to 33-byte character arrays for negative commitments.
       * @exports
       */
      function verifySum(commits, negativeCommits) {
        if (
          !commits ||
          !Array.isArray(commits) ||
          !commits.every((c) => c.length === 33)
        )
          throw new TypeError(
            'commits must be a non empty array of Buffers of 33 bytes'
          );
        if (
          !negativeCommits ||
          !Array.isArray(negativeCommits) ||
          !negativeCommits.every((c) => c.length === 33)
        )
          throw new TypeError(
            'negativeCommits must be a non empty array of Buffers of 33 bytes'
          );
        const ret = Module.ccall(
          'pedersen_verify_tally',
          'number',
          ['number', 'number', 'number', 'number'],
          [
            charStarArray(commits),
            commits.length,
            charStarArray(negativeCommits),
            negativeCommits.length,
          ]
        );
        freeMalloc();
        return ret === 1;
      }

      /**
       *  @summary Authors a proof that a committed value is within a range.
       *  @return {Array} Proof successfully created.
       *  @throws {Error} Decode failed.
       *  @arg {Array} commitment: 33-byte array with the commitment being proved.
       *  @arg {Array} blind: 32-byte blinding factor used by commit.
       *  @arg {Array} nonce: 32-byte secret nonce used to initialize the proof (value can be reverse-engineered out of the proof if this secret is known.).
       *  @arg {string} value: unblinded value.
       *  @arg {Array} generator: 64-byte secret generator for the proof.
       *  @arg {string} minValue: constructs a proof where the verifer can tell the minimum value is at least the specified amount.
       *  @arg {number} base10Exp: Base-10 exponent. Digits below above will be made public, but the proof will be made smaller. Allowed range is -1 to 18.
       *      (-1 is a special case that makes the value public. 0 is the most private.).
       *  @arg {number} minBits: Number of bits of the value to keep private. (0 = auto/minimal, - 64).
       *  @arg {Array} message: optional message.
       *  @arg {Array} extraCommit: optional extra commit.
       *  @exports
       */
      function sign(
        commitment,
        blind,
        nonce,
        value,
        generator,
        minValue = '0',
        base10Exp = 0,
        minBits = 0,
        message = Buffer.alloc(0),
        extraCommit = Buffer.alloc(0)
      ) {
        if (!commitment || !Buffer.isBuffer(commitment) || !commitment.length)
          throw new TypeError('commit must be a non empty Buffer');
        if (!blind || !Buffer.isBuffer(blind) || blind.length !== 32)
          throw new TypeError('blind must be a Buffer of 32 bytes');
        if (!nonce || !Buffer.isBuffer(nonce) || !nonce.length)
          throw new TypeError('nonce must be a non empty Buffer');
        if (
          !generator ||
          !Buffer.isBuffer(generator) ||
          generator.length !== 64
        )
          throw new TypeError('generator must be a Buffer of 64 bytes');
        if (!Buffer.isBuffer(message))
          throw new TypeError('message must be a Buffer');
        if (!Buffer.isBuffer(extraCommit))
          throw new TypeError('extraCommit must be a Buffer');

        const proof = malloc(5134);
        const plen = malloc(8);
        Module.setValue(plen, 5134, 'i64');
        const minValueLong = Long.fromString(minValue, true);
        const valueLong = Long.fromString(value, true);

        const ret = Module.ccall(
          'rangeproof_sign',
          'number',
          [
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
          ],
          [
            proof,
            plen,
            minValueLong.low,
            minValueLong.high,
            charStar(commitment),
            charStar(blind),
            charStar(nonce),
            base10Exp,
            minBits,
            valueLong.low,
            valueLong.high,
            charStar(message),
            message.length,
            charStar(extraCommit),
            extraCommit.length,
            charStar(generator),
          ]
        );
        if (ret === 1) {
          const p = new Uint8Array(
            Module.HEAPU8.subarray(proof, proof + Module.getValue(plen, 'i64'))
          );
          freeMalloc();
          return Buffer.from(p);
        } else {
          freeMalloc();
          throw new Error('secp256k1_rangeproof_sign', ret);
        }
      }

      /**
       *  @typedef {ProofInfo}
       *  @property {number} exp - Exponent used in the proof (-1 means the value isn't private).
       *  @property {string} mantissa - Number of bits covered by the proof.
       *  @property {string} minValue - minimum value that commit could have.
       *  @property {string} maxValue - maximum value that commit could have.
       */
      /**
       *  @summary Returns value info from a range-proof.
       *  @return {ProofInfo} Information successfully extracted.
       *  @throws {Error} Decode failed.
       *  @arg {Array} proof - range-proof.
       *  @exports
       */
      function info(proof) {
        if (!proof || !Buffer.isBuffer(proof) || !proof.length)
          throw new TypeError('proof must be a non empty Buffer');

        const exp = charStar(4);
        const mantissa = charStar(4);
        const min = charStar(8);
        const max = charStar(8);
        const ret = Module.ccall(
          'rangeproof_info',
          'number',
          ['number', 'number', 'number', 'number', 'number', 'number'],
          [exp, mantissa, min, max, charStar(proof), proof.length]
        );

        if (ret === 1) {
          const res = {
            exp: Module.getValue(exp, 'i32'),
            mantissa: Module.getValue(mantissa, 'i32'),
            minValue: Uint64Long(min).toString(),
            maxValue: Uint64Long(max).toString(),
          };
          freeMalloc();
          return res;
        } else {
          freeMalloc();
          throw new Error('secp256k1_rangeproof_info decode failed', ret);
        }
      }

      /**
       *  @summary Verifies a range-proof.
       *  @return {boolean} Proof successfully verified.
       *  @arg {Array} commitment - 33-byte commitment.
       *  @arg {Array} proof - range proof to verify.
       *  @arg {Array} generator - 64-byte generator used for the proof.
       *  @arg {Array} extraCommit - extra data used for the proof.
       */
      function verify(
        commitment,
        proof,
        generator,
        extraCommit = Buffer.alloc(0)
      ) {
        if (
          !commitment ||
          !Buffer.isBuffer(commitment) ||
          commitment.length !== 64
        )
          throw new TypeError('commitment must be a Buffer of 64 bytes');
        if (!proof || !Buffer.isBuffer(proof) || !proof.length)
          throw new TypeError('proof must be a non empty Buffer');
        if (
          !generator ||
          !Buffer.isBuffer(generator) ||
          generator.length !== 64
        )
          throw new TypeError('generator must be a Buffer of 64 bytes');
        if (!extraCommit || !Buffer.isBuffer(extraCommit))
          throw new TypeError('extraCommit must be a Buffer');

        const min = charStar(8);
        const max = charStar(8);
        const ret = Module.ccall(
          'rangeproof_verify',
          'number',
          [
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
          ],
          [
            min,
            max,
            charStar(commitment),
            charStar(proof),
            proof.length,
            charStar(extraCommit),
            extraCommit.length,
            charStar(generator),
          ]
        );

        if (ret === -1) {
          freeMalloc();
          throw new Error('secp256k1_ecdsa_verify failed', ret);
        }

        freeMalloc();
        return ret === 1;
      }

      /**
       *  @typedef {ProofRewind}
       *  @property {Array} blind - 32-byte blinding factor used by commit.
       *  @property {string} value - unblinded value.
       *  @property {string} minValue - minimum value that commit could have.
       *  @property {string} maxValue - maximum value that commit could have.
       *  @property {Array} message - 32-byte unblinded message.
       */
      /**
       *  @summary Extracts information from a range-proof.
       *  @return {ProofRewind} Information successfully extracted.
       *  @throws {Error} Decode failed.
       *  @arg {Array} commitment - 33-byte array with the commitment being proved.
       *  @arg {Array} proof - range-proof.
       *  @arg {Array} nonce - 32-byte secret nonce used to initialize the proof.
       *  @arg {Array} generator - 64-byte generator for the proof.
       *  @arg {Array} extraCommit - extra data for range-proof.
       */
      function rewind(commitment, proof, nonce, generator, extraCommit = []) {
        if (!commitment || !Buffer.isBuffer(commitment) || !commitment.length)
          throw new TypeError('commit must be a non empty Buffer');
        if (!proof || !Buffer.isBuffer(proof) || !proof.length)
          throw new TypeError('proof must be a non empty Buffer');
        if (!nonce || !Buffer.isBuffer(nonce) || !nonce.length)
          throw new TypeError('nonce must be a non empty Buffer');
        if (
          !generator ||
          !Buffer.isBuffer(generator) ||
          generator.length !== 64
        )
          throw new TypeError('generator must be a Buffer of 64 bytes');
        if (!extraCommit || !Buffer.isBuffer(extraCommit))
          throw new TypeError('extraCommit must be a Buffer');
        const blind = malloc(32);
        const value = malloc(8);
        const message = malloc(64);
        const messageLength = malloc(8);
        const minValue = malloc(8);
        const maxValue = malloc(8);
        Module.setValue(messageLength, 64, 'i64');

        const ret = Module.ccall(
          'rangeproof_rewind',
          'number',
          [
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
          ],
          [
            blind,
            value,
            message,
            messageLength,
            charStar(nonce),
            minValue,
            maxValue,
            charStar(commitment),
            charStar(proof),
            proof.length,
            charStar(extraCommit),
            extraCommit.length,
            charStar(generator),
          ]
        );

        if (ret === 1) {
          const bf = new Uint8Array(Module.HEAPU8.subarray(blind, blind + 32));
          const msg = new Uint8Array(
            Module.HEAPU8.subarray(
              message,
              message + Module.getValue(messageLength, 'i64')
            )
          );
          const out = {
            value: Uint64Long(value).toString(),
            minValue: Uint64Long(minValue).toString(),
            maxValue: Uint64Long(maxValue).toString(),
            blindFactor: Buffer.from(bf),
            message: Buffer.from(msg),
          };
          freeMalloc();
          return out;
        } else {
          freeMalloc();
          throw new Error('secp256k1_rangeproof_rewind', ret);
        }
      }

      /**
       *  @typedef {SurjectionProof}
       *  @property {number} nInputs - number of input tags used to generate the proof.
       *  @property {Array} usedInputs - 32-byte inputs bitmap.
       *  @property {Array} data - 8224-byte proof data.
       */
      /**
       *  @summary Serializes a surjection proof.
       *  @return {Array} Serialized surjection proof without leading zeros.
       *  @throws {Error} Decode failed.
       *  @arg {SurjectionProof} proof - proof to serialize.
       */
      function proofSerialize(proof) {
        if (
          !proof ||
          proof.nInputs === undefined ||
          proof.nInputs === null ||
          !proof.usedInputs ||
          !Buffer.isBuffer(proof.usedInputs) ||
          proof.usedInputs.length != 32 ||
          !proof.data ||
          !Buffer.isBuffer(proof.data)
        )
          throw new TypeError(
            'proof must be an object with nInputs of type number and data,' +
              'usedInputs of type Buffer'
          );
        const output = malloc(8258);
        const outputLength = malloc(8);
        Module.setValue(outputLength, 8258, 'i64');
        const ret = Module.ccall(
          'surjectionproof_serialize',
          'number',
          ['number', 'number', 'number', 'number', 'number'],
          [
            output,
            outputLength,
            intStar(proof.nInputs),
            charStar(proof.usedInputs),
            charStar(proof.data),
          ]
        );
        if (ret === 1) {
          const out = new Uint8Array(
            Module.HEAPU8.subarray(
              output,
              output + Module.getValue(outputLength, 'i64')
            )
          );
          freeMalloc();
          return Buffer.from(out);
        } else {
          freeMalloc();
          throw new Error('secp256k1_surjectionproof_serialize', ret);
        }
      }

      /**
       *  @summary Parses a surjection proof.
       *  @return {SurjectionProof} Surjection proof.
       *  @throws {Error} Decode failed.
       *  @arg {Array} proof - Serialized surjection proof as byte array.
       */
      function proofParse(proof) {
        if (!proof || !Buffer.isBuffer(proof))
          throw new TypeError('proof must be a non empty Buffer');

        const nInputs = malloc(4);
        const usedInputs = malloc(32);
        const data = malloc(8224);
        const ret = Module.ccall(
          'surjectionproof_parse',
          'number',
          ['number', 'number', 'number', 'number', 'number'],
          [nInputs, usedInputs, data, charStar(proof), proof.length]
        );
        if (ret > 0) {
          const usedIns = new Uint8Array(
            Module.HEAPU8.subarray(usedInputs, usedInputs + 32)
          );
          const d = new Uint8Array(Module.HEAPU8.subarray(data, data + 8224));
          const out = {
            nInputs: Module.getValue(nInputs, 'i32'),
            usedInputs: Buffer.from(usedIns),
            data: Buffer.from(d),
          };
          freeMalloc();
          return out;
        } else {
          freeMalloc();
          throw new Error('secp256k1_surjectionproof_proof', ret);
        }
      }

      /**
       *  @summary Returns an initialized surjection proof.
       *  @return {SurjectionProof} Proof successfully computed.
       *  @throws {Error} Decode failed.
       *  @arg {Array} inputTags - Array of 32-byte input tags.
       *  @arg {number} inputTagsToUse - The number of inputs to include in the surjection proof.
       *  @arg {Array} outputTag - 32-byte output tag.
       *  @arg {number} maxIterations - Max number of attemoots to compute the proof.
       *  @arg {Array} seed - 32-byte random seed.
       */
      function proofInitialize(
        inputTags,
        inputTagsToUse,
        outputTag,
        maxIterations,
        seed
      ) {
        if (
          !inputTags ||
          !Array.isArray(inputTags) ||
          !inputTags.length ||
          !inputTags.every((t) => t.length === 32)
        )
          throw new TypeError(
            'inputTags must be a non empty array of Buffers of 32 bytes'
          );
        if (
          !outputTag ||
          !Buffer.isBuffer(outputTag) ||
          outputTag.length !== 32
        )
          throw new TypeError('outputTag must be a Buffer of 32 bytes');
        if (!seed || !Buffer.isBuffer(seed) || seed.length !== 32)
          throw new TypeError('seed must be a Buffer of 32 bytes');

        const nInputs = malloc(4);
        const usedInputs = malloc(32);
        const data = malloc(8224);
        const inputIndex = malloc(4);
        const ret = Module.ccall(
          'surjectionproof_initialize',
          'number',
          [
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
          ],
          [
            nInputs,
            usedInputs,
            data,
            inputIndex,
            charStarArray(inputTags),
            inputTags.length,
            inputTagsToUse,
            charStar(outputTag),
            maxIterations,
            charStar(seed),
          ]
        );
        if (ret > 0) {
          const usedIns = new Uint8Array(
            Module.HEAPU8.subarray(usedInputs, usedInputs + 32)
          );
          const d = new Uint8Array(Module.HEAPU8.subarray(data, data + 8224));
          const out = {
            proof: {
              nInputs: Module.getValue(nInputs, 'i32'),
              usedInputs: Buffer.from(usedIns),
              data: Buffer.from(d),
            },
            inputIndex: Module.getValue(inputIndex, 'i32'),
          };
          freeMalloc();
          return out;
        } else {
          freeMalloc();
          throw new Error('secp256k1_surjectionproof_initialize', ret);
        }
      }

      /**
       *  @summary Generates a surjection proof.
       *  @return {SurjectionProof} Proof successfully computed.
       *  @throws {Error} Decode failed.
       *  @arg {SurjectionProof} proof - Initialized surjection proof.
       *  @arg {Array} inputTags - Array of 64-byte ephemeral input tags.
       *  @arg {Array} outputTag - 64-byte ephemeral output tag.
       *  @arg {number} inputIndex - Proof input index.
       *  @arg {Array} inputBlindingKey - 32-byte blinding key for the input tags.
       *  @arg {Array} outputBlindingKey - 32-byte blinding key for the output tag.
       */
      function proofGenerate(
        proof,
        inputTags,
        outputTag,
        inputIndex,
        inputBlindingKey,
        outputBlindingKey
      ) {
        if (
          !proof ||
          proof.nInputs === undefined ||
          proof.nInputs === null ||
          !proof.usedInputs ||
          !Buffer.isBuffer(proof.usedInputs) ||
          proof.usedInputs.length != 32 ||
          !proof.data ||
          !Buffer.isBuffer(proof.data)
        )
          throw new TypeError(
            'proof must be an object with nInputs of type number and data,' +
              'usedInputs of type Buffer'
          );
        if (
          !inputTags ||
          !Array.isArray(inputTags) ||
          !inputTags.length ||
          !inputTags.every((t) => t.length === 64)
        )
          throw new TypeError(
            'inputTags must be a non empty array of Buffers of 64 bytes'
          );
        if (
          !outputTag ||
          !Buffer.isBuffer(outputTag) ||
          outputTag.length !== 64
        )
          throw new TypeError('ouputTag must be a Buffer of 64 bytes');
        if (
          !inputBlindingKey ||
          !Buffer.isBuffer(inputBlindingKey) ||
          inputBlindingKey.length !== 32
        )
          throw new TypeError('inputBlindingKey must be a Buffer of 32 bytes');
        if (
          !outputBlindingKey ||
          !Buffer.isBuffer(outputBlindingKey) ||
          outputBlindingKey.length !== 32
        )
          throw new TypeError('outputBlindingKey must be a Buffer of 32 bytes');
        if (inputIndex < 0 || inputIndex > inputTags.length)
          throw new TypeError(
            'inputIndex must be a number into range [0, ' +
              inputTags.length +
              ']'
          );
        const nInputs = intStar(proof.nInputs);
        const usedInputs = charStar(proof.usedInputs);
        const data = charStar(proof.data);
        const ret = Module.ccall(
          'surjectionproof_generate',
          'number',
          [
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
            'number',
          ],
          [
            nInputs,
            usedInputs,
            data,
            charStarArray(inputTags),
            inputTags.length,
            charStar(outputTag),
            inputIndex,
            charStar(inputBlindingKey),
            charStar(outputBlindingKey),
          ]
        );
        if (ret === 1) {
          const usedIns = new Uint8Array(
            Module.HEAPU8.subarray(usedInputs, usedInputs + 32)
          );
          const d = new Uint8Array(Module.HEAPU8.subarray(data, data + 8224));
          const p = {
            nInputs: inputTags.length,
            usedInputs: Buffer.from(usedIns),
            data: Buffer.from(d),
          };
          freeMalloc();
          return p;
        } else {
          freeMalloc();
          throw new Error('secp256k1_surjectionproof_generate', ret);
        }
      }

      /**
       *  @summary Verifies a surjection proof.
       *  @return {boolean} Proof successfully verified.
       *  @throws {Error} Decode failed.
       *  @arg {SurjectionProof} proof - proof to verify.
       *  @arg {Array} inputTags - Array of 64-byte ephemeral input tags.
       *  @arg {Array} outputTags - 64-byte ephemeral output tags.
       */
      function proofVerify(proof, inputTags, outputTag) {
        if (
          !inputTags ||
          !Array.isArray(inputTags) ||
          !inputTags.length ||
          !inputTags.every((t) => t.length === 64)
        )
          throw new TypeError(
            'inputTags must be a non empty array of Buffers of 64 bytes'
          );
        if (
          !outputTag ||
          !Buffer.isBuffer(outputTag) ||
          outputTag.length !== 64
        )
          throw new TypeError('ouputTag must be a Buffer of 64 bytes');
        const ret = Module.ccall(
          'surjectionproof_verify',
          'number',
          ['number', 'number', 'number', 'number', 'number', 'number'],
          [
            intStar(proof.nInputs),
            charStar(proof.usedInputs),
            charStar(proof.data),
            charStarArray(inputTags),
            inputTags.length,
            charStar(outputTag),
          ]
        );
        freeMalloc();
        return ret === 1;
      }

      /**
       *  @summary Negate a private key.
       *  @return {Array} Negated key as array of bytes.
       *  @throws {Error} Decode failed.
       *  @arg {Array} key - Private key to negate.
       */
      function privateNegate(key) {
        if (!key || !Buffer.isBuffer(key) || key.length !== 32) {
          throw new TypeError('key must be a non-empty Buffer of 32 bytes');
        }

        const keyPtr = charStar(key);
        const ret = Module.ccall(
          'ec_seckey_negate',
          'number',
          ['number'],
          [keyPtr]
        );

        if (ret === 1) {
          const res = new Uint8Array(
            Module.HEAPU8.subarray(keyPtr, keyPtr + 32)
          );
          freeMalloc();
          return Buffer.from(res);
        }
        freeMalloc();
        throw new Error('ec_seckey_negate', ret);
      }

      /**
       *  @summary Tweak a private key by adding tweak to it.
       *  @return {Array} Tweaked private key as array of bytes.
       *  @throws {Error} Decode failed.
       *  @arg {Array} key - Private key to tweak.
       *  @arg {Array} tweak - Tweak to add to private key.
       */
      function privateAdd(key, tweak) {
        if (!key || !Buffer.isBuffer(key) || key.length !== 32) {
          throw new TypeError('key must be a non-empty Buffer of 32 bytes');
        }
        if (!tweak || !Buffer.isBuffer(tweak) || tweak.length !== 32) {
          throw new TypeError('tweak must be a non-empty Buffer of 32 bytes');
        }

        const keyPtr = charStar(key);
        const ret = Module.ccall(
          'ec_seckey_tweak_add',
          'number',
          ['number', 'number'],
          [keyPtr, charStar(tweak)]
        );

        if (ret === 1) {
          const res = new Uint8Array(
            Module.HEAPU8.subarray(keyPtr, keyPtr + 32)
          );
          freeMalloc();
          return Buffer.from(res);
        }
        freeMalloc();
        throw new Error('ec_seckey_tweak_add', ret);
      }

      /**
       *  @summary Tweak a private key by multiplying tweak to it.
       *  @return {Array} Tweaked private key as array of bytes.
       *  @throws {Error} Decode failed.
       *  @arg {Array} key - Private key to tweak.
       *  @arg {Array} tweak - Tweak to multiply by private key.
       */
      function privateMul(key, tweak) {
        if (!key || !Buffer.isBuffer(key) || key.length !== 32) {
          throw new TypeError('key must be a non-empty Buffer of 32 bytes');
        }
        if (!tweak || !Buffer.isBuffer(tweak) || tweak.length !== 32) {
          throw new TypeError('tweak must be a non-empty Buffer of 32 bytes');
        }

        const keyPtr = charStar(key);
        const ret = Module.ccall(
          'ec_seckey_tweak_mul',
          'number',
          ['number', 'number'],
          [keyPtr, charStar(tweak)]
        );

        if (ret === 1) {
          const res = new Uint8Array(
            Module.HEAPU8.subarray(keyPtr, keyPtr + 32)
          );
          freeMalloc();
          return Buffer.from(res);
        }
        freeMalloc();
        throw new Error('ec_seckey_tweak_mul', ret);
      }

      /**
       * @summary check if a point is valid on the curve
       * @argument {Uint8Array} point - point to check
       * @returns {boolean} true if valid, false otherwise
       */
      function isPoint(point) {
        if (!isEccPoint(point)) {
          return false;
        }

        const pointPtr = charStar(point);

        if (point.length === 32) {
          const validXonlyPoint = Module.ccall(
            'is_valid_xonly_pubkey',
            'number',
            ['number'],
            [pointPtr]
          );

          freeMalloc();
          return validXonlyPoint === 1;
        } else {
          const validEcPubkey = Module.ccall(
            'is_valid_ec_pubkey',
            'number',
            ['number', 'number'],
            [pointPtr, point.length]
          );
          freeMalloc();
          return validEcPubkey === 1;
        }
      }

      /**
       *  @summary compress a valid point
       *  @argument {Uint8Array} point - point to compress
       *  @argument {boolean} compressed - true if compressed, false otherwise
       *  @returns {Uint8Array} compressed point
       **/
      function pointCompress(point, compressed) {
        validatePoint(point);
        const outputlen = assumeCompression(compressed, point);
        const output = malloc(outputlen);
        const pointPtr = charStar(point);
        const ret = Module.ccall(
          'point_compress',
          'number',
          ['number', 'number', 'number', 'number'],
          [output, outputlen, pointPtr, point.length]
        );

        if (ret === 1) {
          const res = new Uint8Array(
            Module.HEAPU8.subarray(output, output + outputlen)
          );
          freeMalloc();
          return res;
        }
        freeMalloc();
        throw new Error('point_compress', ret);
      }

      /**
       * check if a point is private
       * @param {Uint8Array} d - point to check
       * @returns {boolean} true if private, false otherwise
       */
      function isPrivate(d) {
        return isPrivatePoint(d);
      }

      /**
       * @summary create point from scalar
       * @param {Uint8Array} d - scalar to check if on the curve
       * @param {*} compressed - true if compressed, false otherwise
       * @returns {Uint8Array | null} point if valid, null otherwise
       */
      function pointFromScalar(d, compressed) {
        validatePrivate(d);
        const outputlen = assumeCompression(compressed);
        const output = malloc(outputlen);
        const dPtr = charStar(d);
        const ret = Module.ccall(
          'point_from_scalar',
          'number',
          ['number', 'number', 'number'],
          [output, outputlen, dPtr, d.length]
        );
        if (ret === 1) {
          const res = new Uint8Array(
            Module.HEAPU8.subarray(output, output + outputlen)
          );
          freeMalloc();
          return res;
        }
        freeMalloc();
        throw new Error('point_from_scalar', ret);
      }

      /**
       * add tweak to an x-only point
       * @param {Uint8Array} p - x-only point
       * @param {Uint8Array} tweak - tweak to add
       * @returns {Uint8Array} x-only point with tweak added
       */
      function xOnlyPointAddTweak(p, tweak) {
        validateXOnlyPoint(p);
        validateTweak(tweak);
        const output = malloc(32);
        const pPtr = charStar(p);
        const tweakPtr = charStar(tweak);
        const parity = Module.ccall(
          'x_only_pubkey_tweak_add',
          'number',
          ['number', 'number', 'number'],
          [output, pPtr, tweakPtr]
        );
        if (parity === -1) {
          freeMalloc();
          throw new Error('x_only_pubkey_tweak_add', parity);
        }
        const res = new Uint8Array(Module.HEAPU8.subarray(output, output + 32));
        freeMalloc();
        return res;
      }

      /**
       * TODO: rename "sign"
       * @summary sign a message using ECDSA
       * @argument {Uint8Array} h - message to sign
       * @argument {Uint8Array} d - private key
       * @argument {Uint8Array | undefined} e - optional, added to the entropy for k generation
       * @returns {Uint8Array} signature
       **/
      function signECDSA(h, d, e) {
        validateHash(h);
        validatePrivate(d);
        validateExtraData(e);
        const output = malloc(64);
        const hPtr = charStar(h);
        const dPtr = charStar(d);
        const ret = Module.ccall(
          'ecdsa_sign',
          'number',
          ['number', 'number', 'number', 'number', 'number'],
          [output, dPtr, hPtr, e ? 1 : 0, e ? charStar(e) : 0]
        );
        if (ret === 1) {
          const res = new Uint8Array(
            Module.HEAPU8.subarray(output, output + 64)
          );
          freeMalloc();
          return res;
        }
        freeMalloc();
        throw new Error('ecdsa_sign', ret);
      }

      /**
       * @summary verify an ECDSA signature
       * @param {Uint8Array} h - message signed
       * @param {Uint8Array} Q - public key
       * @param {Uint8Array} signature - signature to verify
       * @param {Uint8Array} strict - if true, valid signatures with any of (r, s) values greater than order / 2 are rejected
       * @returns {boolean} true if valid, false otherwise
       */
      function verifyECDSA(h, Q, signature, strict) {
        isPoint(Q);
        validateHash(h);
        validateSignature(signature);
        const QPtr = charStar(Q);
        const hPtr = charStar(h);
        const signaturePtr = charStar(signature);
        const ret = Module.ccall(
          'ecdsa_verify',
          'number',
          ['number', 'number', 'number', 'number', 'number'],
          [QPtr, Q.length, hPtr, signaturePtr, strict ? 1 : 0]
        );
        return ret === 1;
      }

      /**
       * @summary sign a message using Schnorr
       * @argument {Uint8Array} h - message to sign
       * @argument {Uint8Array} d - private key
       * @returns {Uint8Array} signature
       **/
      function signSchnorr(h, d) {
        validateHash(h);
        validatePrivate(d);
        const output = malloc(64);
        const hPtr = charStar(h);
        const dPtr = charStar(d);
        const ret = Module.ccall(
          'sign_schnorr',
          'number',
          ['number', 'number', 'number'],
          [output, dPtr, hPtr]
        );
        if (ret === 1) {
          const res = new Uint8Array(
            Module.HEAPU8.subarray(output, output + 64)
          );
          freeMalloc();
          return res;
        }
        freeMalloc();
        throw new Error('schnorr_sign', ret);
      }

      /**
       * @summary verify a Schnorr signature
       * @param {Uint8Array} h - message signed using Schnorr
       * @param {Uint8Array} Q - public key
       * @param {Uint8Array} signature - signature to verify
       * @returns {boolean} true if valid, false otherwise
       */
      function verifySchnorr(h, Q, signature) {
        validateHash(h);
        validatePoint(Q);
        validateSignature(signature);
        const QPtr = charStar(Q);
        const hPtr = charStar(h);
        const signaturePtr = charStar(signature);
        const ret = Module.ccall(
          'verify_schnorr',
          'number',
          ['number', 'number', 'number', 'number'],
          [QPtr, hPtr, 32, signaturePtr]
        );
        return ret === 1;
      }

      function Uint64Long(ptr) {
        return new Long(
          Module.getValue(ptr, 'i32'),
          Module.getValue(ptr + 4, 'i32'),
          true
        );
      }

      function intStar(num) {
        const ptr = malloc(4);
        Module.setValue(ptr, num, 'i32');
        return ptr;
      }

      function charStar(buf) {
        const ptr = malloc(buf.length);
        for (let i = 0; i < buf.length; i++) {
          Module.setValue(ptr + i, buf[i], 'i8');
        }
        return ptr;
      }

      function charStarArray(array) {
        const arrayPtrs = malloc(4 * array.length);
        for (let i = 0; i < array.length; i++) {
          const ptr = charStar(array[i]);
          Module.setValue(arrayPtrs + i * 4, ptr, 'i32');
        }
        return arrayPtrs;
      }

      function longIntStarArray(array) {
        const ptr = malloc(8 * array.length);
        for (let i = 0; i < array.length; i++) {
          Module.setValue(ptr + i * 8, array[i].low, 'i32');
          Module.setValue(ptr + i * 8 + 4, array[i].high, 'i32');
        }
        return ptr;
      }

      resolve({
        isPoint,
        isPrivate,
        pointCompress,
        xOnlyPointAddTweak,
        signECDSA,
        pointFromScalar,
        verifyECDSA,
        signSchnorr,
        verifySchnorr,
        ecdh,
        privateAdd,
        privateNegate,
        privateMul,
        pedersen: {
          commit,
          commitSerialize,
          commitParse,
          blindGeneratorBlindSum,
          blindSum,
          verifySum,
        },
        generator: {
          generate,
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
          parse: proofParse,
          initialize: proofInitialize,
          generate: proofGenerate,
          verify: proofVerify,
        },
      });
    });
  });
};
