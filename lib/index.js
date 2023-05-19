const lib = require('../dist/secp256k1-zkp.js');
const Long = require('long');

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
       *  @summary calculates a ECDH point
       *  @returns {Array} 32-byte ecdh point
       *  @throws {Error} Decode error
       *  @arg {Array} pubkey 33-byte pubkey
       *  @arg {Array} scalar 32-byte scalar
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
          return out;
        } else {
          freeMalloc();
          throw new Error('secp256k1_ecdh', ret);
        }
      }

      /**
       *  @summary generates a blinding generator
       *  @returns {Array} 33-byte serialized generator
       *  @throws {Error} decode error
       *  @arg {Array} seed 32-byte random seed
       */
      function generatorGenerate(seed) {
        if (!seed || !(seed instanceof Uint8Array) || seed.length !== 32) {
          throw new TypeError('seed must be a Uint8Array of 32 bytes');
        }
        const output = malloc(33);

        const ret = Module.ccall(
          'generator_generate',
          'number',
          ['number', 'number'],
          [output, charStar(seed)]
        );
        if (ret === 1) {
          const out = new Uint8Array(
            Module.HEAPU8.subarray(output, output + 33)
          );
          freeMalloc();
          return out;
        }
        freeMalloc();
        throw new Error('secp256k1_generator_generate', ret);
      }

      /**
       *  @summary generates a blinding generator with a blinding factor
       *  @returns {Array} 33-byte serialzed generator
       *  @throws {Error} decode error
       *  @arg {Array} key 32-byte array key
       *  @arg {Array} blinder 32-byte array blinding factor
       */
      function generatorGenerateBlinded(key, blinder) {
        if (!key || !(key instanceof Uint8Array) || key.length !== 32)
          throw new TypeError('key must be a Uint8Array of 32 bytes');
        if (
          !blinder ||
          !(blinder instanceof Uint8Array) ||
          blinder.length !== 32
        )
          throw new TypeError('blind must be a Uint8Array of 32 bytes');

        const output = malloc(33);

        const ret = Module.ccall(
          'generator_generate_blinded',
          'number',
          ['number', 'number', 'number'],
          [output, charStar(key), charStar(blinder)]
        );
        if (ret === 1) {
          const out = new Uint8Array(
            Module.HEAPU8.subarray(output, output + 33)
          );
          freeMalloc();
          return out;
        } else {
          freeMalloc();
          throw new Error('secp256k1_generator_generate_blinded', ret);
        }
      }

      /**
       *  @summary generates a pedersen commitment
       *  @returns {Array} 33-byte serialized commitment
       *  @throws {Error} decode error
       *  @arg {string} value Uint64 value to commit to as string
       *  @arg {Array} generator 33-byte serialized generator
       *  @arg {Array} blinder 32-byte blinding factor
       */
      function pedersenCommitment(value, generator, blinder) {
        if (
          !generator ||
          !(generator instanceof Uint8Array) ||
          generator.length !== 33
        )
          throw new TypeError('generator must be a Uint8Array of 33 bytes');
        if (
          !blinder ||
          !(blinder instanceof Uint8Array) ||
          blinder.length !== 32
        )
          throw new TypeError('blinder must be a Uint8Array of 32 bytes');

        const output = malloc(33);
        const valueLong = Long.fromString(value, true);

        const ret = Module.ccall(
          'pedersen_commitment',
          'number',
          ['number', 'number', 'number', 'number'],
          [
            output,
            valueLong.low,
            valueLong.high,
            charStar(generator),
            charStar(blinder),
          ]
        );
        if (ret === 1) {
          const out = new Uint8Array(
            Module.HEAPU8.subarray(output, output + 33)
          );
          freeMalloc();
          return out;
        } else {
          freeMalloc();
          throw new Error('secp256k1_pedersen_commit', ret);
        }
      }

      /**
       *  @summary sets the final blinding factor correctly when the generators themselves have blinders
       *  @returns {Array} 32-byte final blinder
       *  @throws {Error} decode error
       *  @arg {Array} values list of uint64 values as string
       *  @arg {Array} assetBlinders list of 32-byte asset blinders
       *  @arg {Array} valueBlinders list of 32-byte value blinders
       *  @arg {number} nInputs how many of the initial array elements represent commitments that will be negated in the final sum
       */
      function pedersenBlindGeneratorBlindSum(
        values,
        assetBlinders,
        valueBlinders,
        nInputs
      ) {
        if (
          !assetBlinders ||
          !Array.isArray(assetBlinders) ||
          !assetBlinders.length ||
          !assetBlinders.every((v) => v instanceof Uint8Array)
        )
          throw new TypeError(
            'asset blinders must be a non-empty list of Uint8Array'
          );
        if (!valueBlinders || !Array.isArray(valueBlinders))
          throw new TypeError('value blinders must be a list of Uint8Array');

        const longValues = values.map((v) => Long.fromString(v, true));
        const blindOut = malloc(32);
        const ret = Module.ccall(
          'pedersen_blind_generator_blind_sum',
          'number',
          ['number', 'number', 'number', 'number', 'number', 'number'],
          [
            longIntStarArray(longValues),
            charStarArray(assetBlinders),
            charStarArray(valueBlinders),
            assetBlinders.length,
            nInputs,
            blindOut,
          ]
        );
        if (ret === 1) {
          const output = new Uint8Array(
            Module.HEAPU8.subarray(blindOut, blindOut + 32)
          );
          freeMalloc();
          return output;
        } else {
          freeMalloc();
          throw new Error('secp256k1_pedersen_blind_generator_blind_sum', ret);
        }
      }

      /**
       *  @summary authors a proof that a committed value is within a range
       *  @returns {Array} proof successfully created
       *  @throws {Error} decode failed
       *  @arg {string} value uint64 value to blind as string.
       *  @arg {Array} valueCommitment 33-byte serialized value pedersen commitment
       *  @arg {Array} assetCommitment 33-byte serialized asset pedersen commitment
       *  @arg {Array} valueBlinder 32-byte value blinding factor
       *  @arg {Array} nonce 32-byte secret nonce used to initialize the proof (value can be reverse-engineered out of the proof if this secret is known.)
       *  @arg {string} minValue constructs a proof where the verifer can tell the minimum value is at least the specified amount
       *  @arg {string} base10Exp base-10 exponent. Digits below above will be made public, but the proof will be made smaller. Allowed range is -1 to 18
       *      (-1 is a special case that makes the value public. 0 is the most private.).
       *  @arg {string} minBits number of bits of the value to keep private. (0 = auto/minimal, 64)
       *  @arg {Array} message optional message
       *  @arg {Array} extraCommitment optional extra commitment
       */
      function rangeProofSign(
        value,
        valueCommitment,
        assetCommitment,
        valueBlinder,
        nonce,
        minValue = '0',
        base10Exp = '0',
        minBits = '0',
        message = new Uint8Array(),
        extraCommitment = new Uint8Array()
      ) {
        if (
          !valueCommitment ||
          !(valueCommitment instanceof Uint8Array) ||
          !valueCommitment.length
        )
          throw new TypeError(
            'value commitment must be a Uint8Array of 33 bytes'
          );
        if (
          !assetCommitment ||
          !(assetCommitment instanceof Uint8Array) ||
          assetCommitment.length !== 33
        )
          throw new TypeError(
            'asset commitment must be a Uint8Array of 33 bytes'
          );
        if (
          !valueBlinder ||
          !(valueBlinder instanceof Uint8Array) ||
          valueBlinder.length !== 32
        )
          throw new TypeError('value blinder must be a Uint8Array of 32 bytes');
        if (!nonce || !(nonce instanceof Uint8Array) || !nonce.length)
          throw new TypeError('nonce must be a Uint8Array of 32 bytes');
        if (!(message instanceof Uint8Array))
          throw new TypeError('message must be a Uint8Array');
        if (!(extraCommitment instanceof Uint8Array))
          throw new TypeError('extra commitment must be a Uint8Array');

        const proof = malloc(5134);
        const plen = malloc(8);
        Module.setValue(plen, 5134, 'i64');
        const minValueLong = Long.fromString(minValue, true);
        const valueLong = Long.fromString(value, true);
        const exp = Number.parseInt(base10Exp, 10);
        const bits = Number.parseInt(minBits, 10);

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
            valueLong.low,
            valueLong.high,
            charStar(valueCommitment),
            charStar(assetCommitment),
            charStar(valueBlinder),
            charStar(nonce),
            exp,
            bits,
            minValueLong.low,
            minValueLong.high,
            charStar(message),
            message.length,
            charStar(extraCommitment),
            extraCommitment.length,
          ]
        );
        if (ret === 1) {
          const out = new Uint8Array(
            Module.HEAPU8.subarray(proof, proof + Module.getValue(plen, 'i64'))
          );
          freeMalloc();
          return out;
        } else {
          freeMalloc();
          throw new Error('secp256k1_rangeproof_sign', ret);
        }
      }

      /**
       *  @typedef {ProofInfo}
       *  @arg {string} exp exponent used in the proof (-1 means the value isn't private)
       *  @arg {string} mantissa number of bits covered by the proof
       *  @arg {string} minValue minimum value that commit could have
       *  @arg {string} maxValue maximum value that commit could have
       */
      /**
       *  @summary returns value info from a range-proof
       *  @returns {ProofInfo} information successfully extracted
       *  @throws {Error} decode failed
       *  @arg {Array} proof range proof for which retrieving info
       */
      function rangeProofInfo(proof) {
        if (!proof || !(proof instanceof Uint8Array) || !proof.length)
          throw new TypeError('proof must be a non empty Uint8Array');

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
            exp: Module.getValue(exp, 'i32').toString(),
            mantissa: Module.getValue(mantissa, 'i32').toString(),
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
       *  @summary verifies a range-proof
       *  @returns {boolean} proof successfully verified
       *  @arg {Array} proof range proof to verify
       *  @arg {Array} valueCommitment 33-byte serialized value commitment
       *  @arg {Array} assetCommitment 33-byte serialized asset commitment
       *  @arg {Array} extraCommitment optional extra commitment
       */
      function rangeProofVerify(
        proof,
        valueCommitment,
        assetCommitment,
        extraCommitment = new Uint8Array()
      ) {
        if (!proof || !(proof instanceof Uint8Array) || !proof.length)
          throw new TypeError('proof must be a non empty Uint8Array');
        if (
          !valueCommitment ||
          !(valueCommitment instanceof Uint8Array) ||
          valueCommitment.length !== 33
        )
          throw new TypeError(
            'value commitment must be a Uint8Array of 33 bytes'
          );
        if (
          !assetCommitment ||
          !(assetCommitment instanceof Uint8Array) ||
          assetCommitment.length !== 33
        )
          throw new TypeError(
            'asset commitment must be a Uint8Array of 33 bytes'
          );
        if (!extraCommitment || !(extraCommitment instanceof Uint8Array))
          throw new TypeError('extra commitment must be a Uint8Array');

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
            charStar(proof),
            proof.length,
            charStar(valueCommitment),
            charStar(assetCommitment),
            charStar(extraCommitment),
            extraCommitment.length,
          ]
        );

        freeMalloc();
        return ret === 1;
      }

      /**
       *  @typedef {ProofRewind}
       *  @arg {string} value unblinded uint64 value as string
       *  @arg {string} minValue minimum value that commit could have
       *  @arg {string} maxValue maximum value that commit could have
       *  @arg {Array} blinder 32-byte blinding factor
       *  @arg {Array} message unblinded optional message
       */
      /**
       *  @summary extracts information from a range-proof
       *  @returns {ProofRewind} information successfully extracted
       *  @throws {Error} decode failed
       *  @arg {Array} proof range proof to rewind
       *  @arg {Array} valueCommitment 33-byte serialized value commitment
       *  @arg {Array} assetCommitment 33-byte serialized asset commitment
       *  @arg {Array} nonce 32-byte secret nonce used to initialize the proof
       *  @arg {Array} extraCommitment optional extra commitment
       */
      function rangeProofRewind(
        proof,
        valueCommitment,
        assetCommitment,
        nonce,
        extraCommitment = new Uint8Array()
      ) {
        if (!proof || !(proof instanceof Uint8Array) || !proof.length)
          throw new TypeError('proof must be a non-empty Uint8Array');
        if (
          !valueCommitment ||
          !(valueCommitment instanceof Uint8Array) ||
          valueCommitment.length !== 33
        )
          throw new TypeError(
            'value commitment must be a Uint8Array of 33 bytes'
          );
        if (
          !assetCommitment ||
          !(assetCommitment instanceof Uint8Array) ||
          assetCommitment.length !== 33
        )
          throw new TypeError(
            'asset commitment must be a Uint8Array of 33 bytes'
          );
        if (!nonce || !(nonce instanceof Uint8Array) || !nonce.length)
          throw new TypeError('nonce must be a non empty Uint8Array');
        if (!extraCommitment || !(extraCommitment instanceof Uint8Array))
          throw new TypeError('extra commitment must be a Uint8Array');

        const blind = malloc(32);
        const value = malloc(8);
        const msg = malloc(64);
        const msgLength = malloc(8);
        const minValue = malloc(8);
        const maxValue = malloc(8);
        Module.setValue(msgLength, 64, 'i64');

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
            minValue,
            maxValue,
            msg,
            msgLength,
            charStar(proof),
            proof.length,
            charStar(valueCommitment),
            charStar(assetCommitment),
            charStar(nonce),
            charStar(extraCommitment),
            extraCommitment.length,
          ]
        );

        if (ret === 1) {
          const blinder = new Uint8Array(
            Module.HEAPU8.subarray(blind, blind + 32)
          );
          const message = new Uint8Array(
            Module.HEAPU8.subarray(msg, msg + Module.getValue(msgLength, 'i64'))
          );
          const out = {
            value: Uint64Long(value).toString(),
            minValue: Uint64Long(minValue).toString(),
            maxValue: Uint64Long(maxValue).toString(),
            blinder,
            message,
          };
          freeMalloc();
          return out;
        } else {
          freeMalloc();
          throw new Error('secp256k1_rangeproof_rewind', ret);
        }
      }

      /**
       *  @summary returns an initialized surjection proof
       *  @returns {Array} serialized surjection proof
       *  @throws {Error} decode failed
       *  @arg {Array} inputTags list of 32-byte input tags
       *  @arg {Array} outputTag 32-byte output tag
       *  @arg {number} maxIterations max number of attempts to compute the proof
       *  @arg {Array} seed 32-byte random seed
       */
      function surjectionProofInitialize(
        inputTags,
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
            'input tags must be a non-empty array of Uint8Arrays of 32 bytes'
          );
        if (
          !outputTag ||
          !(outputTag instanceof Uint8Array) ||
          outputTag.length !== 32
        )
          throw new TypeError('output tag must be a Uint8Array of 32 bytes');
        if (!seed || !(seed instanceof Uint8Array) || seed.length !== 32)
          throw new TypeError('seed must be a Uint8Array of 32 bytes');

        const inputTagsToUse = inputTags.length > 3 ? 3 : inputTags.length;
        const output = malloc(8258);
        const outputLength = malloc(8);
        Module.setValue(outputLength, 8258, 'i64');
        const inIndex = malloc(4);
        Module.setValue(inIndex, 0, 'i32');
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
          ],
          [
            output,
            outputLength,
            inIndex,
            charStarArray(inputTags),
            inputTags.length,
            inputTagsToUse,
            charStar(outputTag),
            maxIterations,
            charStar(seed),
          ]
        );
        if (ret > 0) {
          const proof = new Uint8Array(
            Module.HEAPU8.subarray(
              output,
              output + Module.getValue(outputLength, 'i64')
            )
          );
          const inputIndex = Module.getValue(inIndex, 'i32');
          freeMalloc();
          return { proof, inputIndex };
        } else {
          freeMalloc();
          throw new Error('secp256k1_surjectionproof_initialize', ret);
        }
      }

      /**
       *  @summary generates a surjection proof
       *  @returns {Array} serialized surjection proof
       *  @throws {Error} decode failed
       *  @arg {Array} proof initialized surjection proof
       *  @arg {Array} inputTags list of 33-byte ephemeral input tags
       *  @arg {Array} outputTag 33-byte ephemeral output tag
       *  @arg {number} inputIndex proof input index
       *  @arg {Array} inputBlindingKey 32-byte blinding key for the input tags
       *  @arg {Array} outputBlindingKey 32-byte blinding key for the output tag
       */
      function surjectionProofGenerate(
        proofData,
        inputTags,
        outputTag,
        inputIndex,
        inputBlindingKey,
        outputBlindingKey
      ) {
        if (!proofData || !(proofData instanceof Uint8Array))
          throw new TypeError('proof must be a non-empty Uint8Array');
        if (
          !inputTags ||
          !Array.isArray(inputTags) ||
          !inputTags.length ||
          !inputTags.every((t) => t.length === 33)
        )
          throw new TypeError(
            'input tags must be a non-empty array of Uint8Arrays of 33 bytes'
          );
        if (
          !outputTag ||
          !(outputTag instanceof Uint8Array) ||
          outputTag.length !== 33
        )
          throw new TypeError('ouput tag must be a Uint8Array of 33 bytes');
        if (
          !inputBlindingKey ||
          !(inputBlindingKey instanceof Uint8Array) ||
          inputBlindingKey.length !== 32
        )
          throw new TypeError(
            'input blinding key must be a Uint8Array of 32 bytes'
          );
        if (
          !outputBlindingKey ||
          !(outputBlindingKey instanceof Uint8Array) ||
          outputBlindingKey.length !== 32
        )
          throw new TypeError(
            'output blinding key must be a Uint8Array of 32 bytes'
          );
        if (inputIndex < 0 || inputIndex > inputTags.length)
          throw new TypeError(
            `input index must be a number into range [0, ${inputTags.length}]`
          );

        const output = malloc(8258);
        const outputLength = malloc(8);

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
            'number',
          ],
          [
            output,
            outputLength,
            charStar(proofData),
            proofData.length,
            charStarArray(inputTags),
            inputTags.length,
            charStar(outputTag),
            inputIndex,
            charStar(inputBlindingKey),
            charStar(outputBlindingKey),
          ]
        );
        if (ret === 1) {
          const proof = new Uint8Array(
            Module.HEAPU8.subarray(
              output,
              output + Module.getValue(outputLength, 'i64')
            )
          );
          freeMalloc();
          return proof;
        } else {
          freeMalloc();
          throw new Error('secp256k1_surjectionproof_generate', ret);
        }
      }

      /**
       *  @summary verifies a surjection proof
       *  @returns {boolean} whether the proof is verified
       *  @throws {Error} decode failed
       *  @arg {Array} proof surjection proof to verify
       *  @arg {Array} inputTags list of 33-byte ephemeral input tags
       *  @arg {Array} outputTag 33-byte ephemeral output tag
       */
      function surjectionProofVerify(proof, inputTags, outputTag) {
        if (!proof || !(proof instanceof Uint8Array) || !proof.length)
          throw new TypeError('proof must be a non-empty Uint8Array');
        if (
          !inputTags ||
          !Array.isArray(inputTags) ||
          !inputTags.length ||
          !inputTags.every((t) => t.length === 33)
        )
          throw new TypeError(
            'input tags must be a non-empty array of Uint8Arrays of 33 bytes'
          );
        if (
          !outputTag ||
          !(outputTag instanceof Uint8Array) ||
          outputTag.length !== 33
        )
          throw new TypeError('ouput tag must be a Uint8Array of 33 bytes');

        const ret = Module.ccall(
          'surjectionproof_verify',
          'number',
          ['number', 'number', 'number', 'number', 'number'],
          [
            charStar(proof),
            proof.length,
            charStarArray(inputTags),
            inputTags.length,
            charStar(outputTag),
          ]
        );
        freeMalloc();
        return ret === 1;
      }

      /**
       *  @summary negate a private key
       *  @returns {Array} negated private key
       *  @throws {Error} decode failed
       *  @arg {Array} key 32-byte private key to negate
       */
      function privateNegate(key) {
        if (!key || !(key instanceof Uint8Array) || key.length !== 32) {
          throw new TypeError('key must be a non-empty Uint8Array of 32 bytes');
        }

        const keyPtr = charStar(key);
        const ret = Module.ccall(
          'ec_seckey_negate',
          'number',
          ['number'],
          [keyPtr]
        );

        if (ret === 1) {
          const out = new Uint8Array(
            Module.HEAPU8.subarray(keyPtr, keyPtr + 32)
          );
          freeMalloc();
          return out;
        }
        freeMalloc();
        throw new Error('ec_seckey_negate', ret);
      }

      /**
       *  @summary tweak a private key by adding tweak to it
       *  @returns {Array | null} tweaked private key
       *  @throws {Error} decode failed
       *  @arg {Array} key 32-byte private key to tweak
       *  @arg {Array} tweak 32-byte tweak to add to private key
       */
      function privateAdd(key, tweak) {
        if (!key || !(key instanceof Uint8Array) || key.length !== 32) {
          throw new TypeError('key must be a non-empty Uint8Array of 32 bytes');
        }
        if (!tweak || !(tweak instanceof Uint8Array) || tweak.length !== 32) {
          throw new TypeError(
            'tweak must be a non-empty Uint8Array of 32 bytes'
          );
        }

        const keyPtr = charStar(key);
        const ret = Module.ccall(
          'ec_seckey_tweak_add',
          'number',
          ['number', 'number'],
          [keyPtr, charStar(tweak)]
        );

        let out = null;
        if (ret === 1) {
          out = new Uint8Array(Module.HEAPU8.subarray(keyPtr, keyPtr + 32));
        }
        freeMalloc();
        return out;
      }

      /**
       *  @summary tweak a private key by subtracting tweak to it
       *  @returns {Array} tweaked private key
       *  @throws {Error} decode failed
       *  @arg {Array} key 32-byte private key to tweak
       *  @arg {Array} tweak 32-byte tweak to subtract to private key
       */
      function privateSub(key, tweak) {
        if (!key || !(key instanceof Uint8Array) || key.length !== 32) {
          throw new TypeError('key must be a non-empty Uint8Array of 32 bytes');
        }
        if (!tweak || !(tweak instanceof Uint8Array) || tweak.length !== 32) {
          throw new TypeError(
            'tweak must be a non-empty Uint8Array of 32 bytes'
          );
        }

        const keyPtr = charStar(key);
        const ret = Module.ccall(
          'ec_seckey_tweak_sub',
          'number',
          ['number', 'number'],
          [keyPtr, charStar(tweak)]
        );

        if (ret === 1) {
          const out = new Uint8Array(
            Module.HEAPU8.subarray(keyPtr, keyPtr + 32)
          );
          freeMalloc();
          return out;
        }
        freeMalloc();
        throw new Error('ec_seckey_tweak_sub', ret);
      }

      /**
       *  @summary tweak a private key by multiplying tweak to it
       *  @returns {Array} tweaked private
       *  @throws {Error} decode failed
       *  @arg {Array} key 32-byte private key to tweak
       *  @arg {Array} tweak 32-byte tweak to multiply by private key
       */
      function privateMul(key, tweak) {
        if (!key || !(key instanceof Uint8Array) || key.length !== 32) {
          throw new TypeError('key must be a non-empty Uint8Array of 32 bytes');
        }
        if (!tweak || !(tweak instanceof Uint8Array) || tweak.length !== 32) {
          throw new TypeError(
            'tweak must be a non-empty Uint8Array of 32 bytes'
          );
        }

        const keyPtr = charStar(key);
        const ret = Module.ccall(
          'ec_seckey_tweak_mul',
          'number',
          ['number', 'number'],
          [keyPtr, charStar(tweak)]
        );

        if (ret === 1) {
          const out = new Uint8Array(
            Module.HEAPU8.subarray(keyPtr, keyPtr + 32)
          );
          freeMalloc();
          return out;
        }
        freeMalloc();
        throw new Error('ec_seckey_tweak_mul', ret);
      }

      /**
       * @summary check if a point is valid on the curve
       * @arg {Uint8Array} point - point to check
       * @returns {boolean} true if valid, false otherwise
       */
      function isPoint(point) {
        if (!point || !(point instanceof Uint8Array)) {
          throw new TypeError('point must be a Uint8Array');
        }

        const pointPtr = charStar(point);
        const res = Module.ccall(
          'ec_is_point',
          'number',
          ['number', 'number'],
          [pointPtr, point.length]
        );
        freeMalloc();
        return res === 1;
      }

      /**
       *  @summary compress or uncompress a valid point
       *  @arg {Uint8Array} point - point to (un)compress
       *  @arg {boolean} compress - whether to compress or uncompress
       *  @returns {Uint8Array} compressed point
       **/
      function pointCompress(point, compress = true) {
        if (!point || !(point instanceof Uint8Array)) {
          throw new TypeError('point must be a Uint8Array');
        }

        const output = malloc(65);
        const outputlen = malloc(8);
        Module.setValue(outputlen, 65, 'i64');

        const ret = Module.ccall(
          'ec_point_compress',
          'number',
          ['number', 'number', 'number', 'number', 'number'],
          [output, outputlen, charStar(point), point.length, compress ? 1 : 0]
        );

        if (ret === 1) {
          const res = new Uint8Array(
            Module.HEAPU8.subarray(
              output,
              output + Module.getValue(outputlen, 'i64')
            )
          );
          freeMalloc();
          return res;
        }
        freeMalloc();
        throw new Error('point_compress', ret);
      }

      /**
       * @summary check if a point is private
       * @arg {Uint8Array} point - point to check
       * @returns {boolean} true if private, false otherwise
       */
      function isPrivate(point) {
        if (!point || !(point instanceof Uint8Array)) {
          throw new TypeError('point must be a Uint8Array');
        }

        const dPtr = charStar(point);
        const ret = Module.ccall(
          'ec_seckey_verify',
          'number',
          ['number'],
          [dPtr]
        );
        freeMalloc();
        return ret === 1;
      }

      /**
       * @summary create point from scalar
       * @arg {Uint8Array} scalar - scalar to check if on the curve
       * @arg {boolean} compress - whether to compress or uncompress
       * @returns {Uint8Array | null} point if valid, null otherwise
       */
      function pointFromScalar(scalar, compress = true) {
        if (!scalar || !(scalar instanceof Uint8Array)) {
          throw new TypeError('scalar must be a Uint8Array');
        }

        const output = malloc(65);
        const outputlen = malloc(8);
        Module.setValue(outputlen, 65, 'i64');

        const ret = Module.ccall(
          'ec_point_from_scalar',
          'number',
          ['number', 'number', 'number', 'number'],
          [output, outputlen, charStar(scalar), compress ? 1 : 0]
        );
        if (ret === 1) {
          const res = new Uint8Array(
            Module.HEAPU8.subarray(
              output,
              output + Module.getValue(outputlen, 'i64')
            )
          );
          freeMalloc();
          return res;
        }
        freeMalloc();
        throw new Error('point_from_scalar', ret);
      }

      /**
       * @summary add tweak to an x-only point
       * @arg {Uint8Array} point - x-only point
       * @arg {Uint8Array} tweak - tweak to add
       * @returns {Object} x-only point with tweak added and parity
       */
      function xOnlyPointAddTweak(point, tweak) {
        if (!point || !(point instanceof Uint8Array) || point.length !== 32) {
          throw new TypeError('point must be a Uint8Array of 32 bytes');
        }
        if (!tweak || !(tweak instanceof Uint8Array) || tweak.length !== 32) {
          throw new TypeError('tweak must be a Uint8Array of 32 bytes');
        }
        const output = malloc(32);
        const parityBit = malloc(4);
        Module.setValue(parityBit, 0, 'i32');
        const res = Module.ccall(
          'ec_x_only_point_tweak_add',
          'number',
          ['number', 'number', 'number', 'number'],
          [output, parityBit, charStar(point), charStar(tweak)]
        );
        if (res === 1) {
          const xOnlyPubkey = new Uint8Array(
            Module.HEAPU8.subarray(output, output + 32)
          );
          const parity = Module.getValue(parityBit, 'i32');
          freeMalloc();
          return { xOnlyPubkey, parity };
        }
        freeMalloc();
        return null;
      }

      /**
       * @summary sign a message using ECDSA
       * @arg {Uint8Array} message - message to sign
       * @arg {Uint8Array} privateKey - private key
       * @arg {Uint8Array | undefined} extraEntropy - optional, added to the entropy for k generation
       * @returns {Uint8Array} signature
       **/
      function signECDSA(message, privateKey, extraEntropy) {
        if (!message || !(message instanceof Uint8Array)) {
          throw new TypeError('message must be a Uint8Array');
        }
        if (!privateKey || !(privateKey instanceof Uint8Array)) {
          throw new TypeError('privateKey must be a Uint8Array');
        }
        if (extraEntropy && !(extraEntropy instanceof Uint8Array)) {
          throw new TypeError('extraEntropy must be a Uint8Array');
        }
        const output = malloc(64);
        const hPtr = charStar(message);
        const dPtr = charStar(privateKey);
        const ret = Module.ccall(
          'ec_sign_ecdsa',
          'number',
          ['number', 'number', 'number', 'number', 'number'],
          [
            output,
            dPtr,
            hPtr,
            extraEntropy ? 1 : 0,
            extraEntropy ? charStar(extraEntropy) : 0,
          ]
        );
        if (ret === 1) {
          const res = new Uint8Array(
            Module.HEAPU8.subarray(output, output + 64)
          );
          freeMalloc();
          return res;
        }
        freeMalloc();
        throw new Error('sign_ecdsa', ret);
      }

      /**
       * @summary verify an ECDSA signature
       * @arg {Uint8Array} message - message signed
       * @arg {Uint8Array} publicKey - public key
       * @arg {Uint8Array} signature - signature to verify
       * @arg {Uint8Array} strict - if true, valid signatures with any of (r, s) values greater than order / 2 are rejected
       * @returns {boolean} true if valid, false otherwise
       */
      function verifyECDSA(message, publicKey, signature, strict = false) {
        if (!message || !(message instanceof Uint8Array)) {
          throw new TypeError('message must be a Uint8Array');
        }
        if (!publicKey || !(publicKey instanceof Uint8Array)) {
          throw new TypeError('publicKey must be a Uint8Array');
        }
        if (!signature || !(signature instanceof Uint8Array)) {
          throw new TypeError('signature must be a Uint8Array');
        }
        if (typeof strict !== 'boolean') {
          throw new TypeError('strict must be a boolean');
        }

        const ret = Module.ccall(
          'ec_verify_ecdsa',
          'number',
          ['number', 'number', 'number', 'number', 'number'],
          [
            charStar(publicKey),
            publicKey.length,
            charStar(message),
            charStar(signature),
            strict ? 1 : 0,
          ]
        );
        return ret === 1;
      }

      /**
       * @summary sign a message using Schnorr
       * @arg {Uint8Array} message - message to sign
       * @arg {Uint8Array} privateKey - private key
       * @arg {Uint8Array | undefined} extraEntropy - optional, added to the entropy for k generation
       * @returns {Uint8Array} signature
       **/
      function signSchnorr(message, privateKey, extraEntropy) {
        if (!message || !(message instanceof Uint8Array)) {
          throw new TypeError('message must be a Uint8Array');
        }
        if (!privateKey || !(privateKey instanceof Uint8Array)) {
          throw new TypeError('privateKey must be a Uint8Array');
        }
        if (
          extraEntropy &&
          (!(extraEntropy instanceof Uint8Array) || extraEntropy.length !== 32)
        ) {
          throw new TypeError('extraEntropy must be a 32-byte Uint8Array');
        }

        const output = malloc(64);
        const ret = Module.ccall(
          'ec_sign_schnorr',
          'number',
          ['number', 'number', 'number', 'number', 'number'],
          [
            output,
            charStar(privateKey),
            charStar(message),
            extraEntropy ? 1 : 0,
            extraEntropy ? charStar(extraEntropy) : 0,
          ]
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
       * @arg {Uint8Array} message - message signed using Schnorr
       * @arg {Uint8Array} publicKey - public key
       * @arg {Uint8Array} signature - signature to verify
       * @returns {boolean} true if valid, false otherwise
       */
      function verifySchnorr(message, publicKey, signature) {
        if (!message || !(message instanceof Uint8Array)) {
          throw new TypeError('message must be a Uint8Array');
        }
        if (!publicKey || !(publicKey instanceof Uint8Array)) {
          throw new TypeError('publicKey must be a Uint8Array');
        }
        if (!signature || !(signature instanceof Uint8Array)) {
          throw new TypeError('signature must be a Uint8Array');
        }

        const ret = Module.ccall(
          'ec_verify_schnorr',
          'number',
          ['number', 'number', 'number', 'number'],
          [
            charStar(publicKey),
            charStar(message),
            message.length,
            charStar(signature),
          ]
        );
        freeMalloc();
        return ret === 1;
      }

      function Uint64Long(ptr) {
        return new Long(
          Module.getValue(ptr, 'i32'),
          Module.getValue(ptr + 4, 'i32'),
          true
        );
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
        ecdh,
        ecc: {
          isPoint,
          isPrivate,
          pointCompress,
          xOnlyPointAddTweak,
          sign: signECDSA,
          verify: verifyECDSA,
          pointFromScalar,
          signSchnorr,
          verifySchnorr,
          privateAdd,
          privateNegate,
          privateMul,
          privateSub,
        },
        pedersen: {
          commitment: pedersenCommitment,
          blindGeneratorBlindSum: pedersenBlindGeneratorBlindSum,
        },
        generator: {
          generate: generatorGenerate,
          generateBlinded: generatorGenerateBlinded,
        },
        rangeproof: {
          sign: rangeProofSign,
          info: rangeProofInfo,
          verify: rangeProofVerify,
          rewind: rangeProofRewind,
        },
        surjectionproof: {
          initialize: surjectionProofInitialize,
          generate: surjectionProofGenerate,
          verify: surjectionProofVerify,
        },
      });
    });
  });
};
