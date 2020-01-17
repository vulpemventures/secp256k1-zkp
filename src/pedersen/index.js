
/** @module secp256k1.pedersen */
const Long = require('long')
const Module = require('..')
const {malloc, freeMalloc, intStar, charStar, charStarArray, Uint64Long} = require('../MemUtils')

module.exports = {
    commit,
    serializeCommit,
    parseCommit,
    blindSum,
    verifySum,
    rangeProofSign,
    rangeProofInfo,
    rangeProofVerify,
    rangeProofRewind,
    generatorGenerateBlinded,
    surjectionProofParse,
    surjectionProofSerialize,
    surjectionProofInitialize,
    surjectionProofGenerate,
    surjectionProofVerify,
}

/**
 *  @summary Generate a pedersen commitment.
 *  @desription Blinding factors can be generated and verified in the same way as secp256k1 private keys for ECDSA.
 *
 *  @return {Uint8Array} commitment successfully created. (33 bytes)
 *  @arg {Array} blindFactor - 32-byte blinding factor (cannot be NULL)
 *  @arg {uint64} value - unsigned 64-bit integer value to commit to.
 *  @throws Error
 *  @exports
 */

function commit(blindFactor, value) {
    if(!blindFactor || blindFactor.length !== 32)
        throw new TypeError('blindFactor is a required 32 byte array')

    const commitment = malloc(33)
    const valueLong = Long.fromString(String(value), true)

    const ret = Module.ccall(
        'pedersen_commit', 'number',
        ['number', 'number', 'number'],
        [commitment, charStar(blindFactor), valueLong]
    )
    if(ret === 1) {
        const cmt = new Uint8Array(Module.HEAPU8.subarray(commitment, commitment + 33))
        freeMalloc()
        return cmt
    } else {
        freeMalloc()
        throw new Error('secp256k1_pedersen_commit', ret);
    }
}

/**
 *  @summary Serialize a pedersen commitment.
 *
 *  @return {Uint8Array} Serialized pedersen commitment. (33 bytes)
 *  @arg {Array} commitment - 33-byte pedersen commitment (cannot be NULL)
 *  @throws Error
 *  @exports
 */

function serializeCommit(commitment) {
    const out = malloc(33)

    const ret = Module.ccall(
        'pedersen_commitment_serialize', 'number',
        [ 'number', 'number' ],
        [ out, charStar(commitment) ]
    )
    if(ret === 1) {
        const cmt = new Uint8Array(Module.HEAPU8.subarray(out, out + 33))
        freeMalloc()
        return cmt
    } else {
        freeMalloc()
        throw new Error('secp256k1_pedersen_commit', ret);
    }
}

/**
 *  @summary Parse a pedersen commitment.
 *
 *  @return {Uint8Array} Pedersen commitment. (33 bytes)
 *  @arg {Array} input - 33-byte commitment to parse (cannot be NULL)
 *  @throws Error
 *  @exports
 */

function parseCommit(input) {
    const commitment = malloc(33)

    const ret = Module.ccall(
        'pedersen_commitment_parse', 'number',
        [ 'number', 'number' ],
        [ commitment, charStar(input) ]
    )
    if(ret === 1) {
        const cmt = new Uint8Array(Module.HEAPU8.subarray(commitment, commitment + 33))
        freeMalloc()
        return cmt
    } else {
        freeMalloc()
        throw new Error('secp256k1_pedersen_commit', ret);
    }
}

/** Computes the sum of multiple positive and negative blinding factors.
 *
 *  @return {Uint8Array} sum successfully computed (32 bytes)
 *  @arg {Array.<Array>} blinds - 32-byte character arrays for blinding factors.
 *  @arg {number} [nneg = blinds.length] - how many of the initial factors should be treated with a positive sign.
 *  @throws Error
 *  @exports
 */
function blindSum(blinds, nneg = 0) {
    const sum = malloc(32)
    const ret = Module.ccall(
        'pedersen_blind_sum', 'number',
        ['number', 'number', 'number', 'number'],
        [sum, charStarArray(blinds), blinds.length, nneg]
    )
    if(ret === 1) {
        const s = new Uint8Array(Module.HEAPU8.subarray(sum, sum + 32))
        freeMalloc()
        return s
    } else {
        freeMalloc()
        throw new Error('secp256k1_pedersen_blind_sum', ret);
    }
}


/** Verify pedersen commitments - negativeCommits - excess === 0
 * @return {boolean} commitments successfully sum to zero.
 * @throws {Error} Commitments do not sum to zero or other error.
 * @arg {Array} commits: pointer to pointers to 33-byte character arrays for the commitments.
 * @arg {Array} ncommits: pointer to pointers to 33-byte character arrays for negative commitments.
 *
 * This computes sum(commit[0..pcnt)) - sum(ncommit[0..ncnt)) - excess*H == 0.
 *
 * A pedersen commitment is xG + vH where G and H are generators for the secp256k1 group and x is a blinding factor,
 * while v is the committed value. For a collection of commitments to sum to zero both their blinding factors and
 * values must sum to zero.
 *
 */
function verifySum(commits, negativeCommits) {
    const ret = Module.ccall(
        'pedersen_verify_tally', 'number',
        ['number', 'number', 'number', 'number'],
        [charStarArray(commits), commits.length, charStarArray(negativeCommits), negativeCommits.length]
    )
    freeMalloc()
    return ret === 1
}

/*
 * @summary Author a proof that a committed value is within a range.
 *
 * @return {Uint8Array} Proof successfully created.
 * @arg {uint64} minValue: constructs a proof where the verifer can tell the minimum value is at least the specified amount.
 * @arg {Array} commit: 33-byte array with the commitment being proved.
 * @arg {Array} commitBlind: 32-byte blinding factor used by commit.
 * @arg {Array} nonce: 32-byte secret nonce used to initialize the proof (value can be reverse-engineered out of the proof if this secret is known.)
 * @arg {int8} base10Exp: Base-10 exponent. Digits below above will be made public, but the proof will be made smaller. Allowed range is -1 to 18.
 *      (-1 is a special case that makes the value public. 0 is the most private.)
 * @arg {uint8} minBits: Number of bits of the value to keep private. (0 = auto/minimal, - 64).
 * @arg {uint64} actualValue:  Actual value of the commitment.
 * @exports
 *
 *  If min_value or exp is non-zero then the value must be on the range [0, 2^63) to prevent the proof range from spanning past 2^64.
 *
 *  If exp is -1 the value is revealed by the proof (e.g. it proves that the proof is a blinding of a specific value, without revealing the blinding key.)
 *
 *  This can randomly fail with probability around one in 2^100. If this happens, buy a lottery ticket and retry with a different nonce or blinding.
 *
 */
function rangeProofSign(commitment, commitBlind, nonce, actualValue, minValue = 0, base10Exp = 0, minBits = 0, message = null, extraData = null) {
    // array to receive the proof, can be up to 5134 bytes. (cannot be NULL)
    const proof = malloc(5134)
    // *  In/out: plen: point to an integer with the size of the proof buffer and the size of the constructed proof.
    const plen = charStar(8)
    Module.setValue(plen, 5134, 'i64')

    const minValueLong = Long.fromString(String(minValue), true)
    const actualValueLong = Long.fromString(String(actualValue), true)
    const msg = message ? charStar(message) : charStar([])
    const msgLength = message ? message.length : 0
    const data = extraData ? charStar(extraData) : charStar([])
    const dataLength = extraData ? extraData.length : 0

    const ret = Module.ccall(
        'rangeproof_sign', 'number',
        [
            'number', 'number',
            'number',
            'number', 'number', 'number',
            'number', 'number', 'number',
            'number', 'number', 'number', 'number' 
        ],
        [
            proof, plen,
            minValueLong.low, minValueLong.high,
            charStar(commitment), charStar(commitBlind), charStar(nonce),
            base10Exp, minBits, actualValueLong.low, actualValueLong.high,
            msg, msgLength, data, dataLength
        ]
    )
    if(ret === 1) {
        const plenRet = Module.getValue(plen, 'i64')
        const p = new Uint8Array(Module.HEAPU8.subarray(proof, proof + plenRet))
        freeMalloc()
        return p
    } else {
        freeMalloc()
        throw new Error('secp256k1_rangeproof_sign', ret);
    }
}

/**
    @typedef {ProofInfo}
    @property {int8} exp - Exponent used in the proof (-1 means the value isn't private).
    @property {int8} mantissa - Number of bits covered by the proof.
    @property {int64} min - minimum value that commit could have
    @property {int64} max - maximum value that commit could have
*/
/** Extract some basic information from a range-proof.
 *  @return {ProofInfo} 1: Information successfully extracted.
 *  @throws {Error} Decode failed
 *  @arg {Array} proof
 */
function rangeProofInfo(proof) {
    const exp = charStar(4)
    const mantissa = charStar(4)
    const min = charStar(8)
    const max = charStar(8)
    const ret = Module.ccall(
        'rangeproof_info', 'number',
        ['number', 'number', 'number', 'number', 'number', 'number'],
        [exp, mantissa, min, max, charStar(proof), proof.length]
    )

    if(ret === 1) {
        const info = {
            exp: Module.getValue(exp, 'i32'),
            mantissa: Module.getValue(mantissa, 'i32'),
            min: Uint64Long(min).toString(),
            max: Uint64Long(max).toString(),
        }
        freeMalloc()
        return info
    } else {
        freeMalloc()
        throw new Error('secp256k1_rangeproof_info decode failed', ret)
    }
}

/**
    @property {Array} exp - Exponent used in the proof (-1 means the value isn't private).
    @property {int8} mantissa - Number of bits covered by the proof.
    @property {int64} min - minimum value that commit could have
    @property {int64} max - maximum value that commit could have
*/
/** Verify a range-proof.
 *  @return {ProofInfo} 1: Information successfully extracted.
 *  @throws {Error} Decode failed
 *  @arg {Array} proof
 */
function rangeProofVerify(commitment, proof, extraData = []) {
    const min = charStar(8)
    const max = charStar(8)
    const ret = Module.ccall(
        'rangeproof_verify', 'number',
        [
            'number', 'number',
            'number', 'number', 'number',
            'number', 'number'
        ],
        [
            min, max, 
            charStar(commitment), charStar(proof), proof.length,
            charStar(extraData), extraData.length
        ]
    )
    freeMalloc()
    return ret === 1
}

/**
    @typedef {ProofRewind}
    @property {int8} exp - Exponent used in the proof (-1 means the value isn't private).
    @property {int8} mantissa - Number of bits covered by the proof.
    @property {int64} min - minimum value that commit could have
    @property {int64} max - maximum value that commit could have
*/
/** Extract some basic information from a range-proof.
 *  @return {ProofInfo} 1: Information successfully extracted.
 *  @throws {Error} Decode failed
 *  @arg {Array} proof
 */
function rangeProofRewind(commitment, proof, nonce, extraData = []) {
    const blind = malloc(32)
    const value = charStar(8)
    const message = malloc(4096)
    const messageLength = charStar(8)
    const minValue = charStar(8)
    const maxValue = charStar(8)
    // Module.setValue(messageLength, 4096, 'i64')
    const ret = Module.ccall(
        'rangeproof_rewind', 'number',
        [
            'number', 'number', 'number', 'number', 
            'number', 'number', 'number',
            'number', 'number', 'number',
            'number', 'number'
        ],
        [
            blind, value, message, messageLength,
            charStar(nonce), minValue, maxValue,
            charStar(commitment), charStar(proof), proof.length,
            charStar(extraData), extraData.length
        ]
    )

    if(ret === 1) {
        const out = {
            blind: new Uint8Array(Module.HEAPU8.subarray(blind, blind + 32)),
            value: Uint64Long(value).toString(),
            minValue: Uint64Long(minValue).toString(),
            maxValue: Uint64Long(maxValue).toString(),
            message: new Uint8Array(Module.HEAPU8.subarray(message, message + Module.getValue(messageLength, 'i32'))),
        }
        freeMalloc()
        return out
    } else {
        freeMalloc()
        throw new Error('secp256k1_rangeproof_rewind', ret)
    }
}

function generatorGenerateBlinded(input, blindingKey) {
    const output = malloc(64)

    const ret = Module.ccall(
        'generator_generate_blinded', 'number',
        [ 'number', 'number', 'number' ],
        [ output, charStar(input), charStar(blindingKey)]
    )
    if (ret === 1) {
        const out = new Uint8Array(Module.HEAPU8.subarray(output, output + 64))
        freeMalloc()
        return out
    } else {
        freeMalloc()
        throw new Error('secp256k1_generator_generate_blinded', ret)
    }
}

function surjectionProofParse(input) {
    const nInputs = 0
    const usedInputs = malloc(32)
    const data = malloc(8224)
    const ret = Module.call(
        'surjectionproof_parse', 'number',
        [ 'number', 'number', 'number', 'number', 'number' ],
        [nInputs, usedInputs, data, charStar(input), input.length]
    )
    if (ret === 1) {
        const proof = {
            "nInputs": Module.getValue(nInputs, 'i32'),
            "usedInputs": Uint8Array(Module.HEAPU8.subarray(usedInputs, usedInputs + 32)),
            "data": Uint8Array(Module.HEAPU8.subarray(data, data + 32))
        }
        freeMalloc()
        return proof
    } else {
        throw new Error('secp256k1_surjectionproof_parse', ret)
    }
}

function surjectionProofSerialize(proof) {
    const output = malloc(8258)
    const outputlen = malloc(4)
    const ret = Module.ccall(
        'surjectionproof_serialize', 'number',
        [ 'number', 'number', 'number', 'number', 'number' ],
        [ output, outputlen, intStar(proof.nInputs), charStar(proof.usedInputs), charStar(proof.data) ]
    )
    if (ret === 1) {
        const out = Uint8Array(Module.HEAPU8.subarray(outputlen, outputlen + Module.getValue(outputlen, 'i32')))
        freeMalloc()
        return out
    } else {
        freeMalloc()
        throw new Error('secp256k1_surjectionproof_serialize', ret)
    }
}

function surjectionProofInitialize(inTags, inTagsToUse, outTag, maxIterations, seed) {
    const nInputs = malloc(4)
    const usedInputs = malloc(32)
    const data = malloc(8224)
    const inputIndex = malloc(4)
    const ret = Module.ccall(
        'surjectionproof_initialize', 'number',
        [
            'number', 'number', 'number', 'number',
            'number', 'number', 'number',
            'number', 'number', 'number'
        ],
         [
             nInputs, usedInputs, data, inputIndex,
             charStarArray(inTags), inTags.length, inTagsToUse,
             charStar(outTag), maxIterations, charStar(seed)
        ]
    )
    if (ret === 1) {
        const out = {
            'proof': {
                'nInputs': Module.getValue(nInputs, 'i32'),
                'usedInputs': new Uint8Array(Module.HEAPU8.subarray(usedInputs, usedInputs + 32)),
                'data': new Uint8Array(Module.HEAPU8.subarray(data, data + 8224))
            },
            'inputIndex': Module.getValue(inputIndex, 'i32')
        }
        freeMalloc()
        return out
    } else {
        freeMalloc()
        throw new Error('secp256k1_surjectionproof_initialize', ret)
    }
}

function surjectionProofGenerate(proof, inTags, outTag, inIndex, inBlindingKey, outBlindingKey) {
    const cProof = {}
    Object.assign(cProof, proof)
    const nInputs = intStar(cProof.nInputs)
    const usedInputs = charStar(cProof.usedInputs)
    const data = charStar(cProof.data)
    const ret = Module.ccall(
        'surjectionproof_generate', 'number',
        [
            'number', 'number', 'number',
            'number', 'number', 'number', 'number',
            'number', 'number'
        ],
        [
            nInputs, usedInputs, data,
            charStarArray(inTags), inTags.length, charStar(outTag), inIndex,
            charStar(inBlindingKey), charStar(outBlindingKey)
        ]
    )
    if (ret === 1) {
        const p = {
            "nInputs": inTags.length,
            "usedInputs": new Uint8Array(Module.HEAPU8.subarray(usedInputs, usedInputs + 32)),
            "data": new Uint8Array(Module.HEAPU8.subarray(data, data + 8224))
        }
        freeMalloc()
        return p
    } else {
        freeMalloc()
        throw new Error('secp256k1_surjectionproof_generate', ret)
    }
}

function surjectionProofVerify(proof, inTags, outTag) {
    const ret = Module.ccall(
        'surjectionproof_verify', 'number',
        [
            'number', 'number', 'number',
            'number', 'number', 'number'
        ],
        [
            intStar(proof.nInputs), charStar(proof.usedInputs), charStar(proof.data),
            charStarArray(inTags), inTags.length, charStar(outTag)
        ]
    )
    freeMalloc()
    return ret === 1
}

const hexId = arr => Buffer.from(arr).slice(0, 4).toString('hex')