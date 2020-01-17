const assert = require('assert')
const createHash = require('create-hash')
const randomBytes = require('randombytes')
const Long = require('long')

const Module = require('..')
const pedersen = require('.')

const MAX_U64 = Long.MAX_UNSIGNED_VALUE.toString()
const sha256 = data => createHash('sha256').update(data).digest()
const {
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
    surjectionProofInitialize,
    surjectionProofGenerate,
    surjectionProofVerify,
    surjectionProofSerialize,
} = pedersen

describe('libsecp256k1-zkp', () => {

    before((done) => {
        Module.initPromise.then(() => {
            console.log("runtime initialized")
            done()
        })
    })

    const h1 = sha256('h1') // blinding factor
    const h2 = sha256('h2')
    const nonce = sha256('nonce')

    describe('pedersen', () => {

        it('blind sum', (done) => {
            assert.equal(blindSum([h1], 0).length, 32)
            assert.equal(hexId(blindSum([h1], 0)), 'cceed11e')
            assert.equal(hexId(blindSum([h1], 1)), '33112ee1')
            assert.equal(hexId(blindSum([h1, h2], 0)), 'd355d318')
            assert.equal(hexId(blindSum([h1, h2], 1)), '397830da')
            assert.equal(hexId(blindSum([h1, h2], 2)), '2caa2ce7')
            done()
        })

        it('verify sum', (done) => {
            const B1 = blindSum([h1])
            const C1 = commit(B1, 0)
            assert.equal(verifySum([], []), true)
            assert.equal(verifySum([C1], [C1]), true)
            assert.equal(verifySum([C1], []), false)
            assert.equal(verifySum([], [C1]), false)
            done()
        })

        it('commit', (done) => {
            const blind = blindSum([h1], 0)
            assert.equal(commit(blind, 0).length, 33)
            assert.equal(hexId(commit(blind, 0)), '089253b1')
            assert.equal(hexId(commit(blind, 1)), '09150291')
            assert.equal(hexId(commit(h1, 0)), '099253b1')
            assert.equal(hexId(commit(h1, 1)), '09d014f6')
            assert.equal(hexId(commit(h1, MAX_U64)), '099253b1')
            done()
        })

        it('serialize commit', (done) => {
            const B1 = blindSum([h1], 0)
            const C1 = commit(B1, 0)
            assert.equal(hexId(serializeCommit(C1)), '089253b1')
            done()
        })

        it ('parse commit', (done) => {
            const C1 = new Uint8Array([
                0x09,
                0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8,
                0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5
            ])
            assert.equal(hexId(parseCommit(C1)), '09c6047f')
            done()
        })
    })

    describe('range proof', () => {

        it('proof sign', (done) => {
            const B1 = blindSum([h1], 0)
            const C1 = commit(B1, 0)

            // All of the following pass and return the same proofs aa the crypto_api in bitshares.
            assert.equal(shaId(rangeProofSign(C1, B1, nonce, 0)), 'a297bd49')
            assert.equal(shaId(rangeProofSign(C1, B1, nonce, 19, 0, 0, MAX_U64)), '3ade4c09')
            throws(() => {rangeProofSign(C1, B1, nonce, 0, MAX_U64, 0, MAX_U64)}, /secp256k1_rangeproof_sign/)
            throws(() => {rangeProofSign(C1, B1, nonce, 0, 0, 65, MAX_U64)}, /secp256k1_rangeproof_sign/)
            throws(() => {rangeProofSign(C1, B1, nonce, -1, 0, 0, 123)}, /secp256k1_rangeproof_sign/)
            throws(() => {rangeProofSign(C1, B1, nonce, 18, 0, 0, 123)}, /secp256k1_rangeproof_sign/)
            done()
        })

        it('proof info', (done) => {
            const B1 = blindSum([h1], 0)
            const C1 = commit(B1, 0)
            const P1 = rangeProofSign(C1, B1, nonce)
            const p1 = rangeProofInfo(P1)
            assert.equal(p1.exp, 0)
            assert.equal(p1.mantissa, 1)
            assert.equal(p1.min, 0)
            assert.equal(p1.max, 1)
            done()
        })

        it('proof verify', (done) => {
            const B1 = blindSum([h1], 0)
            const C1 = commit(B1, 0)
            const P1 = rangeProofSign(C1, B1, nonce)
            assert.equal(rangeProofVerify(C1, P1), true)
            done()
        })

        it('range proof rewind', (done) => {
            const B1 = blindSum([h1])
            const C1 = commit(B1, 0)
            const P1 = rangeProofSign(C1, B1, nonce)
            const res = rangeProofRewind(C1, P1, nonce)
            assert.equal(res.value, 0)
            assert.equal(res.minValue, 0)
            assert.equal(res.maxValue, 1)
            assert.equal(hexId(res.blind), 'cceed11e')
            done()
        })
    })

    describe('surjection proof', () => {
        const seed = randomBytes(32)
        const inputTags = [
            Buffer.alloc(32),
            Buffer.alloc(32),
            Buffer.alloc(32),
          ]
        const outputTag = inputTags[0]
        const ephInputTags = [
            Buffer.alloc(64),
            Buffer.alloc(64),
            Buffer.alloc(64),
        ]
        const ephOutputTag = ephInputTags[0]
        const inputBlindKey = Buffer.alloc(32)
        const outputBlindKey = Buffer.alloc(32)
        
        it('initialize proof', (done) => {
            const init = surjectionProofInitialize(inputTags, 1, outputTag, 100, seed)
            assert.equal(init.proof.nInputs, 3)
            assert.equal(init.proof.usedInputs.length, 32)
            assert.equal(hexId(init.proof.data), '00000000')
            done()
        })

        it('generate proof', (done) => {
            const init = surjectionProofInitialize(inputTags, 1, outputTag, 100, seed)
            const proof = surjectionProofGenerate(init.proof, ephInputTags, ephOutputTag, init.inputIndex, inputBlindKey, outputBlindKey)
            assert.equal(proof.nInputs, 3)
            assert.equal(hexId(proof.data), '7690bac7')
            done()
        })

        // it('serialize proof', (done) => {
        //     const init = surjectionProofInitialize(inputTags, 1, outputTag, 100, seed)
        //     const proof = surjectionProofGenerate(init.proof, ephInputTags, ephOutputTag, init.inputIndex, inputBlindKey, outputBlindKey)
        //     const serializedProof = surjectionProofSerialize(proof)
        //     console.log(hexId(serializedProof))
        //     done()
        // })

        it('verify proof', (done) => {
            const init = surjectionProofInitialize(inputTags, 1, outputTag, 100, seed)
            const proof = surjectionProofGenerate(init.proof, ephInputTags, ephOutputTag, init.inputIndex, inputBlindKey, outputBlindKey)
            assert.equal(surjectionProofVerify(proof, ephInputTags, ephOutputTag), false)
            done()
        })
    })

    // describe('usage', () => {

    //     const BF1 = randomBytes(32) // secret
    //     const BF2 = randomBytes(32) // secret
    //     const amount1 = randomBytes(1)[0]
    //     const amount2 = randomBytes(1)[0]
    //     let C1, C2

    //     before((done) => {
    //         C1 = commit(BF1, amount1)
    //         C2 = commit(BF2, amount2)
    //         done()
    //     })

    //     it('proof', () => {
    //         const nonce = randomBytes(32)
    //         const P1 = rangeProofSign(0, C1, BF1, nonce, 0, 0, amount1)
    //         const p1 = rangeGetInfo(P1)
    //         assert.equal(p1.exp, 0)
    //         assert(p1.mantissa <= 8, p1.mantissa)
    //         assert.equal(p1.min, 0)
    //         assert(p1.max <= 255, p1.max)
    //     })

    //     it('verify sum', () => {
    //         // @see https://www.weusecoins.com/confidential-transactions
    //         // Commitments can be added, and the sum of a set of commitments is
    //         // the same as a commitment to the sum of the data.

    //         // C(BF1, amount1) + C(BF2, amount2) == C(BF1 + BF2, amount1 + amount2)
    //         const C3 = commit(blindSum([BF1, BF2]), amount1 + amount2)
    //         assert(verifySum([C1, C2], [C3]))
    //         assert(verifySum([C1], [C1]))
    //         assert(verifySum([C2], [C2]))
    //         assert(verifySum([C3], [C3]))

    //         // TODO: C(BF1, amount1) + C(BF2, amount2) - C(BF4, data4) == 0
    //     })

    //     it('medium proof', () => {
    //         const nonce = randomBytes(32)
    //         const B1 = blindSum([BF1], 0)
    //         const P1 = rangeProofSign(0, C1, B1, nonce, 0, 0, MAX_U64) // S L O W
    //         const p1 = rangeGetInfo(P1)
    //         assert.equal(p1.exp, 0)
    //         assert.equal(p1.mantissa, 64)
    //         assert(p1.min >= 0, p1.min)
    //         assert(p1.max == Long.MAX_UNSIGNED_VALUE.toString(), p1.max)
    //     })

    //     it('strong proof', () => {
    //         const nonce = randomBytes(32)
    //         const B1 = blindSum([BF1], 0)
    //         const P1 = rangeProofSign(0, C1, B1, nonce, 0, 0, Math.pow(2, 32))
    //         const p1 = rangeGetInfo(P1)
    //         assert.equal(p1.exp, 0)
    //         assert.equal(p1.mantissa, 33)
    //         assert(p1.min >= 0)
    //         assert(p1.max == Math.pow(2, 33) - 1, p1.max)
    //     })
    // })
})

// const hex = arr => Buffer.from(arr).toString('hex')
const hexId = arr => Buffer.from(arr).slice(0, 4).toString('hex')
const shaId = buf => hexId(createHash('sha1').update(buf).digest())

function throws(fn, match) {
    try {
        fn()
        assert(false, 'Expecting error')
    } catch(error) {
        if(!match.test(error)) {
            error.message = `Error did not match ${match}\n${error.message}`
            throw error
        }
    }
}
