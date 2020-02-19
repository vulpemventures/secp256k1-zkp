const assert = require("assert");
const randomBytes = require("randombytes");

const Module = require("../src");
const {
  parse,
  verify,
  generate,
  serialize,
  initialize,
} = Module.surjectionproof;

describe("libsecp256k1-zkp", () => {
  describe("surjection proof", () => {
    const seed = randomBytes(32);
    const inputTags = [Buffer.alloc(32), Buffer.alloc(32), Buffer.alloc(32)];
    const outputTag = inputTags[0];
    const ephInputTags = [Buffer.alloc(64), Buffer.alloc(64), Buffer.alloc(64)];
    const ephOutputTag = ephInputTags[0];
    const inputBlindKey = Buffer.alloc(32);
    const outputBlindKey = Buffer.alloc(32);

    it("initialize proof", done => {
      const init = initialize(
        inputTags,
        1,
        outputTag,
        100,
        seed
      );
      assert.equal(init.proof.nInputs, 3);
      assert.equal(init.proof.usedInputs.length, 32);
      assert.equal(hexId(init.proof.data), "00000000");
      done();
    });

    it("generate proof", done => {
      const init = initialize(
        inputTags,
        1,
        outputTag,
        100,
        seed
      );
      const proof = generate(
        init.proof,
        ephInputTags,
        ephOutputTag,
        init.inputIndex,
        inputBlindKey,
        outputBlindKey
      );
      assert.equal(proof.nInputs, 3);
      assert.equal(hexId(proof.data), "7690bac7");
      done();
    });

    // it('serialize proof', (done) => {
    //     const init = initialize(inputTags, 1, outputTag, 100, seed)
    //     const proof = generate(init.proof, ephInputTags, ephOutputTag, init.inputIndex, inputBlindKey, outputBlindKey)
    //     const serializedProof = serialize(proof)
    //     console.log(hexId(serializedProof))
    //     done()
    // })

    it("verify proof", done => {
      const init = initialize(
        inputTags,
        1,
        outputTag,
        100,
        seed
      );
      const proof = generate(
        init.proof,
        ephInputTags,
        ephOutputTag,
        init.inputIndex,
        inputBlindKey,
        outputBlindKey
      );
      assert.equal(
        verify(proof, ephInputTags, ephOutputTag),
        false
      );
      done();
    });
  });

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
});

const hexId = arr =>
  Buffer.from(arr)
    .slice(0, 4)
    .toString("hex");
