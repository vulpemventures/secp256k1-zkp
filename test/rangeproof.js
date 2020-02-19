const assert = require("assert");
const createHash = require("create-hash");
const Long = require("long");

const Module = require("../src");
const { sign, info, verify, rewind } = Module.rangeproof;
const { blindSum, commit } = Module.pedersen;

const MAX_U64 = Long.MAX_UNSIGNED_VALUE.toString();
const sha256 = data =>
  createHash("sha256")
    .update(data)
    .digest();

describe("libsecp256k1-zkp", () => {
  const h1 = sha256("h1"); // blinding factor
  const nonce = sha256("nonce");

  describe("range proof", () => {
    it("proof sign", done => {
      const B1 = blindSum([h1], 0);
      const C1 = commit(B1, 0);

      // All of the following pass and return the same proofs aa the crypto_api in bitshares.
      assert.equal(shaId(sign(C1, B1, nonce, 0)), "a297bd49");
      assert.equal(
        shaId(sign(C1, B1, nonce, 19, 0, 0, MAX_U64)),
        "3ade4c09"
      );
      throws(() => {
        sign(C1, B1, nonce, 0, MAX_U64, 0, MAX_U64);
      }, /secp256k1_rangeproof_sign/);
      throws(() => {
        sign(C1, B1, nonce, 0, 0, 65, MAX_U64);
      }, /secp256k1_rangeproof_sign/);
      throws(() => {
        sign(C1, B1, nonce, -1, 0, 0, 123);
      }, /secp256k1_rangeproof_sign/);
      throws(() => {
        sign(C1, B1, nonce, 18, 0, 0, 123);
      }, /secp256k1_rangeproof_sign/);
      done();
    });

    it("proof info", done => {
      const B1 = blindSum([h1], 0);
      const C1 = commit(B1, 0);
      const P1 = sign(C1, B1, nonce);
      const p1 = info(P1);
      assert.equal(p1.exp, 0);
      assert.equal(p1.mantissa, 1);
      assert.equal(p1.min, 0);
      assert.equal(p1.max, 1);
      done();
    });

    it("proof verify", done => {
      const B1 = blindSum([h1], 0);
      const C1 = commit(B1, 0);
      const P1 = sign(C1, B1, nonce);
      assert.equal(verify(C1, P1), true);
      done();
    });

    it("range proof rewind", done => {
      const B1 = blindSum([h1]);
      const C1 = commit(B1, 0);
      const P1 = sign(C1, B1, nonce);
      const res = rewind(C1, P1, nonce);
      assert.equal(res.value, 0);
      assert.equal(res.minValue, 0);
      assert.equal(res.maxValue, 1);
      assert.equal(hexId(res.blind), "cceed11e");
      done();
    });
  });
});

const hexId = arr =>
  Buffer.from(arr)
    .slice(0, 4)
    .toString("hex");
const shaId = buf =>
  hexId(
    createHash("sha1")
      .update(buf)
      .digest()
  );

function throws(fn, match) {
  try {
    fn();
    assert(false, "Expecting error");
  } catch (error) {
    if (!match.test(error)) {
      error.message = `Error did not match ${match}\n${error.message}`;
      throw error;
    }
  }
}
