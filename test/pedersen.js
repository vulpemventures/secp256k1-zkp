const assert = require("assert");
const createHash = require("create-hash");
const Long = require("long");

const Module = require("../src");
const {
  commit,
  commitParse,
  commitSerialize,
  blindSum,
  verifySum,
} = Module.pedersen;

const MAX_U64 = Long.MAX_UNSIGNED_VALUE.toString();
const sha256 = data =>
  createHash("sha256")
    .update(data)
    .digest();

describe("libsecp256k1-zkp", () => {
  const h1 = sha256("h1"); // blinding factor
  const h2 = sha256("h2");

  describe("pedersen", () => {
    it("blind sum", done => {
      assert.equal(blindSum([h1], 0).length, 32);
      assert.equal(hexId(blindSum([h1], 0)), "cceed11e");
      assert.equal(hexId(blindSum([h1], 1)), "33112ee1");
      assert.equal(hexId(blindSum([h1, h2], 0)), "d355d318");
      assert.equal(hexId(blindSum([h1, h2], 1)), "397830da");
      assert.equal(hexId(blindSum([h1, h2], 2)), "2caa2ce7");
      done();
    });

    it("verify sum", done => {
      const B1 = blindSum([h1]);
      const C1 = commit(B1, 0);
      assert.equal(verifySum([], []), true);
      assert.equal(verifySum([C1], [C1]), true);
      assert.equal(verifySum([C1], []), false);
      assert.equal(verifySum([], [C1]), false);
      done();
    });

    it("commit", done => {
      const blind = blindSum([h1], 0);
      assert.equal(commit(blind, 0).length, 33);
      assert.equal(hexId(commit(blind, 0)), "089253b1");
      assert.equal(hexId(commit(blind, 1)), "09150291");
      assert.equal(hexId(commit(h1, 0)), "099253b1");
      assert.equal(hexId(commit(h1, 1)), "09d014f6");
      assert.equal(hexId(commit(h1, MAX_U64)), "099253b1");
      done();
    });

    it("serialize commit", done => {
      const B1 = blindSum([h1], 0);
      const C1 = commit(B1, 0);
      assert.equal(hexId(commitSerialize(C1)), "089253b1");
      done();
    });

    it("parse commit", done => {
      const C1 = new Uint8Array([
        0x09,
        0xc6,
        0x04,
        0x7f,
        0x94,
        0x41,
        0xed,
        0x7d,
        0x6d,
        0x30,
        0x45,
        0x40,
        0x6e,
        0x95,
        0xc0,
        0x7c,
        0xd8,
        0x5c,
        0x77,
        0x8e,
        0x4b,
        0x8c,
        0xef,
        0x3c,
        0xa7,
        0xab,
        0xac,
        0x09,
        0xb9,
        0x5c,
        0x70,
        0x9e,
        0xe5
      ]);
      assert.equal(hexId(commitParse(C1)), "09c6047f");
      done();
    });
  });
});

const hexId = arr =>
  Buffer.from(arr)
    .slice(0, 4)
    .toString("hex");
