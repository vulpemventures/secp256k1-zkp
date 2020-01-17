const assert = require("assert");

const Module = require("../lib");
const {
  commit,
  commitParse,
  commitSerialize,
  blindSum,
  verifySum,
  blindGeneratorBlindSum
} = Module.pedersen;
const fixtures = require("./fixtures/pedersen.json");

describe("pedersen", () => {
  it("blind sum", () => {
    fixtures.blindSum.forEach(f => {
      const blinds = f.blinds.map(b => Buffer.from(b, "hex"));
      assert.deepEqual(
        blindSum(blinds, f.nNegatives).toString("hex"),
        f.expected
      );
    });
  });

  it("verify sum", () => {
    fixtures.verifySum.forEach(f => {
      const commits = f.commits.map(b => Buffer.from(b, "hex"));
      const negativeCommits = f.negativeCommits.map(b => Buffer.from(b, "hex"));
      assert.deepEqual(verifySum(commits, negativeCommits), f.expected);
    });
  });

  it("commit", () => {
    fixtures.commit.forEach(f => {
      const blind = Buffer.from(f.blind, "hex");
      const generator = Buffer.from(f.generator, "hex");
      assert.deepEqual(
        commit(blind, f.value, generator).toString("hex"),
        f.expected
      );
    });
  });

  it("serialize commit", () => {
    fixtures.commitSerialize.forEach(f => {
      const commitment = Buffer.from(f.commit, "hex");
      assert.deepEqual(commitSerialize(commitment).toString("hex"), f.expected);
    });
  });

  it("parse commit", () => {
    fixtures.commitParse.forEach(f => {
      const commitment = Buffer.from(f.input, "hex");
      assert.deepEqual(commitParse(commitment).toString("hex"), f.expected);
    });
  });

  it("blind generator blind sum", () => {
    fixtures.blindGeneratorBlindSum.forEach(f => {
      const blindFactors = f.blindFactors.map(b => Buffer.from(b, "hex"));
      const blindGenerators = f.blindGenerators.map(b => Buffer.from(b, "hex"));
      assert.equal(
        blindGeneratorBlindSum(
          f.values,
          f.nInputs,
          blindGenerators,
          blindFactors
        ).toString("hex"),
        f.expected
      );
    });
  });
});
