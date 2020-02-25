const assert = require("assert");

const Module = require("../lib");
const { verify, generate, serialize, initialize } = Module.surjectionproof;
const fixtures = require("./fixtures/surjectionproof.json");

describe("surjection proof", () => {
  it("initialize proof", () => {
    fixtures.initialize.forEach(f => {
      const seed = Buffer.from(f.seed, "hex");
      const inputTags = f.inputTags.map(t => Buffer.from(t, "hex"));
      const outputTag = Buffer.from(f.outputTag, "hex");
      const res = initialize(
        inputTags,
        f.inputTagsToUse,
        outputTag,
        f.maxIterations,
        seed
      );
      assert.deepEqual(res.proof.nInputs, f.expected.proof.nInputs);
      assert.deepEqual(res.proof.data.toString("hex"), f.expected.proof.data);
      assert.deepEqual(
        res.proof.usedInputs.toString("hex"),
        f.expected.proof.usedInputs
      );
      assert.deepEqual(res.proof.inputIndex, f.expected.proof.inputIndex);
    });
  });

  it("generate proof", () => {
    fixtures.generate.forEach(f => {
      const proof = {
        nInputs: f.proof.nInputs,
        data: Buffer.from(f.proof.data, "hex"),
        usedInputs: Buffer.from(f.proof.usedInputs, "hex")
      };
      const ephemeralInputTags = f.ephemeralInputTags.map(v =>
        Buffer.from(v, "hex")
      );
      const ephemeralOutputTag = Buffer.from(f.ephemeralOutputTag, "hex");
      const inputBlindingKey = Buffer.from(f.inputBlindingKey, "hex");
      const outputBlindingKey = Buffer.from(f.outputBlindingKey, "hex");
      const res = generate(
        proof,
        ephemeralInputTags,
        ephemeralOutputTag,
        f.inputIndex,
        inputBlindingKey,
        outputBlindingKey
      );
      assert.deepEqual(res.nInputs, f.expected.proof.nInputs);
      assert.deepEqual(res.data.toString("hex"), f.expected.proof.data);
      assert.deepEqual(
        res.usedInputs.toString("hex"),
        f.expected.proof.usedInputs
      );
    });
  });

  it("serialize proof", () => {
    fixtures.serialize.forEach(f => {
      const proof = {
        nInputs: f.proof.nInputs,
        data: Buffer.from(f.proof.data, "hex"),
        usedInputs: Buffer.from(f.proof.usedInputs, "hex")
      };
      assert.deepEqual(serialize(proof).toString("hex"), f.expected);
    });
  });

  it("verify proof", () => {
    fixtures.verify.forEach(f => {
      const proof = {
        nInputs: f.proof.nInputs,
        data: Buffer.from(f.proof.data, "hex"),
        usedInputs: Buffer.from(f.proof.usedInputs, "hex")
      };
      const ephemeralInputTags = f.ephemeralInputTags.map(v =>
        Buffer.from(v, "hex")
      );
      const ephemeralOutputTag = Buffer.from(f.ephemeralOutputTag, "hex");
      assert.deepEqual(
        verify(proof, ephemeralInputTags, ephemeralOutputTag),
        f.expected
      );
    });
  });
});
