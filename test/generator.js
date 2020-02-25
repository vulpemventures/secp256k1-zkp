const assert = require("assert");

const Module = require("../lib");
const { generateBlinded, parse, serialize } = Module.generator;
const fixtures = require("./fixtures/generator.json");

describe("generator", () => {
  it("generate_blinded", () => {
    fixtures.generateBlinded.forEach(f => {
      const key = Buffer.from(f.key, "hex");
      const blindingKey = Buffer.from(f.blind, "hex");
      assert.deepEqual(
        generateBlinded(key, blindingKey).toString("hex"),
        f.expected
      );
    });
  });

  it("serialize", () => {
    fixtures.serialize.forEach(f => {
      const generator = Buffer.from(f.generator, "hex");
      assert.deepEqual(serialize(generator).toString("hex"), f.expected);
    });
  });

  it("parse", () => {
    fixtures.parse.forEach(f => {
      const sergen = Buffer.from(f.serializedGenerator, "hex");
      assert.deepEqual(parse(sergen).toString("hex"), f.expected);
    });
  });
});
