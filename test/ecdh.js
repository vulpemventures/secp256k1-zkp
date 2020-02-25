const assert = require("assert");

const Module = require("../lib");
const { ecdh } = Module.ecdh;
const fixtures = require("./fixtures/ecdh.json");

describe("ecdh", () => {
  it("ecdh", () => {
    fixtures.ecdh.forEach(f => {
      const pubkey = Buffer.from(f.pubkey, "hex");
      const scalar = Buffer.from(f.scalar, "hex");
      assert.equal(ecdh(pubkey, scalar).toString("hex"), f.expected);
    });
  });
});
