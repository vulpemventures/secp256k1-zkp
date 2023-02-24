const chai = require('chai');
const assert = chai.assert;

const secp256k1 = require('../lib');
const fixtures = require('./fixtures/generator.json');

describe('generator', () => {
  let generateBlinded, generate;

  before(async () => {
    ({ generateBlinded, generate } = (await secp256k1()).generator);
  });

  it('generate', () => {
    fixtures.generate.forEach((f) => {
      const seed = new Uint8Array(Buffer.from(f.seed, 'hex'));
      assert.deepStrictEqual(
        Buffer.from(generate(seed)).toString('hex'),
        f.expected
      );
    });
  });

  it('generate_blinded', () => {
    fixtures.generateBlinded.forEach((f) => {
      const key = new Uint8Array(Buffer.from(f.key, 'hex'));
      const blindingKey = new Uint8Array(Buffer.from(f.blind, 'hex'));
      assert.deepStrictEqual(
        Buffer.from(generateBlinded(key, blindingKey)).toString('hex'),
        f.expected
      );
    });
  });
});
