const assert = require('assert');

const secp256k1 = require('../lib');
const fixtures = require('./fixtures/generator.json');

describe('generator', () => {
  let generateBlinded, parse, serialize;

  before(async () => {
    ({ generateBlinded, parse, serialize } = (await secp256k1()).generator);
  });

  it('generate_blinded', () => {
    fixtures.generateBlinded.forEach((f) => {
      const key = Buffer.from(f.key, 'hex');
      const blindingKey = Buffer.from(f.blind, 'hex');
      assert.deepStrictEqual(
        generateBlinded(key, blindingKey).toString('hex'),
        f.expected
      );
    });
  });

  it('serialize', () => {
    fixtures.serialize.forEach((f) => {
      const generator = Buffer.from(f.generator, 'hex');
      assert.deepStrictEqual(serialize(generator).toString('hex'), f.expected);
    });
  });

  it('parse', () => {
    fixtures.parse.forEach((f) => {
      const sergen = Buffer.from(f.serializedGenerator, 'hex');
      assert.deepStrictEqual(parse(sergen).toString('hex'), f.expected);
    });
  });
});
