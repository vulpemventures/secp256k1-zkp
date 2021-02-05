const assert = require('assert');

const secp256k1 = require('../lib');
const fixtures = require('./fixtures/pedersen.json');

describe('pedersen', () => {
  let commit,
    commitParse,
    commitSerialize,
    blindSum,
    verifySum,
    blindGeneratorBlindSum;

  before(async () => {
    ({
      commit,
      commitParse,
      commitSerialize,
      blindSum,
      verifySum,
      blindGeneratorBlindSum,
    } = (await secp256k1()).pedersen);
  });

  it('blind sum', () => {
    fixtures.blindSum.forEach((f) => {
      const blinds = f.blinds.map((b) => Buffer.from(b, 'hex'));
      assert.deepStrictEqual(
        blindSum(blinds, f.nNegatives).toString('hex'),
        f.expected
      );
    });
  });

  it('verify sum', () => {
    fixtures.verifySum.forEach((f) => {
      const commits = f.commits.map((b) => Buffer.from(b, 'hex'));
      const negativeCommits = f.negativeCommits.map((b) =>
        Buffer.from(b, 'hex')
      );
      assert.deepStrictEqual(verifySum(commits, negativeCommits), f.expected);
    });
  });

  it('commit', () => {
    fixtures.commit.forEach((f) => {
      const blind = Buffer.from(f.blind, 'hex');
      const generator = Buffer.from(f.generator, 'hex');
      assert.deepStrictEqual(
        commit(blind, f.value, generator).toString('hex'),
        f.expected
      );
    });
  });

  it('serialize commit', () => {
    fixtures.commitSerialize.forEach((f) => {
      const commitment = Buffer.from(f.commit, 'hex');
      assert.deepStrictEqual(
        commitSerialize(commitment).toString('hex'),
        f.expected
      );
    });
  });

  it('parse commit', () => {
    fixtures.commitParse.forEach((f) => {
      const commitment = Buffer.from(f.input, 'hex');
      assert.deepStrictEqual(
        commitParse(commitment).toString('hex'),
        f.expected
      );
    });
  });

  it('blind generator blind sum', () => {
    fixtures.blindGeneratorBlindSum.forEach((f) => {
      const blindFactors = f.blindFactors.map((b) => Buffer.from(b, 'hex'));
      const blindGenerators = f.blindGenerators.map((b) =>
        Buffer.from(b, 'hex')
      );
      assert.equal(
        blindGeneratorBlindSum(
          f.values,
          f.nInputs,
          blindGenerators,
          blindFactors
        ).toString('hex'),
        f.expected
      );
    });
  });
});
