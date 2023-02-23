const chai = require('chai');
const assert = chai.assert;
const secp256k1 = require('../lib');
const fixtures = require('./fixtures/points.json');

describe('points', () => {
  let isPoint;
  let pointFromScalar;
  let pointCompress;

  before(async () => {
    const lib = await secp256k1();
    isPoint = lib.isPoint;
    pointCompress = lib.pointCompress;
    pointFromScalar = lib.pointFromScalar;
  });

  describe('isPoint', () => {
    for (const f of fixtures.valid.isPoint) {
      it(`should return true for ${f.P}`, async () => {
        const point = Buffer.from(f.P, 'hex');
        assert.strictEqual(isPoint(point), f.expected);
      });
    }
  });

  describe('pointCompress', () => {
    for (const f of fixtures.valid.pointCompress) {
      it(`should return ${f.expected} for ${f.P}`, () => {
        const p = Buffer.from(f.P, 'hex');
        if (f.noarg) {
          assert.strictEqual(
            Buffer.from(pointCompress(p)).toString('hex'),
            f.expected
          );
        } else {
          assert.strictEqual(
            Buffer.from(pointCompress(p, f.compress)).toString('hex'),
            f.expected
          );
        }
      });
    }

    for (const f of fixtures.invalid.pointCompress) {
      it(`should throw for ${f.P}`, () => {
        const p = Buffer.from(f.P, 'hex');
        assert.throws(() => {
          pointCompress(p, f.compress);
        });
      });
    }
  });

  describe('pointFromScalar', () => {
    for (const f of fixtures.valid.pointFromScalar) {
      it(`should return ${f.expected} for ${f.d}`, () => {
        const d = Buffer.from(f.d, 'hex');
        const expected = Buffer.from(f.expected, 'hex');
        let description = `${f.d} * G = ${f.expected}`;
        if (f.description) description += ` (${f.description})`;
        assert.strictEqual(
          Buffer.from(pointFromScalar(d)).toString('hex'),
          f.expected,
          description
        );
        if (f.expected === null) return;
        assert.strictEqual(
          Buffer.from(pointFromScalar(d, true)).toString('hex'),
          Buffer.from(pointCompress(expected, true)).toString('hex'),
          description
        );
        assert.strictEqual(
          Buffer.from(pointFromScalar(d, false)).toString('hex'),
          Buffer.from(pointCompress(expected, false)).toString('hex'),
          description
        );
      });
    }

    for (const f of fixtures.invalid.pointFromScalar) {
      it(`should throw for ${f.d}`, () => {
        const d = Buffer.from(f.d, 'hex');
        assert.throws(() => {
          pointFromScalar(d);
        });
      });
    }
  });
});
