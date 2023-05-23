import anyTest, { TestInterface } from 'ava';

import fixtures from '../fixtures/pedersen.json';

import { loadSecp256k1ZKP } from './cmodule';
import { ZKP } from './interface';
import { pedersen } from './pedersen';

const test = anyTest as TestInterface<ZKP['pedersen']>;

test.before(async (t) => {
  const cModule = await loadSecp256k1ZKP();
  t.context = pedersen(cModule);
});

test('commitment', (t) => {
  const { commitment } = t.context;

  fixtures.commitment.forEach((f) => {
    const blinder = new Uint8Array(Buffer.from(f.blinder, 'hex'));
    const generator = new Uint8Array(Buffer.from(f.generator, 'hex'));
    t.is(
      Buffer.from(commitment(f.value, generator, blinder)).toString('hex'),
      f.expected
    );
  });
});

test('blind generator blind sum', (t) => {
  const { blindGeneratorBlindSum } = t.context;

  fixtures.blindGeneratorBlindSum.forEach((f) => {
    const assetBlinders = f.assetBlinders.map((b) => Buffer.from(b, 'hex'));
    const valueBlinders = f.valueBlinders.map((b) => Buffer.from(b, 'hex'));
    t.is(
      Buffer.from(
        blindGeneratorBlindSum(
          f.values,
          assetBlinders,
          valueBlinders,
          f.nInputs
        )
      ).toString('hex'),
      f.expected
    );
  });
});
