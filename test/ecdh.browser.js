const assert = chai.assert;

describe('ecdh', () => {
  it('ecdh', async () => {
    const t00 = performance.now();
    const { ecdh } = await secp256k1();
    const t01 = performance.now();
    console.log(`Instance of secp256 ${t01 - t00} milliseconds.`);

    const response = await fetch('fixtures/ecdh.json');
    const fixtures = await response.json();

    fixtures.ecdh.forEach((f) => {
      const t0 = performance.now();
      const pubkey = fromHexString(f.pubkey);
      const scalar = fromHexString(f.scalar);
      const t1 = performance.now();

      console.log(
        `Going from hex to arry buffer took ${t1 - t0} milliseconds.`
      );

      const t2 = performance.now();
      const result = ecdh(pubkey, scalar).toString('hex');
      const t3 = performance.now();

      console.log(`Call to ecdh took ${t3 - t2} milliseconds.`);

      assert.strictEqual(result, f.expected);
    });
  });
});

const fromHexString = (hexString) =>
  new Uint8Array(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

const toHexString = (bytes) =>
  bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
