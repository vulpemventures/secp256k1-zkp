import { loadSecp256k1ZKP } from './cmodule';
import { ecc } from './ecc';
import { ecdh } from './ecdh';
import { generator } from './generator';
import { Secp256k1ZKP } from './interface';
import { musig } from './musig';
import { pedersen } from './pedersen';
import { rangeproof } from './rangeproof';
import { surjectionproof } from './surjectionproof';

export const secp256k1Function = async (): Promise<Secp256k1ZKP> => {
  const cModule = await loadSecp256k1ZKP();
  return {
    ecdh: ecdh(cModule),
    ecc: ecc(cModule),
    musig: musig(cModule),
    pedersen: pedersen(cModule),
    generator: generator(cModule),
    rangeproof: rangeproof(cModule),
    surjectionproof: surjectionproof(cModule),
  };
};
