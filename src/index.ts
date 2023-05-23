import { loadSecp256k1ZKP } from './lib/cmodule';
import { ecc } from './lib/ecc';
import { ecdh } from './lib/ecdh';
import { generator } from './lib/generator';
import { ZKP } from './lib/interface';
import { pedersen } from './lib/pedersen';
import { rangeproof } from './lib/rangeproof';
import { surjectionproof } from './lib/surjectionproof';

const secp256k1Function = async (): Promise<ZKP> => {
  const cModule = await loadSecp256k1ZKP();
  return {
    ecdh: ecdh(cModule),
    ecc: ecc(cModule),
    pedersen: pedersen(cModule),
    generator: generator(cModule),
    rangeproof: rangeproof(cModule),
    surjectionproof: surjectionproof(cModule),
  };
};

export default secp256k1Function;
