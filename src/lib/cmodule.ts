/// <reference types="emscripten" />
import lib from './secp256k1-zkp';

export interface CModule extends EmscriptenModule {
  ccall: typeof ccall;
  setValue: typeof setValue;
  getValue: typeof getValue;
}

export async function loadSecp256k1ZKP(): Promise<CModule> {
  return lib() as Promise<CModule>;
}
