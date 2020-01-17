# Tiny-secp256k1-zkp

## Build steps (with Docker)

```sh
$ npm install
$ git submodule update --init
$ docker build -t secp256k1-js .yarn
$ yarn configure
$ yarn make
$ yarn test
```

## Build steps (without Docker)

```sh
$ npm install
$ git submodule update --init
$ emconfigure ./configure src secp256k1-zkp --enable-module-rangeproof=yes --enable-module-surjectionproof=yes --enable-experimental=yes --enable-module-generator=yes
$ emmake make
$ npm run test
```

NOTE:  
Before runnning `make`, copy the content of `rangeproof.wrapper` and `surjectionproof.wrapper` just before the `#endif` at the very bottom of  `main_impl.h` of the respective C module that you can find at path `secp256k1-zkp/src/module/<rangeproof|surjection>/`.