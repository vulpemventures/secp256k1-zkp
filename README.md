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
$ emconfigure ./configure src secp256k1-zkp --enable-module-rangeproof=yes --enable-module-surjectionproof=yes --enable-experimental=yes --enable-module-generator=yes --enable-module-ecdh=yes
$ emmake make
$ npm run test
```
