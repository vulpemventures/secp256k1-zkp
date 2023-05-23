[![Build Status](https://travis-ci.org/vulpemventures/secp256k1-zkp.png?branch=master)](https://travis-ci.org/vulpemventures/secp256k1-zkp)
[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

# secp256k1-zkp

Essential methods of the secp256k1-zkp lib exported to JS for handling Elements confidential transactions

## Installation

Use the package manager yarn or npm to install secp256k1-zkp.

```bash
yarn add @vulpemventures/secp256k1-zkp

npm install @vulpemventures/secp256k1-zkp

```

## Usage

The library is exported as a function that returns a promise.

```ts
import secp256k1 from '@vulpemventures/secp256k1-zkp'

async function main() {
    const lib = await secp256k1();
    // use the library functions
}

```

## Development

Fetch submodules

```bash
git submodule update --init --recursive
```

Install dependencies

```bash
yarn install
```

Compile the WASM (writes ./lib/secp256k1-zkp.js file)

```bash
yarn compile
```

Build the library

```bash
yarn build
```

Run tests

```bash
yarn test
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)