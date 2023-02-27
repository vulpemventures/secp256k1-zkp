# Secp256k1-zkp

[![Build Status](https://travis-ci.org/vulpemventures/secp256k1-zkp.png?branch=master)](https://travis-ci.org/vulpemventures/secp256k1-zkp)
[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

This library is under development, and, like the [secp256k1-zkp](https://github.com/ElementsProject/secp256k1-zkp) C library it depends on, this is a research effort to determine an optimal API for end-users of the liquidjs ecosystem.

## Installation

### Build steps (with Docker)

```sh
# Install node dependencies
$ npm install

# Pull the latest secp256k1-zkp as a git submodule
$ git submodule update --init

# This will copy secp256k1-zkp folder along with the main.c wrapper and build with emscripten inside the docker container
$ npm run compile
```

## Bundle for browsers

```sh
$ npx browserify lib/index.js --standalone secp256k1 > bundle.browser.js
```

## Test

```sh
# lint & prettier & node
$ npm run test
# Only node
$ npm run unit:node
# Only browser
$ npm run unit:web
```

## Usage


### Install

```sh
$ npm install vulpemventures/secp256k1-zkp
# or with yarn
$ yarn add vulpemventures/secp256k1-zkp
```

### Import

```js
const secp256k1 = require('secp256k1-zkp');

// secp256k1 returns a Promise that must be resolved before using the exported methods
const { rangeproof, surjectionproof } = await secp256k1();

rangeproof.rewind(...)
surjectionproof.verify(...)
```

## Documentation

### Ecdh

#### ecdh(pubkey, scalar)

```haskell
ecdh :: Buffer -> Buffer -> Buffer
```

Compute an EC Diffie-Hellman secret in constant time.

- `pubkey` 33-byte representation of a point.
- `scalar` 32-byte arrayscalar with which to multiply the point.

### Ecc

#### isPoint(point)

```haskell
isPoint :: Buffer -> Bool
```

Whether a point is valid or not.
- `point` 33-byte (compressed) or 65-bytes (uncompressed) representation of a point.

#### isPrivate(key)

```haskell
isPrivate :: Buffer -> Bool
```

Whether a scalar is valid to be used as a private key.
- `key` 32-byte scalar.

#### privateNegate(key)

```haskell
privateNegate :: Buffer -> Buffer
```

Negate a private key.
- `key` 32-byte scalar.

#### privateAdd(key, tweak)

```haskell
privateAdd :: Buffer -> Buffer -> Buffer
```

Add a tweak to a private key.
- `key` 32-byte scalar.
- `tweak` 32-byte scalar.

#### privateMul(key, tweak)

```haskell
privateMul :: Buffer -> Buffer -> Buffer
```

Multiply a private key by a tweak.
- `key` 32-byte scalar.
- `tweak` 32-byte scalar.

#### pointCompress(point[, compressed])

```haskell
pointCompress :: Buffer -> Bool -> Buffer
```

Compress or uncompress a point.
- `point` 33-byte (compressed) or 65-bytes (uncompressed) representation of a point.
- `compressed` unused.

### pointFromScalar(scalar[, compressed])

```haskell
pointFromScalar :: Buffer -> Bool -> Buffer
```

Compute a public key from a secret key.
- `scalar` 32-byte scalar.
- `compressed` unused.

#### xOnlyPointAddTweak(point, tweak)

```haskell
xOnlyPointAddTweak :: Buffer -> Buffer -> Buffer
```

Add a tweak to a point.
- `point` 32-byte x-only point.
- `tweak` 32-byte scalar.

#### sign(message, privateKey[, extraEntropy])

```haskell
sign :: Buffer -> Buffer -> Buffer -> Buffer
```

Sign a message using the private key (ECDSA with RFC6979 nonce generation).
- `message` message to sign.
- `privateKey` 32-byte private key.
- `extraEntropy` 32-byte extra entropy to add to the nonce generation, if not specified: null.

#### verify(message, publicKey, signature, [, strict])

```haskell
verify :: Buffer -> Buffer -> Buffer -> Bool -> Bool
```

Verify an ECDSA signature.
- `message` message to verify.
- `publicKey` 33-byte (compressed) or 65-bytes (uncompressed) representation of a point.
- `signature` 64-byte signature.
- if true valid signatures with any of (r, s) values greater than order / 2 are rejected. if not specified: false.

#### signSchnorr(message, privateKey[, extraEntropy])

```haskell
signSchnorr :: Buffer -> Buffer -> Buffer -> Buffer
```

Sign a message using Schnorr following BIP340.
- `message` 32-byte message to sign.
- `privateKey` 32-byte private key.
- `extraEntropy` 32-byte extra entropy to add to the nonce generation, if not specified: '00' * 32.

#### verifySchnorr(message, publicKey, signature)

```haskell
verifySchnorr :: Buffer -> Buffer -> Buffer -> Bool
```

Verify a Schnorr signature following BIP340.
- `message` 32-byte message to verify.
- `publicKey` 32-byte x-only public key.
- `signature` 64-byte signature.

### Generator

#### generate(seed)

```haskell
generate :: Buffer -> Buffer
```

Generate a blinding generator.
- `seed` 32-byte seed.

#### generateBlinded(key, blinder)

```haskell
generateBlinded :: Buffer -> Buffer -> Buffer
```

Generate a blinded generator for the curve.

- `key` 32-byte key.
- `blinder` 32-byte secret value to blind the generator with.


### Pedersen

#### commitment(value, generator, blinder)

```haskell
commit :: String -> Buffer -> Buffer -> Buffer
```

Generate a pedersen commitment.

- `value` uint64 value to commit to as string.
- `generator` 33-byte generator to commit to.
- `blinder` 32-byte blinding factor.

#### blindGeneratorBlindSum(values, assetBlinders, valueBlinders, nInputs)

```haskell
blindGeneratorBlindSum :: Array -> Array -> Array -> Number -> Buffer
```

Set the final Pedersen blinding factor correctly when the generators themselves have blinding factors.

- `values` array of string asset values.
- `assetBlinders` array of asset blinding factors.
- `valueBlinders` array of value blinding factors.
- `nInputs` How many of the initial array elements represent commitments that will be negated in the final sum.

### Rangeproof

#### sign(commit, blind, nonce, value[, minValue="0", base10Exp=0, minBits=0, message=[], extraCommit=[]])

```haskell
sign :: Buffer -> Buffer -> Buffer -> String [-> String -> Number -> Number -> Buffer -> Buffer] -> Buffer
```

Author a proof that a committed value is within a range.

- `commit` 33-byte commitment to being proved.
- `blind` 32-byte blinding factor used by commit.
- `nonce` 32-byte secret nonce used to initialize the proof.
- `value` actual value of the commitment as string.
- `minValue` constructs a proof where the verifer can tell the minimum value is at least the specified amount (passed as string).
- `base10Exp` base-10 exponent. Digits below above will be made public, but the proof will be made smaller. Allowed range is -1 to 18.
- `minBits` number of bits of the value to keep private. (0 = auto/minimal, - 64).
- `message` data to be embedded in the rangeproof that can be recovered by rewinding the proof.
- `extraCommit` additional data to be covered in rangeproof signature.

#### info(proof)

```haskell
info :: Object -> Object
```

Extract some basic information from a range-proof.

- `proof` rangeproof to extract information to.

#### verify(commit, proof[, extraCommit=[]])

```haskell
verify :: Buffer -> Object [-> Buffer] -> Bool
```

Verify a proof that a committed value is within a range.

- `commit` 33-byte commitments being proved.
- `proof` rangeproof used to verify commitment.
- `extraCommit` additional data covered in rangeproof signature.

#### rewind(commit, proof, nonce[, extraCommit = []])

```haskell
rewind :: Buffer -> Object -> Buffer [-> Buffer] -> Object
```

Verify a range proof and rewind the proof to recover information sent by its author.

- `commit` 33-byte commitment being proved.
- `proof` rangeproof.
- `nonce` 32-byte secret nonce used by the prover.
- `extraCommit` additional data covered in rangeproof signature.

Returns wether the value is within the range [0..2^64), the specifically proven range is in the min/max value outputs, and the value and blinding were recovered.

- `value` uint64 which has the exact value of the commitment.
- `minValue` uint64 which will be updated with the minimum value that commit could have.
- `maxValue` uint64 which will be updated with the maximum value that commit could have.
- `blindFactor` 32-byte blinding factor used for the commitment.
- `message` message data from the proof author.

### Surjectionproof

#### initialize(inputTags, inputTagsToUse, outputTag, maxIterations, seed)

```haskell
initialize :: Array -> Number -> Buffer -> Number -> Buffer
```

Initialize a surjection proof.

- `inputTags` fixed input tags `A_i` for all inputs.
- `inputTagsToUse` the number of inputs to select randomly to put in the anonymity set.
- `outputTag` fixed output tag.
- `maxIterations` the maximum number of iterations to do before giving up.
- `seed` a random seed to be used for input selection.

#### generate(proof, inputTags, outputTag, inputIndex, inputBlindingKey, outputBlindingKey)

```haskell
generate :: Object -> Array -> Buffer -> Number -> Buffer -> Buffer -> Buffer
```

Generate an initialized surjection proof.

- `proof` initialized surjection proof
- `inputTags` the ephemeral asset tag of all inputs.
- `outputTag` the ephemeral asset tag of the output.
- `inputIndex` the index of the input that actually maps to the output.
- `inputBlindingKey` the blinding key of the input.
- `outputBlindingKey` the blinding key of the output.

#### verify(proof, inputTags, outputTag)

```haskell
verify :: Object -> Array -> Buffer -> Bool
```

Verify a surjection proof.

- `proof` surjection proof to be verified.
- `inputTags` the ephemeral asset tag of all inputs.
- `outputTag` the ephemeral asset tag of the output.

---

## Credit

This library uses the native library [secp256k1-zkp](https://github.com/ElementsProject/secp256k1-zkp) by the Elements Project developers, including derivatives of its tests and test vectors.

# LICENSE [MIT](LICENSE)
