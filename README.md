# X25519KeyPair _(x25519-key-pair)_

> An X25519 (Curve25519) DH key implementation to work with the crypto-ld LDKeyPair API

## Table of Contents

- [Security](#security)
- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Security

TBD

## Background

This is a low-level level library to generate and serialize X25519 (Curve25519)
key pairs (uses `nacl.box` under the hood).

To actually perform encryption with those keys, we recommend you use
the https://github.com/digitalbazaar/minimal-cipher library.

See also (related specs):

* [Linked Data Proofs](https://w3c-ccg.github.io/ld-proofs/)
* [Linked Data Cryptographic Suite Registry](https://w3c-ccg.github.io/ld-cryptosuite-registry/)

## Install

Requires Node.js 8.3+

To install locally (for development):

```
git clone https://github.com/digitalbazaar/x25519-key-pair.git
cd x25519-key-pair
npm install
```

## Usage

Importing:

```
const {X25519KeyPair} = require('x25519-key-pair');

// Or, if you're testing code in the interactive Node CLI, right in this repo:
const {X25519KeyPair} = require('./');
```

Generating:

```js
const keyPair = await X25519KeyPair.generate({
  controller: 'did:example:1234'
});
// Don't forget to set your key's id. For example, DID + fingerprint
keyPair.id = 'did:example:1234#' + keyPair.fingerprint();
```

Serializing just the public key:

```js
keyPair.publicNode();
// ->
{
  id: 'did:example:1234#z6LSbh9HiAU2zzBdFMdKZGHfg1UjvAYF8C8kYnkfGKuCxYEB',
  type: 'X25519KeyAgreementKey2019',
  controller: 'did:example:1234',
  publicKeyBase58: '1y8BrfAuXTt9yFZ2cmiMRGG5218Raxbfp2ymsFgFATR'
}
```

Serializing both the private and public key:

```js
// a different key pair than the previous example
await keyPair.export()
// ->
 {
  id: 'did:example:1234#z6LSjeJZaUHMvEKW7tEJXV4PrSm61NzxxHhDXF6zHnVtDu9g',
  type: 'X25519KeyAgreementKey2019',
  controller: 'did:example:1234',
  publicKeyBase58: '8y8Q4AUVpmbm2VrXzqYSXrYcAETrFgX4eGPJoKrMWXNv',
  privateKeyBase58: '95tmYuhqSuJqY77FEg78Zy3LFQ1cENxGv2wMvayk7Lqf'
}
```

Deserializing:

```js
// Loading public key only
const keyPair = await X25519KeyPair.from({
  id: 'did:example:1234#z6LSjeJZaUHMvEKW7tEJXV4PrSm61NzxxHhDXF6zHnVtDu9g',
  type: 'X25519KeyAgreementKey2019',
  controller: 'did:example:1234',
  publicKeyBase58: '8y8Q4AUVpmbm2VrXzqYSXrYcAETrFgX4eGPJoKrMWXNv'
});
```

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

Small note: If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © Digital Bazaar
