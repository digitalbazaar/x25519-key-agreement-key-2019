# @digitalbazaar/x25519-key-agreement-key-2019 ChangeLog

## 5.0.0 - 2021-03-17

## Changed
- Update to use `crypto-ld v5.0`.
- **BREAKING**: Removed helper methods `addPublicKey` and `addPrivateKey`.

## 4.1.0 - 2021-03-14

### Added
- `fromEdKeyPair()` is now an alias for `fromEd25519VerificationKey2018()` to
  maintain backwards compatibility. New code should use 
  `fromEd25519VerificationKey2020()` (or whatever the latest Ed25519 suite is).

## 4.0.0 - 2021-03-11

### Changed
- **BREAKING**: Rename repo and NPM package name to 
  `@digitalbazaar/x25519-key-agreement-key-2019`.
- **BREAKING**: Rename `addEncodedPublicKey()` to `addPublicKey()`.
- **BREAKING**: Rename `addEncryptedPrivateKey()` to `addPrivateKey()`.
- **BREAKING**: Changed `verifyFingerprint()` param signature to use named 
  params.
- **BREAKING**: Changed `fromEdKeyPair()` param signature to use named params.
- **BREAKING**: Changed `convertFromEdPublicKey()` param signature to use named 
  params.
- **BREAKING**: Changed `convertFromEdPrivateKey()` param signature to use named 
  params.
- See also [`crypto-ld` v4.0 Changelog](https://github.com/digitalbazaar/crypto-ld/blob/master/CHANGELOG.md#400---2020-08-01)

### Purpose and Upgrade Instructions
See [`crypto-ld` v4.0 Purpose](https://github.com/digitalbazaar/crypto-ld/blob/master/CHANGELOG.md#400---purpose)
and [`crypto-ld` Upgrade from v3.7 notes](https://github.com/digitalbazaar/crypto-ld/blob/master/CHANGELOG.md#upgrading-from-v370)

## 3.1.0 - 2020-10-08

### Changes
- Use node-forge@0.10.0.
- Update dev dependencies.

## 3.0.0 - 2020-08-01

### Added
- Auto-initialize key.id based on controller (if it's present).

### Changed
- **BREAKING**: Explicitly make `publicBase58` property required for Ed25519
  type keys (throw error if missing).

## 2.0.0 - 2020-03-09

### Changed
- **BREAKING**: Changed the key fingerprint prefix to the recently registered
  `multicodec` value of `0xec`.

## 1.0.0 - 2020-02-25

- See git history for changes.
