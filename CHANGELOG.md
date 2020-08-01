# x25519-key-agreement-key-2019 ChangeLog

## 4.0.0 - TBD

### Changed
- **BREAKING**: Rename repo and NPM package name to 
  `@digitalbazaar/x25519-key-agreement-key-2019`.
- See also [`crypto-ld` v4.0 Changelog](https://github.com/digitalbazaar/crypto-ld/blob/master/CHANGELOG.md#400---2020-08-01)

### Purpose and Upgrade Instructions
See [`crypto-ld` v4.0 Purpose](https://github.com/digitalbazaar/crypto-ld/blob/master/CHANGELOG.md#400---purpose)
and [`crypto-ld` Upgrade from v3.7 notes](https://github.com/digitalbazaar/crypto-ld/blob/master/CHANGELOG.md#upgrading-from-v370)

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
