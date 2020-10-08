# x25519-key-pair ChangeLog

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
