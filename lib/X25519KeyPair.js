/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const forge = require('node-forge');
const {util: {binary: {base58}}} = forge;
const {LDKeyPair} = require('crypto-ld');
const {base58Decode} = require('crypto-ld/lib/util');
const ed2curve = require('ed2curve');
const nacl = require('tweetnacl');

class X25519KeyPair extends LDKeyPair {
  /**
   * An implementation of x25519-xsalsa20-poly1305
   * [X25519 Key Agreement 2019]{@link https://w3c-dvcg.github.io/} representation
   * @example
   * > const privateKeyBase58 =
   *   '...';
   * > const options = {
   *   publicKeyBase58: '...',
   *   privateKeyBase58
   * };
   * > const DHKey = new X25519KeyPair(options);
   * > DHKey
   * X25519KeyPair { ...
   * @param {KeyPairOptions} options - Base58 keys plus other options
   * @param {string} options.controller
   * @param {string} options.id
   * @param {string} options.publicKeyBase58 - Base58 encoded Public Key
   * unencoded is 32-bytes.
   * @param {string} options.privateKeyBase58 - Base58 Private Key
   * unencoded is 32-bytes.
   */
  constructor(options = {}) {
    super(options);
    this.type = 'X25519KeyAgreementKey2019';
    this.privateKeyBase58 = options.privateKeyBase58;
    this.publicKeyBase58 = options.publicKeyBase58;
  }
  /**
   * Returns the Base58 encoded public key.
   * @implements {LDKeyPair#publicKey}
   * @readonly
   *
   * @returns {string} The Base58 encoded public key.
   * @see [publicKey]{@link ./LDKeyPair.md#publicKey}
   */
  get publicKey() {
    return this.publicKeyBase58;
  }
  /**
   * Returns the Base58 encoded private key.
   * @implements {LDKeyPair#privateKey}
   * @readonly
   *
   * @returns {string} The Base58 encoded private key.
   * @see [privateKey]{@link ./LDKeyPair.md#privateKey}
   */
  get privateKey() {
    return this.privateKeyBase58;
  }

  /**
   * Generates a new public/private X25519 Key Pair.
   * Note: This is async only to match the async signature of other LDKeyPair
   * subclasses.
   * @example
   * > const keyPair = await X25519KeyPair.generate();
   * > keyPair
   * X25519KeyPair { ...
   * @param {KeyPairOptions} [options={}]
   * @param {string} [options.controller]
   * @param {string} [options.id]
   *
   * @returns {Promise<X25519KeyPair>} Generates a key pair.
   */
  static async generate(options = {}) {
    // Each is a Uint8Array with 32-byte key
    const {publicKey, secretKey: privateKey} = nacl.box.keyPair()

    return new X25519KeyPair({
      publicKeyBase58: base58.encode(publicKey),
      privateKeyBase58: base58.encode(privateKey),
      ...options
    });
  }

  /**
   * Creates an X25519KeyPair Key Pair from an existing key (constructor method)
   * @example
   * > const options = {
   *   id,
   *   controller,
   *   publicKeyBase58,
   *   privateKeyBase58: privateKey
   * };
   * > const key = await X25519KeyPair.from(options);
   * > key
   * X25519KeyPair { ...
   * @param {Object} options
   * @param {string} [options.privateKeyBase58] - A Base58 encoded Private key
   *
   * @returns {X25519KeyPair} An X25519 Key Pair.
   */
  static async from(options) {
    return new X25519KeyPair(options);
  }

  static fromEdKeyPair(edKeyPair) {
    const xKey = new X25519KeyPair({
      controller: edKeyPair.controller
    });

    xKey.publicKeyBase58 = X25519KeyPair
      .convertFromEdPublicKey(edKeyPair.publicKeyBase58);

    if(edKeyPair.privateKeyBase58) {
      xKey.privateKeyBase58 = X25519KeyPair
        .convertFromEdPrivateKey(edKeyPair.privateKeyBase58)
    }

    return xKey;
  }

  /**
   * @param {string} edPublicKeyBase58 - base58 encoded Ed25519 Public key
   * @returns {string} base58 encoded X25519 Public key
   */
  static convertFromEdPublicKey(edPublicKeyBase58) {
    const edPubkeyBytes = base58Decode({
      decode: base58.decode,
      keyMaterial: edPublicKeyBase58,
      type: 'public'
    });

    // Converts a 32-byte Ed25519 public key into a 32-byte Curve25519 key
    // Returns null if the given public key in not a valid Ed25519 public key.
    const dhPubkeyBytes = ed2curve.convertPublicKey(edPubkeyBytes);
    if(!dhPubkeyBytes) {
      throw new Error(
        'Error converting to X25519: Invalid Ed25519 public key.');
    }
    const dhPublicKeyBase58 = base58.encode(dhPubkeyBytes);
    return dhPublicKeyBase58;
  }

  /**
   * @param {string} edPrivateKeyBase58 - base58 encoded Ed25519 Private key
   * @returns {string} base58 encoded X25519 Private key
   */
  static convertFromEdPrivateKey(edPrivateKeyBase58) {
    const edPrivkeyBytes = base58Decode({
      decode: base58.decode,
      keyMaterial: edPrivateKeyBase58,
      type: 'private'
    });
    // Converts a 64-byte Ed25519 secret key (or just the first 32-byte part of
    // it, which is the secret value) into a 32-byte Curve25519 secret key
    const dhPrivkeyBytes = ed2curve.convertSecretKey(edPrivkeyBytes);
    if(!dhPrivkeyBytes) {
      throw new Error(
        'Error converting to X25519: Invalid Ed25519 private key.');
    }
    const dhPrivateKeyBase58 = base58.encode(dhPrivkeyBytes);
    return dhPrivateKeyBase58;
  }

  /**
   * Adds a public key base to a public key node.
   * @example
   * > keyPair.addEncodedPublicKey({});
   * { publicKeyBase58: 'GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq' }
   * @param {Object} publicKeyNode - The public key node
   * @param {string} publicKeyNode.publicKeyBase58 - Base58 Public Key
   *
   * @returns {{verify: Function}} A PublicKeyNode in a block.
   */
  addEncodedPublicKey(publicKeyNode) {
    publicKeyNode.publicKeyBase58 = this.publicKeyBase58;
    return publicKeyNode;
  }

  /**
   * Generates and returns a multiformats encoded
   * X25519 public key fingerprint (for use with cryptonyms, for example).
   * @see https://github.com/multiformats/multicodec
   *
   * @param {string} publicKeyBase58 - The base58 encoded public key material.
   *
   * @returns {string} The fingerprint.
   */
  static fingerprintFromPublicKey({publicKeyBase58}) {
    // X25519 cryptonyms are multicodec encoded values, specifically:
    // (multicodec x25519-pub 0x25 + key bytes)
    const pubkeyBytes = base58Decode({
      decode: base58.decode,
      keyMaterial: publicKeyBase58,
      type: 'public'
    });
    const buffer = new Uint8Array(1 + pubkeyBytes.length);
    buffer[0] = 0x25;
    buffer.set(pubkeyBytes, 1);
    // prefix with `z` to indicate multi-base base58btc encoding
    return `z${base58.encode(buffer)}`;
  }

  /**
   * Derives a shared secret via a given public key, typically for use
   * as one parameter for computing a shared key. It should not be used as
   * a shared key itself, but rather input into a key derivation function (KDF)
   * to produce a shared key.
   * @param {LDKeyPair} remoteKey
   * @throws {TypeError} On invalid base58 encoding of public or private keys
   * @returns {String}
   */
  async deriveSecret({remoteKey}) {
    const remotePubkeyBytes = base58Decode({
      decode: base58.decode,
      keyMaterial: remoteKey.publicKeyBase58,
      type: 'public'
    });

    const privateKeyBytes = base58Decode({
      decode: base58.decode,
      keyMaterial: this.privateKeyBase58,
      type: 'private'
    });

    return nacl.scalarMult(privateKeyBytes, remotePubkeyBytes);
  }

  /**
   * Generates and returns a multiformats encoded
   * X25519 public key fingerprint (for use with cryptonyms, for example).
   * @see https://github.com/multiformats/multicodec
   *
   * @returns {string} The fingerprint.
   */
  fingerprint() {
    const {publicKeyBase58} = this;
    return X25519KeyPair.fingerprintFromPublicKey({publicKeyBase58});
  }

  /**
   * Tests whether the fingerprint was generated from a given key pair.
   * @example
   * > xKeyPair.verifyFingerprint('...');
   * {valid: true};
   * @param {string} fingerprint - A Base58 public key.
   *
   * @returns {Object} An object indicating valid is true or false.
   */
  verifyFingerprint(fingerprint) {
    // TODO: implement
    throw new Error('`verifyFingerprint` API is not implemented.');
  }
}

module.exports = X25519KeyPair;
