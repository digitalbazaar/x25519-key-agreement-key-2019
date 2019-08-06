/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// const env = require('./env');
// const forge = require('node-forge');
// const base64url = require('base64url-universal');
// const {pki: {ed25519}, util: {binary: {base58}}} = forge;
// const util = require('./util');
const {LDKeyPair} = require('crypto-ld');

class X25519KeyPair extends LDKeyPair {
  /**
   * An implementation of
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
   * @param {KeyPairOptions} options - Base58 keys plus
   * other options most follow
   * [KeyPairOptions]{@link ./index.md#KeyPairOptions}.
   * @param {string} options.publicKeyBase58 - Base58 encoded Public Key
   * unencoded is ?-bytes.
   * @param {string} options.privateKeyBase58 - Base58 Private Key
   * unencoded is ?-bytes.
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
   * Generates a KeyPair with an optional deterministic seed.
   * @example
   * > const keyPair = await X25519KeyPair.generate();
   * > keyPair
   * X25519KeyPair { ...
   * @param {KeyPairOptions} [options={}] - See LDKeyPair
   * docstring for full list.
   * @param {Uint8Array|Buffer} [options.seed] -
   * a 32-byte array seed for a deterministic key.
   *
   * @returns {Promise<X25519KeyPair>} Generates a key pair.
   */
  static async generate(options = {}) {
  }

  /**
   * Creates an X25519KeyPair Key Pair from an existing private key.
   * @example
   * > const options = {
   *   privateKeyBase58: privateKey
   * };
   * > const key = await X25519KeyPair.from(options);
   * > key
   * Ed25519KeyPair { ...
   * @param {Object} options - Contains a private key.
   * @param {Object} [options.privateKey] - A private key object.
   * @param {string} [options.privateKeyBase58] - A Base58
   * Private key string.
   *
   * @returns {X25519KeyPair} An Ed25519 Key Pair.
   */
  static async from(options) {
  }

  /**
   * Adds a public key base to a public key node.
   * @example
   * > keyPair.addEncodedPublicKey({});
   * { publicKeyBase58: 'GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq' }
   * @param {Object} publicKeyNode - The public key node in a jsonld-signature.
   * @param {string} publicKeyNode.publicKeyBase58 - Base58 Public Key for
   * [jsonld-signatures]{@link https://github.com/digitalbazaar/jsonld-signatures}.
   *
   * @returns {{verify: Function}} A PublicKeyNode in a block.
   */
  addEncodedPublicKey(publicKeyNode) {
    publicKeyNode.publicKeyBase58 = this.publicKeyBase58;
    return publicKeyNode;
  }

  /**
   * Generates and returns a multiformats encoded
   * ed25519 public key fingerprint (for use with cryptonyms, for example).
   * @see https://github.com/multiformats/multicodec
   *
   * @param {string} publicKeyBase58 - The base58 encoded public key material.
   *
   * @returns {string} The fingerprint.
   */
  static fingerprintFromPublicKey({publicKeyBase58}) {
  }

  /**
   * Generates and returns a multiformats encoded
   * ed25519 public key fingerprint (for use with cryptonyms, for example).
   * @see https://github.com/multiformats/multicodec
   *
   * @returns {string} The fingerprint.
   */
  fingerprint() {
    const {publicKeyBase58} = this;
    return X25519KeyPair.fingerprintFromPublicKey({publicKeyBase58});
  }

  /**
   * Tests whether the fingerprint was
   * generated from a given key pair.
   * @example
   * > xKeyPair.verifyFingerprint('z2S2Q6MkaFJewa');
   * {valid: true};
   * @param {string} fingerprint - A Base58 public key.
   *
   * @returns {Object} An object indicating valid is true or false.
   */
  verifyFingerprint(fingerprint) {
  }
}

module.exports = X25519KeyPair;
