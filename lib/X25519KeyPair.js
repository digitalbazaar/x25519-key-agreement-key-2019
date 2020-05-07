/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {util} from 'node-forge';
const base58 = util.binary.base58;
import {LDKeyPair} from 'crypto-ld';
import {base58Decode} from 'crypto-ld/lib/util';
import ed2curve from 'ed2curve';
import nacl from 'tweetnacl';

export class X25519KeyPair extends LDKeyPair {
  /**
   * An implementation of x25519
   * [X25519 Key Agreement 2019]{@link https://w3c-dvcg.github.io/}
   * representation
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
    if(this.controller && this.publicKeyBase58 && !this.id) {
      this.id = `${this.controller}#${this.fingerprint()}`;
    }
  }
  /**
   * Returns the Base58 encoded public key.
   * @implements {LDKeyPair#publicKey}
   * @readonly
   *
   * @returns {string} The Base58 encoded public key.
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
    const {publicKey, secretKey: privateKey} = nacl.box.keyPair();

    return new X25519KeyPair({
      publicKeyBase58: base58.encode(publicKey),
      privateKeyBase58: base58.encode(privateKey),
      ...options
    });
  }

  /**
   * Creates an X25519KeyPair Key Pair from an existing key (constructor
   * method).
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
        .convertFromEdPrivateKey(edKeyPair.privateKeyBase58);
    }

    return xKey;
  }

  /**
   * @param {string} edPublicKeyBase58 - base58 encoded Ed25519 Public key
   *
   * @returns {string} base58 encoded X25519 Public key.
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
        'Error converting to X25519; Invalid Ed25519 public key.');
    }
    const dhPublicKeyBase58 = base58.encode(dhPubkeyBytes);
    return dhPublicKeyBase58;
  }

  /**
   * @param {string} edPrivateKeyBase58 - base58 encoded Ed25519 Private key
   *
   * @returns {string} base58 encoded X25519 Private key.
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
        'Error converting to X25519; Invalid Ed25519 private key.');
    }
    const dhPrivateKeyBase58 = base58.encode(dhPrivkeyBytes);
    return dhPrivateKeyBase58;
  }

  /**
   * Adds a public key base to a public key node.
   * Used by LDKeyPair.publicNode(), to serialize the public key material.
   * @example
   * > keyPair.publicNode();
   * {
   *   id: 'did:example:1234#z6LSbh9HiAU2zzBdFMdKZGHfg1UjvAYF8C8kYnkfGKuCxYEB',
   *   type: 'X25519KeyAgreementKey2019',
   *   controller: 'did:example:1234',
   *   publicKeyBase58: '1y8BrfAuXTt9yFZ2cmiMRGG5218Raxbfp2ymsFgFATR'
   * }
   * @param {object} publicKeyNode - The public key node
   * @param {string} publicKeyNode.publicKeyBase58 - Base58 Public Key
   *
   * @returns {object} A PublicKeyNode in a block.
   */
  addEncodedPublicKey(publicKeyNode) {
    publicKeyNode.publicKeyBase58 = this.publicKeyBase58;
    return publicKeyNode;
  }

  /**
   * Adds an encrypted private key to the KeyPair.
   * Used by LDKeyPair.export(), to serialize public + private key pair.
   *
   * Usage:
   *
   * ```
   * await keyPair.export();
   * // ->
   * {
   *   id: 'did:example:1234#z6LSjeJZaUHMvEKW7tEJXV4PrSm61NzxxHhDXF6zHnVtDu9g',
   *   type: 'X25519KeyAgreementKey2019',
   *   controller: 'did:example:1234',
   *   publicKeyBase58: '8y8Q4AUVpmbm2VrXzqYSXrYcAETrFgX4eGPJoKrMWXNv',
   *   privateKeyBase58: '95tmYuhqSuJqY77FEg78Zy3LFQ1cENxGv2wMvayk7Lqf'
   * }
   * ```
   *
   * @param {object} keyNode - A plain object.
   *
   * @return {object} The keyNode with an encrypted private key attached.
   */
  async addEncryptedPrivateKey(keyNode) {
    if(this.passphrase !== null) {
      throw new Error('Encrypted export not yet implemented.');
    }
    // no passphrase, do not encrypt private key
    keyNode.privateKeyBase58 = this.privateKeyBase58;
    return keyNode;
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
    // (multicodec('x25519-pub') + key bytes)
    const pubkeyBytes = base58Decode({
      decode: base58.decode,
      keyMaterial: publicKeyBase58,
      type: 'public'
    });
    const buffer = new Uint8Array(2 + pubkeyBytes.length);
    // See https://github.com/multiformats/multicodec/blob/master/table.csv
    // 0xec is the value for X25519 public key
    // 0x01 is from varint.encode(0xec) -> [0xec, 0x01]
    // See https://github.com/multiformats/unsigned-varint
    buffer[0] = 0xec; //
    buffer[1] = 0x01;
    buffer.set(pubkeyBytes, 2);
    // prefix with `z` to indicate multi-base base58btc encoding
    return `z${base58.encode(buffer)}`;
  }

  /**
   * Creates an instance of X25519KeyPair from a key fingerprint.
   *
   * @param {string} fingerprint
   * @returns {X25519KeyPair}
   * @throws Unsupported Fingerprint Type.
   */
  static fromFingerprint({fingerprint}) {
    // skip leading `z` that indicates base58 encoding
    const buffer = base58.decode(fingerprint.substr(1));

    // buffer is: 0xec 0x01 <public key bytes>
    if(buffer[0] !== 0xec || buffer[1] !== 0x01) {
      throw new Error(`Unsupported Fingerprint Type: ${fingerprint}`);
    }

    return new X25519KeyPair({
      publicKeyBase58: base58.encode(buffer.slice(2))
    });
  }

  /**
   * Derives a shared secret via a given public key, typically for use
   * as one parameter for computing a shared key. It should not be used as
   * a shared key itself, but rather input into a key derivation function (KDF)
   * to produce a shared key.
   * @param {LDKeyPair} publicKey - Remote key pair
   * @throws {TypeError} On invalid base58 encoding of public or private keys
   * @returns {String}
   */
  deriveSecret({publicKey}) {
    const remotePubkeyBytes = base58Decode({
      decode: base58.decode,
      keyMaterial: publicKey.publicKeyBase58,
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
    // fingerprint should have `z` prefix indicating
    // that it's multi-base encoded
    if(!(typeof fingerprint === 'string' && fingerprint[0] === 'z')) {
      return {
        error: new Error('`fingerprint` must be a multibase encoded string.'),
        valid: false
      };
    }
    let fingerprintBuffer;
    try {
      fingerprintBuffer = base58Decode({
        decode: base58.decode,
        keyMaterial: fingerprint.slice(1),
        type: `fingerprint's`
      });
    } catch(e) {
      return {error: e, valid: false};
    }
    let publicKeyBuffer;
    try {
      publicKeyBuffer = base58Decode({
        decode: base58.decode,
        keyMaterial: this.publicKeyBase58,
        type: 'public'
      });
    } catch(e) {
      return {error: e, valid: false};
    }
    // validate the first buffer multicodec bytes 0xec 0x01
    const valid = fingerprintBuffer[0] === 0xec &&
      fingerprintBuffer[1] === 0x01 &&
      publicKeyBuffer.toString() === fingerprintBuffer.slice(2).toString();
    if(!valid) {
      return {
        error: new Error('The fingerprint does not match the public key.'),
        valid: false
      };
    }
    return {valid};
  }
}
