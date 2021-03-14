/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import {LDVerifierKeyPair} from 'crypto-ld';
import ed2curve from 'ed2curve';
import {encode, decode} from 'base58-universal';
import * as nodeCrypto from './nodeCrypto.js';
import * as naclCrypto from './naclCrypto.js';
import * as env from './env.js';

const SUITE_ID = 'X25519KeyAgreementKey2019';

export class X25519KeyAgreementKey2019 extends LDVerifierKeyPair {
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
   * > const DHKey = new X25519KeyAgreementKey2019(options);
   * > DHKey
   * X25519KeyAgreementKey2019 { ...
   * @param {object} options - Base58 keys plus other options
   * @param {string} options.controller
   * @param {string} options.id
   * @param {string} options.publicKeyBase58 - Base58 encoded Public Key.
   * @param {string} [options.privateKeyBase58] - Base58 Private Key.
   */
  constructor(options = {}) {
    super(options);
    this.type = SUITE_ID;
    this.publicKeyBase58 = options.publicKeyBase58;
    if(!this.publicKeyBase58) {
      throw TypeError('The "publicKeyBase58" property is required.');
    }
    this.privateKeyBase58 = options.privateKeyBase58;
    if(this.controller && !this.id) {
      this.id = `${this.controller}#${this.fingerprint()}`;
    }
  }

  /**
   * Generates a new public/private X25519 Key Pair.
   * @example
   * > const keyPair = await X25519KeyAgreementKey2019.generate();
   * > keyPair
   * X25519KeyAgreementKey2019 { ...
   * @param {object} [options={}]
   * @param {string} [options.controller]
   * @param {string} [options.id]
   *
   * @returns {Promise<X25519KeyAgreementKey2019>} Generates a key pair.
   */
  static async generate(options = {}) {
    let keyPair;

    if(env.nodejs && env.hasDiffieHellman) {
      keyPair = await nodeCrypto.generateKeyPair();
    } else {
      keyPair = await naclCrypto.generateKeyPair();
    }
    const {publicKey, privateKey} = keyPair;

    return new X25519KeyAgreementKey2019({
      publicKeyBase58: encode(publicKey),
      privateKeyBase58: encode(privateKey),
      ...options
    });
  }

  /**
   * Creates an X25519KeyAgreementKey2019 Key Pair from an existing key
   * (constructor method).
   * @example
   * > const options = {
   *   id,
   *   controller,
   *   publicKeyBase58,
   *   privateKeyBase58: privateKey
   * };
   * > const key = await X25519KeyAgreementKey2019.from(options);
   * > key
   * X25519KeyAgreementKey2019 { ...
   * @param {object} options
   * @param {string} [options.privateKeyBase58] - A Base58 encoded Private key
   *
   * @returns {X25519KeyAgreementKey2019} An X25519 Key Pair.
   */
  static async from(options) {
    return new X25519KeyAgreementKey2019(options);
  }

  /**
   * Converts a keypair instance of type Ed25519VerificationKey2018 to an
   * instance of this class.
   * @see https://github.com/digitalbazaar/ed25519-verification-key-2018
   *
   * @param {Ed25519VerificationKey2018} keyPair
   * @returns {X25519KeyAgreementKey2019}
   */
  static fromEd25519VerificationKey2018({keyPair}) {
    const xKey = new X25519KeyAgreementKey2019({
      controller: keyPair.controller,
      publicKeyBase58: X25519KeyAgreementKey2019
        .convertFromEdPublicKey(keyPair)
    });

    if(keyPair.privateKeyBase58) {
      xKey.privateKeyBase58 = X25519KeyAgreementKey2019
        .convertFromEdPrivateKey(keyPair);
    }

    return xKey;
  }

  /**
   * Converts a keypair instance of type Ed25519VerificationKey2020 to an
   * instance of this class.
   * @see https://github.com/digitalbazaar/ed25519-verification-key-2020
   *
   * @param {Ed25519VerificationKey2020} keyPair
   * @returns {X25519KeyAgreementKey2019}
   */
  static fromEd25519VerificationKey2020({keyPair}) {
    const xKey = new X25519KeyAgreementKey2019({
      controller: keyPair.controller,
      publicKeyBase58: X25519KeyAgreementKey2019
        .convertFromEdPublicKey(keyPair.publicKeyMultibase.substr(1))
    });

    if(keyPair.privateKeyMultibase) {
      xKey.privateKeyBase58 = X25519KeyAgreementKey2019
        .convertFromEdPrivateKey(keyPair.privateKeyMultibase.substr(1));
    }

    return xKey;
  }

  /**
   * @deprecated
   * NOTE: This is now an alias of `fromEd25519VerificationKey2018()`, to
   * maintain backwards compatibility. Going forward, code should be using
   * the conversion method specific to the Ed25519 suite it's using.
   *
   * Converts a keypair instance of type Ed25519VerificationKey2018 to an
   * instance of this class.
   *
   * @param {Ed25519VerificationKey2018} keyPair
   * @returns {X25519KeyAgreementKey2019}
   */
  static fromEdKeyPair({keyPair}) {
    return this.fromEd25519VerificationKey2018({keyPair});
  }

  /**
   * @param {string} publicKeyBase58 - base58 encoded Ed25519 Public key
   *
   * @returns {string} base58 encoded X25519 Public key.
   */
  static convertFromEdPublicKey({publicKeyBase58}) {
    const edPubkeyBytes = decode(publicKeyBase58);

    // Converts a 32-byte Ed25519 public key into a 32-byte Curve25519 key
    // Returns null if the given public key in not a valid Ed25519 public key.
    const dhPubkeyBytes = ed2curve.convertPublicKey(edPubkeyBytes);
    if(!dhPubkeyBytes) {
      throw new Error(
        'Error converting to X25519; Invalid Ed25519 public key.');
    }
    const dhPublicKeyBase58 = encode(dhPubkeyBytes);
    return dhPublicKeyBase58;
  }

  /**
   * @param {string} privateKeyBase58 - base58 encoded Ed25519 Private key
   *
   * @returns {string} base58 encoded X25519 Private key.
   */
  static convertFromEdPrivateKey({privateKeyBase58}) {
    const edPrivkeyBytes = decode(privateKeyBase58);
    // Converts a 64-byte Ed25519 secret key (or just the first 32-byte part of
    // it, which is the secret value) into a 32-byte Curve25519 secret key
    const dhPrivkeyBytes = ed2curve.convertSecretKey(edPrivkeyBytes);
    if(!dhPrivkeyBytes) {
      throw new Error(
        'Error converting to X25519; Invalid Ed25519 private key.');
    }
    const dhPrivateKeyBase58 = encode(dhPrivkeyBytes);
    return dhPrivateKeyBase58;
  }

  /**
   * Adds a public key base to a public key node.
   *
   * @param {object} key - The public key object in a jsonld-signature.
   * @param {string} key.publicKeyBase58 - Base58btc encoded Public Key.
   *
   * @see https://github.com/digitalbazaar/jsonld-signatures
   *
   * @returns {object} A PublicKeyNode, with key material.
   */
  addPublicKey({key}) {
    key.publicKeyBase58 = this.publicKeyBase58;
    return key;
  }

  /**
   * Adds the private key material to the KeyPair.
   * @param {object} key - A plain object.
   * @param {string} key.privateKeyBase58 - Base58btc encoded Private Key
   *
   * @return {object} The keyNode with encoded private key material.
   */
  addPrivateKey({key}) {
    key.privateKeyBase58 = this.privateKeyBase58;
    return key;
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
    const pubkeyBytes = decode(publicKeyBase58);
    const buffer = new Uint8Array(2 + pubkeyBytes.length);
    // See https://github.com/multiformats/multicodec/blob/master/table.csv
    // 0xec is the value for X25519 public key
    // 0x01 is from varint.encode(0xec) -> [0xec, 0x01]
    // See https://github.com/multiformats/unsigned-varint
    buffer[0] = 0xec; //
    buffer[1] = 0x01;
    buffer.set(pubkeyBytes, 2);
    // prefix with `z` to indicate multi-base base58btc encoding
    return `z${encode(buffer)}`;
  }

  /**
   * Creates an instance of X25519KeyAgreementKey2019 from a key fingerprint.
   *
   * @param {string} fingerprint
   * @returns {X25519KeyAgreementKey2019}
   * @throws Unsupported Fingerprint Type.
   */
  static fromFingerprint({fingerprint} = {}) {
    if(!fingerprint ||
      !(typeof fingerprint === 'string' && fingerprint[0] === 'z')) {
      throw new Error('`fingerprint` must be a multibase encoded string.');
    }
    // skip leading `z` that indicates base58 encoding
    const buffer = decode(fingerprint.substr(1));

    // buffer is: 0xec 0x01 <public key bytes>
    if(buffer[0] !== 0xec || buffer[1] !== 0x01) {
      throw new Error(`Unsupported Fingerprint Type: ${fingerprint}`);
    }

    return new X25519KeyAgreementKey2019({
      publicKeyBase58: encode(buffer.slice(2))
    });
  }

  /**
   * Derives a shared secret via a given public key, typically for use
   * as one parameter for computing a shared key. It should not be used as
   * a shared key itself, but rather input into a key derivation function (KDF)
   * to produce a shared key.
   * @param {LDKeyPair} publicKey - Remote key pair
   * @throws {TypeError} On invalid base58 encoding of public or private keys.
   * @returns {string}
   */
  async deriveSecret({publicKey}) {
    const remotePublicKey = decode(publicKey.publicKeyBase58);
    const privateKey = decode(this.privateKeyBase58);

    if(env.nodejs && env.hasDiffieHellman) {
      return nodeCrypto.deriveSecret({
        privateKey, remotePublicKey
      });
    }

    return naclCrypto.deriveSecret({privateKey, remotePublicKey});
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
    return X25519KeyAgreementKey2019
      .fingerprintFromPublicKey({publicKeyBase58});
  }

  /**
   * Tests whether the fingerprint was generated from a given key pair.
   * @example
   * > xKeyPair.verifyFingerprint('...');
   * {valid: true};
   * @param {string} fingerprint - A Base58 public key.
   *
   * @returns {object} An object indicating valid is true or false.
   */
  verifyFingerprint({fingerprint} = {}) {
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
      fingerprintBuffer = decode(fingerprint.slice(1));
    } catch(e) {
      return {error: e, valid: false};
    }
    let publicKeyBuffer;
    try {
      publicKeyBuffer = decode(this.publicKeyBase58);
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

X25519KeyAgreementKey2019.suite = SUITE_ID;