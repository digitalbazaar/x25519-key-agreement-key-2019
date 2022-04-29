/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
import {LDKeyPair} from 'crypto-ld';
import ed2curve from 'ed2curve';
import {encode, decode} from 'base58-universal';
import {generateKeyPair, deriveSecret} from './crypto.js';
import {Point} from '@noble/ed25519';

const SUITE_ID = 'X25519KeyAgreementKey2019';

// multicodec ed25519-pub header as varint
const MULTICODEC_ED25519_PUB_HEADER = new Uint8Array([0xed, 0x01]);
// multicodec ed25519-priv header as varint
const MULTICODEC_ED25519_PRIV_HEADER = new Uint8Array([0x80, 0x26]);

export class X25519KeyAgreementKey2019 extends LDKeyPair {
  /**
   * An implementation of x25519
   * [X25519 Key Agreement 2019]{@link https://w3c-dvcg.github.io/}
   * representation.
   *
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
   *
   * @param {object} options - Options hashmap.
   * @param {string} options.controller - Controller DID or document url.
   * @param {string} [options.id] - Key ID, typically composed of controller
   *   URL and key fingerprint as hash fragment.
   * @param {string} options.publicKeyBase58 - Base58 encoded public key.
   * @param {string} [options.privateKeyBase58] - Base58 private key.
   * @param {string} [options.revoked] - Timestamp of when the key has been
   *   revoked, in RFC3339 format. If not present, the key itself is considered
   *   not revoked. Note that this mechanism is slightly different than DID
   *   Document key revocation, where a DID controller can revoke a key from
   *   that DID by removing it from the DID Document.
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
   *
   * @example
   * > const keyPair = await X25519KeyAgreementKey2019.generate();
   * > keyPair
   * X25519KeyAgreementKey2019 { ...
   *
   * @param {object} [options={}] - The options.
   * @param {string} [options.controller] - A controller.
   * @param {string} [options.id] - An id.
   *
   * @returns {Promise<X25519KeyAgreementKey2019>} Generates a key pair.
   */
  static async generate(options = {}) {
    const {publicKey, privateKey} = await generateKeyPair();

    return new X25519KeyAgreementKey2019({
      publicKeyBase58: encode(publicKey),
      privateKeyBase58: encode(privateKey),
      ...options
    });
  }

  /**
   * Creates an X25519KeyAgreementKey2019 Key Pair from an existing key
   * (constructor method).
   *
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
   *
   * @param {object} options - The options.
   * @param {string} [options.privateKeyBase58] - A Base58 encoded Private key.
   *
   * @returns {X25519KeyAgreementKey2019} An X25519 Key Pair.
   */
  static async from(options) {
    return new X25519KeyAgreementKey2019(options);
  }

  /**
   * Converts a keypair instance of type Ed25519VerificationKey2018 to an
   * instance of this class.
   *
   * @see https://github.com/digitalbazaar/ed25519-verification-key-2018
   *
   * @typedef {object} Ed25519VerificationKey2018
   *
   * @param {Ed25519VerificationKey2018} keyPair - The source key pair.
   *
   * @returns {X25519KeyAgreementKey2019} The converted output.
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
   *
   * @see https://github.com/digitalbazaar/ed25519-verification-key-2020
   *
   * @typedef {object} Ed25519VerificationKey2020
   *
   * @param {Ed25519VerificationKey2020} keyPair - The source key pair.
   *
   * @returns {X25519KeyAgreementKey2019} - The converted output.
   */
  static fromEd25519VerificationKey2020({keyPair}) {
    if(!keyPair.publicKeyMultibase) {
      throw new Error('Source public key is required to convert.');
    }

    if(!keyPair.publicKeyMultibase.startsWith('z')) {
      throw new TypeError(
        'Expecting source public Ed25519 2020 key to have base58btc encoding.'
      );
    }

    const publicKeyBase58 = encode(_multibaseDecode(
      MULTICODEC_ED25519_PUB_HEADER,
      keyPair.publicKeyMultibase));

    const xKey = new X25519KeyAgreementKey2019({
      controller: keyPair.controller,
      publicKeyBase58: X25519KeyAgreementKey2019
        .convertFromEdPublicKey({publicKeyBase58})
    });

    if(keyPair.privateKeyMultibase) {
      if(!keyPair.privateKeyMultibase.startsWith('z')) {
        throw new TypeError(
          // eslint-disable-next-line max-len
          'Expecting source private Ed25519 2020 key to have base58btc encoding.'
        );
      }

      const privateKeyBase58 = encode(_multibaseDecode(
        MULTICODEC_ED25519_PRIV_HEADER, keyPair.privateKeyMultibase));

      xKey.privateKeyBase58 = X25519KeyAgreementKey2019
        .convertFromEdPrivateKey({privateKeyBase58});
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
   * @param {Ed25519VerificationKey2018} keyPair - The source key pair.
   *
   * @returns {X25519KeyAgreementKey2019} - The converted output.
   */
  static fromEdKeyPair({keyPair}) {
    return this.fromEd25519VerificationKey2018({keyPair});
  }

  /**
   * @param {string} publicKeyBase58 - The base58 encoded Ed25519 Public key.
   *
   * @returns {string} The base58 encoded X25519 Public key.
   */
  static convertFromEdPublicKey({publicKeyBase58}) {
    const edPubkeyBytes = decode(publicKeyBase58);

    // Converts a 32-byte Ed25519 public key into a 32-byte Curve25519 key
    // Returns null if the given public key in not a valid Ed25519 public key.
    const dhPubkeyBytes = Point.fromHex(edPubkeyBytes).toX25519();
    if(!dhPubkeyBytes) {
      throw new Error(
        'Error converting to X25519; Invalid Ed25519 public key.');
    }
    const dhPublicKeyBase58 = encode(dhPubkeyBytes);
    return dhPublicKeyBase58;
  }

  /**
   * @param {string} privateKeyBase58 - The base58 encoded Ed25519 Private key.
   *
   * @returns {string} The base58 encoded X25519 Private key.
   */
  static convertFromEdPrivateKey({privateKeyBase58}) {
    const edPrivkeyBytes = decode(privateKeyBase58);
    // Converts a 64-byte Ed25519 secret key (or just the first 32-byte part of
    // it, which is the secret value) into a 32-byte Curve25519 secret key
    const dhPrivkeyBytes = ed2curve.convertSecretKey(edPrivkeyBytes);
    // note: a future version should make this method async to allow use of
    // noble to convert private keys -- but `ed2curve` is much faster x100:
    // const {head: dhPrivkeyBytes} = await utils.getExtendedPublicKey(
    //   edPrivkeyBytes.slice(0, 32));
    if(!dhPrivkeyBytes) {
      throw new Error(
        'Error converting to X25519; Invalid Ed25519 private key.');
    }
    const dhPrivateKeyBase58 = encode(dhPrivkeyBytes);
    return dhPrivateKeyBase58;
  }

  /**
   * Exports the serialized representation of the KeyPair.
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {boolean} [options.publicKey] - Export public key material?
   * @param {boolean} [options.privateKey] - Export private key material?
   * @param {boolean} [options.includeContext] - Include JSON-LD context?
   *
   * @returns {object} A plain js object that's ready for serialization
   *   (to JSON, etc), for use in DIDs etc.
   */
  export({publicKey = false, privateKey = false, includeContext = false} = {}) {
    if(!(publicKey || privateKey)) {
      throw new TypeError(
        'Export requires specifying either "publicKey" or "privateKey".');
    }
    const exportedKey = {
      id: this.id,
      type: this.type
    };
    if(includeContext) {
      exportedKey['@context'] = X25519KeyAgreementKey2019.SUITE_CONTEXT;
    }
    if(this.controller) {
      exportedKey.controller = this.controller;
    }
    if(publicKey) {
      exportedKey.publicKeyBase58 = this.publicKeyBase58;
    }
    if(privateKey) {
      exportedKey.privateKeyBase58 = this.privateKeyBase58;
    }
    if(this.revoked) {
      exportedKey.revoked = this.revoked;
    }
    return exportedKey;
  }

  /**
   * Generates and returns a multiformats encoded X25519 public key
   * fingerprint (for use with cryptonyms, for example).
   *
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
   * @param {string} fingerprint - The fingerprint.
   *
   * @throws Unsupported Fingerprint Type.
   * @returns {X25519KeyAgreementKey2019} The key.
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
   *
   * @param {LDKeyPair} publicKey - Remote key pair.
   *
   * @throws {TypeError} On invalid base58 encoding of public or private keys.
   * @returns {Promise<Uint8Array>} The derived secret.
   */
  async deriveSecret({publicKey}) {
    const remotePublicKey = decode(publicKey.publicKeyBase58);
    const privateKey = decode(this.privateKeyBase58);

    return deriveSecret({privateKey, remotePublicKey});
  }

  /**
   * Generates and returns a multiformats encoded X25519 public key
   * fingerprint (for use with cryptonyms, for example).
   *
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
   *
   * @example
   * > xKeyPair.verifyFingerprint('...');
   * {valid: true};
   *
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

// Used by CryptoLD harness for dispatching.
X25519KeyAgreementKey2019.suite = SUITE_ID;
X25519KeyAgreementKey2019.SUITE_CONTEXT =
  'https://w3id.org/security/suites/x25519-2019/v1';

/**
 * Decodes a given string as a multibase-encoded multicodec value.
 *
 * @param {Uint8Array} header - Expected header bytes for the multicodec value.
 * @param {string} text - Multibase encoded string to decode.
 * @returns {Uint8Array} Decoded bytes.
 */
function _multibaseDecode(header, text) {
  const mcValue = decode(text.slice(1));

  if(!header.every((val, i) => mcValue[i] === val)) {
    throw new Error('Multibase value does not have expected header.');
  }

  return mcValue.slice(header.length);
}
