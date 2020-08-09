/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */

import * as crypto from 'crypto';
import {promisify} from 'util';

const PUBLIC_KEY_DER_PREFIX = new Uint8Array([
  48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0
]);

const PRIVATE_KEY_DER_PREFIX = new Uint8Array([
  48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
]);

export async function deriveSecret({privateKey, remotePublicKey}) {
  const nodePrivateKey = crypto.createPrivateKey({
    key: Buffer.concat([PRIVATE_KEY_DER_PREFIX, privateKey]),
    format: 'der',
    type: 'pkcs8'
  });
  const nodePublicKey = crypto.createPublicKey({
    key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, remotePublicKey]),
    format: 'der',
    type: 'spki'
  });
  return crypto.diffieHellman({
    privateKey: nodePrivateKey,
    publicKey: nodePublicKey,
  });
}

export async function generateKeyPair() {
  const generateKeyPairAsync = promisify(crypto.generateKeyPair);
  const publicKeyEncoding = {format: 'der', type: 'spki'};
  const privateKeyEncoding = {format: 'der', type: 'pkcs8'};
  const {publicKey: publicDerBytes, privateKey: privateDerBytes} =
    await generateKeyPairAsync('x25519', {
      publicKeyEncoding, privateKeyEncoding
    });
  const publicKey = publicDerBytes.slice(12, 12 + 32);
  const privateKey = privateDerBytes.slice(16, 16 + 32);
  return {publicKey, privateKey};
}
