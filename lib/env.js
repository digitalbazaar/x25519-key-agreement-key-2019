/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import crypto from 'crypto';

export const nodejs = (
  typeof process !== 'undefined' && process.versions && process.versions.node);

export const browser = !nodejs &&
  (typeof window !== 'undefined' || typeof self !== 'undefined');

export const hasDiffieHellman = nodejs && crypto.diffieHellman;
