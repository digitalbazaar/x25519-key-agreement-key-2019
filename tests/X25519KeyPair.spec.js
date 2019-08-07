/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const chai = require('chai');
chai.should();
const {expect} = chai;

const {Ed25519KeyPair} = require('crypto-ld');
const X25519KeyPair = require('../lib/X25519KeyPair');

describe('X25519KeyPair', () => {
  describe('fromEdKeyPair', () => {
    it('should convert both public and private key', async () => {
      const edKeyPair = await Ed25519KeyPair.from({
        controller: 'did:example:123',
        "privateKeyBase58": "4F71TAGqQYe7KE9p4HUzoVV9arQwKP4gPtvi89EPNGuwA1qLE4RRxitA2rEcdEszERj3pN1DWKARBZQ2BACLbW1V",
        "publicKeyBase58": "HLi1h9SzENZyEv7ifPNtu8xyJNzCFFeaC6X9rsZKFgv3"
      });

      const xKeyPair = X25519KeyPair.fromEdKeyPair(edKeyPair);

      expect(xKeyPair.type).to.equal('X25519KeyAgreementKey2019');
      expect(xKeyPair.controller).to.equal('did:example:123');
      expect(xKeyPair.publicKeyBase58).to
        .equal('9K6xjwBdjKC4W3r41ZP5WUxp8XXm8gT9GvR1G5Eocs1Z');
      expect(xKeyPair.privateKeyBase58).to
        .equal('H9ruaVs9LnRUwxNMLTjDkEbWW1P3bcBuiu7GxoBbEpdV');
    });
  });
});
