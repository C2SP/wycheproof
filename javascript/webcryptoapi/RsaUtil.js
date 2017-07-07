/**
 * @license
 * Copyright 2017 Google Inc. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Some utilities for testing RSA on Web Crypto APIs
 */
goog.provide('wycheproof.webcryptoapi.RsaUtil');
goog.require('goog.testing.asserts');
goog.require('wycheproof.webcryptoapi.HashUtil');

var HashUtil = wycheproof.webcryptoapi.HashUtil;

// algorithm names
wycheproof.webcryptoapi.RsaUtil.RSASSA_PKCS1 = 'RSASSA-PKCS1-v1_5';
wycheproof.webcryptoapi.RsaUtil.RSA_OAEP = 'RSA-OAEP';

// public exponents
wycheproof.webcryptoapi.RsaUtil.E_65537 = new Uint8Array([0x01, 0x00, 0x01]);
wycheproof.webcryptoapi.RsaUtil.E_3 = new Uint8Array([0x03]);

/**
 * Imports a RSA public key.
 * @param {!string} e RSA public exponent in base64url format
 * @param {!string} n RSA modulus in base64url format
 * @param {!string} schemeName The usage scheme.
 *     Supported values are "RSASSA-PKCS1-v1_5", "RSA-PSS".
 * @param {!string} hashAlg The hash algorithm used for the scheme.
 *     Supported values are "SHA-1", "SHA-256", "SHA-384", and "SHA-512".
 * @param {!Array<string>} usages An Array indicating what can be done with the key.
 *
 * @return {!Promise} A Promise object containing the public key
 */
wycheproof.webcryptoapi.RsaUtil.importPublicKey =
    function(e, n, schemeName, hashAlg, usages) {
  return window.crypto.subtle.importKey(
      'jwk', {
          kty: 'RSA',
          e: e,
          n: n,
          ext: true,
      }, {
        name: schemeName,
        hash: {name: hashAlg},
      },
      false,
      usages
  );
};

/**
 * Verifies a RSA signature using the given public key.
 * @param {!CryptoKey} pk The public key object
 * @param {!ArrayBuffer} msg
 *     The message that was signed by the corresponding private key, in
 * @param {!ArrayBuffer} sig
 *     The signature to be verified
 * @param {!string} hashAlg The hash algorithm
 * @param {!string} schemeName The signature scheme
 *
 * @return {!Promise} A Promise object containing the verification result.
 */
wycheproof.webcryptoapi.RsaUtil.verify = function(pk, msg, sig, hashAlg, schemeName) {
  return window.crypto.subtle.verify(
      {
        name: schemeName,
        hash: hashAlg
      },
      pk,
      sig,
      msg
  );
};

/**
 * Generates a new RSA key pair.
 * @param {!string} schemeName The algorithm scheme
 * @param {number} keySize The key size in bits
 * @param {!ArrayBuffer} e The public exponent
 * @param {!string} hashAlg The hash algorithm
 * @param {!Array<string>} usages The usages of the key
 *
 * @return {!Promise} A promise containing the new key pair.
 */
wycheproof.webcryptoapi.RsaUtil.generateKey
    = function(schemeName, keySize, e, hashAlg, usages) {
  return window.crypto.subtle.generateKey(
    {
        name: schemeName,
        modulusLength: keySize,
        publicExponent: e,
        hash: {name: hashAlg},
    },
    true,
    usages
  );
};

/**
 * Decrypts the given ciphertext.
 * @param {!string} schemeName The algorithm scheme
 * @param {!CryptoKey} sk The private key that will be used for decryption
 * @param {!string} ct The ciphertext to be decrypted
 *
 * @return {!Promise} A promise containing the decrypted text.
 */
wycheproof.webcryptoapi.RsaUtil.decrypt = function(schemeName, sk, ct) {
  return window.crypto.subtle.decrypt({name: schemeName}, sk, ct);
};

/**
 * A class containing RSA signature test case's parameters
 * @param {!number} id
 * @param {!string} e RSA public exponent in base64url format
 * @param {!string} n RSA modulus in base64url format
 * @param {!string} hashAlg The hash algorithm used for the scheme.
 * @param {!string} scheme The usage scheme.
 * @param {!ArrayBuffer} msg The message to be verified
 * @param {!ArrayBuffer} sig The signature to be verified
 * @param {!string} result The test result
 */
wycheproof.webcryptoapi.RsaUtil.RsaSignatureTestCase
    = function(id, e, n, hashAlg, scheme, msg, sig, result) {
  this.id = id;
  this.e = e;
  this.n = n;
  this.hashAlg = hashAlg;
  this.scheme = scheme;
  this.msg = msg;
  this.sig = sig;
  this.result = result;
};

/**
 * Tests RSA signature verification.
 *
 * @return {!Promise}
 */
wycheproof.webcryptoapi.RsaUtil.testVerification = function() {
  var tc = this;
  var promise = new Promise(function(resolve, reject){
    RsaUtil.importPublicKey(tc.e, tc.n, tc.scheme, tc.hashAlg, ['verify'])
      .then(function(pk){
      wycheproof.webcryptoapi.RsaUtil.verify(pk, tc.msg, tc.sig,
        tc.hashAlg, tc.scheme).then(function(isValid){
        if ((tc.result == 'valid' && !isValid) ||
            (tc.result == 'invalid' && isValid)) {
          reject('Failed on test case ' + tc.id);
        }
        resolve();
      }).catch(function(err){
        // don't expect any exception in signature verification
        reject('Unexpected exception on test case ' + tc.id + ": " + err);
      });
    }).catch(function(err){
      reject('Failed to import public key in test case ' + tc.id + ': ' + err);
    });
  });
  return promise;
};
