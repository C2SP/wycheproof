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
 * Tests for ECDH implementations of Web Crypto API.
 */
goog.provide('wycheproof.webcryptoapi.ECDH');
goog.require('goog.testing.TestCase');
goog.require('goog.testing.asserts');
goog.require('goog.testing.jsunit');
goog.require('wycheproof.BigInteger');
goog.require('wycheproof.TestUtil');
goog.require('wycheproof.webcryptoapi.RsaUtil');

var TestUtil = wycheproof.TestUtil;
var RsaUtil = wycheproof.webcryptoapi.RsaUtil;
var BigInteger = wycheproof.BigInteger;

// Test vector files
var ECDH_VECTOR_FILE = '../../testvectors/ecdh_webcrypto_test.json';

/** ECDH wrapper */
var Ecdh = function() {};

/**
 * Generates an ECDH key pair using the given curve name.
 * @param {!string} curveName The curve name
 *
 * @return {!Promise}
 */
Ecdh.generateKey = function(curveName) {
  return window.crypto.subtle.generateKey(
    {
        name: 'ECDH',
        namedCurve: curveName,
    },
    true,
    ['deriveKey', 'deriveBits']
  );
};


/**
 * Imports a ECDH key from the given key data.
 * @param {!JSONObject} keyData The key data in JWK format
 * @param {!Array<string>} usages The usages of the key
 *
 * @return {!Promise}
 */
Ecdh.importKey = function(keyData, usages) {
  return window.crypto.subtle.importKey(
    "jwk",
    keyData,
    {
        name: 'ECDH',
        namedCurve: keyData['crv'],
    },
    true,
    usages
  );
};


/**
 * Exports the given ECDSA key as a JSON object.
 * @param {!CryptoKey} key The ECDH key to be exported
 *
 * @return {!Promise}
 */
Ecdh.exportKey = function(key) {
  return window.crypto.subtle.exportKey("jwk", key);
};


/**
 * Derives bits from a public key and a private key.
 * @param {!CryptoKey} pubKey The public key
 * @param {!CryptoKey} privKey The private key
 * @param {number} bitLen The number of bits to be derived
 *
 * @return {!Promise}
 */
Ecdh.deriveBits = function(pubKey, privKey, bitLen) {
  return window.crypto.subtle.deriveBits(
    {
        name: 'ECDH',
        public: pubKey,
    },
    privKey,
    bitLen
  );
};


/**
 * Tests ECDH key derivation. The test case's parameters are passed
 * to 'this' variable of the function.
 *
 * @return {!Promise}
 */
Ecdh.testKeyDerivation = function() {
  tc = this;
  var sk, pk;
  var promise = new Promise(function(resolve, reject){
    Ecdh.importKey(tc.privKeyData, ['deriveBits']).then(function(key){
      sk = key;
      Ecdh.importKey(tc.pubKeyData, []).then(function(key){
        pk = key;
        Ecdh.deriveBits(pk, sk, tc.sharedKeyLen).then(function(sharedKey){
          if (tc.result == 'invalid') {
            reject('Failed on test case ' + tc.id);
          }
          var hexSharedKey = TestUtil.arrayBufferToHex(sharedKey);
          if (hexSharedKey != tc.sharedKey) {
            reject('Failed on test case ' + tc.id);
          }
          resolve();
        }).catch(function(err) {
          if (tc.result == 'valid') {
            reject('Unexpected exception on test case ' + tc.id + ": " + err);
          }
          resolve();
        });
      }).catch(function(err) {
        if (tc.result == 'valid') {
          reject('Failed to import public key: ' + err);
        }
        resolve();
      });
    }).catch(function(err) {
      // Allow skipping P-256K curve since this curve is not yet supported
      // by most implementations.
      if (tc.privKeyData['crv'] == 'P-256K') {
        resolve();
      }
      reject('Failed to import private key ' +tc.id + ":"  + err);
    });
  });
  return promise;
};

/**
 * Parameters of a ECDH key derivation test.
 * @param {!number} id Test case's id
 * @param {!JSONObject} privKeyData The private key's data in JWK format
 * @param {!JSONObject} pubKeyData The public key's data in JWK format
 * @param {!string} sharedKey The expected shared key
 * @param {!string} result The expected result of the test case
 */
var EcdhTestCase = function(id, privKeyData, pubKeyData, sharedKey, result) {
  this.id = id;
  this.privKeyData = privKeyData;
  this.pubKeyData = pubKeyData;
  this.sharedKey = sharedKey;
  this.sharedKeyLen = sharedKey.length/2*8;
  this.result = result;
};

/**
 * Tests ECDH key derivation with a number of test vectors.
 *
 * @return {!Promise}
 */
function testEcdhVectors() {
  var tv = TestUtil.readJsonTestVectorsFromFile(ECDH_VECTOR_FILE);
  var testCase = new goog.testing.TestCase();
  for (var i = 0; i < tv['testGroups'].length; i++) {
    tg = tv['testGroups'][i];
    for (var j = 0; j < tg['tests'].length; j++) {
      tc = tg['tests'][j];
      var test = new EcdhTestCase(tc['tcId'], tc['private'], tc['public'],
          tc['shared'], tc['result']);
      testCase.addNewTest(tc['tcId'], Ecdh.testKeyDerivation, test);
    }
  }
  return testCase.runTestsReturningPromise().then(TestUtil.checkTestCaseResult);
}
