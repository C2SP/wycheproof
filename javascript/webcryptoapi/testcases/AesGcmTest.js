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
 * Tests for AES-GCM encryption scheme in implementations of Web Crypto API.
 */

/**
 * TODO(thanhb):
 * - Tests invalid parameters
 */

goog.provide('wycheproof.webcryptoapi.AES-GCM');
goog.require('goog.array');
goog.require('goog.testing.TestCase');
goog.require('goog.testing.asserts');
goog.require('goog.testing.jsunit');
goog.require('wycheproof.BigInteger');
goog.require('wycheproof.Constants');
goog.require('wycheproof.TestUtil');

var TestUtil = wycheproof.TestUtil;
var BigInteger = wycheproof.BigInteger;
var Constants = wycheproof.Constants;


/**
 * A class containing a AES-GCM test case's parameters.
 * @param {!number} id Identifier of the test case
 * @param {!string} k The key in Base64URL format
 * @param {!number} keySize The key's size in bits
 * @param {!string} tag The expected tag of the encryption in hex format
 * @param {!number} tagSize The tag size in bits
 * @param {!ArrayBuffer} iv The initialization vector
 * @param {!number} ivSize The iv's size in bits
 * @param {!ArrayBuffer} aad The additional authentication data
 * @param {!ArrayBuffer} msg The message to be encrypted
 * @param {!string} ct The expected ciphertext of the encryption in hex format
 * @param {!string} result The expected result of the test
 */
var AesGcmTestCase = function(id, k, keySize, tag, tagSize, iv, ivSize,
                              aad, msg, ct, result) {
  this.id = id;
  this.k = k;
  this.keySize = keySize;
  this.tag = tag;
  this.tagSize = tagSize;
  this.iv = iv;
  this.ivSize = ivSize;
  this.aad = aad;
  this.msg = msg;
  this.ct = ct;
  this.result = result;
  this.key = null;
};


/** AES-GCM wrapper */
var AesGcm = function() {};

/**
 * Returns the AES-GCM algorithm name that is accepted by WebCrypto APIs.
 * @param {!number} keySize The key's size
 *
 * @return {!string} The algorithm's name
 */
AesGcm.getAlgName = function(keySize) {
  return 'A' + keySize + 'GCM';
};


/**
 * Imports a AES-GCM key.
 * @param {!string} k The key in Base64URL format
 * @param {!number} keySize The key's size in bits
 *
 * @return {!Promise} A Promise containing the imported key
 */
AesGcm.importKey = function(k, keySize) {
  return window.crypto.subtle.importKey(
    "jwk",
    {
        kty: 'oct',
        k: k,
        alg: AesGcm.getAlgName(keySize),
        ext: true,
    }, {
        name: 'AES-GCM',
    },
    true,
    ["encrypt", "decrypt"]
  );
};


/**
 * Performs AES-GCM encryption.
 * @param {!CryptoKey} key The key that is used for encryption
 * @param {!ArrayBuffer} aad The additional authentication data
 * @param {!ArrayBuffer} msg The message to be encrypted
 * @param {!ArrayBuffer} iv The initialization vector
 * @param {number} tagSize The tag size in bits
 *
 * @return {!Promise} A Promise containing the ciphetext
 */
AesGcm.encrypt = function(key, aad, msg, iv, tagSize) {
  return window.crypto.subtle.encrypt(
    {
        name: 'AES-GCM',
        iv: iv,
        additionalData: aad,
        tagLength: tagSize
    },
    key,
    msg
  );
};


/**
 * Tests AES-GCM import key.
 *
 * @return {!Promise}
 */
AesGcm.testImportKey = function() {
  var tc = this;
  var promise = AesGcm.importKey(tc.k, tc.keySize).then(function(key){
    tc.key = key;
  }).catch(function(err){
    fail('Failed to import key in test case ' + tc.id + ': ' + err);
  });
  return promise;
};


/**
 * Tests AES-GCM encryption.
 *
 * @return {!Promise}
 */
AesGcm.testEncrypt = function() {
  var tc = this;
  var promise = AesGcm.encrypt(tc.key, tc.aad, tc.msg, tc.iv, tc.tagSize)
      .then(function(ct){
    // Fail if the iv is empty and the encryption still succeeds
    if (tc.ivSize == 0) {
      fail('Failed on test case ' + tc.id + ': 0-length iv should not be accepted');
    } else {
      var hexCt = TestUtil.arrayBufferToHex(ct);
      if (tc.result == 'valid') {
        assertEquals('Failed on test case ' + tc.id, hexCt, tc.ct+tc.tag);
      } else if (tc.result == 'invalid') {
        assertNotEquals('Failed on test case ' + tc.id, hexCt, tc.ct+tc.tag);
      }
    }
  }).catch(function(err){
    assertNotEquals('Failed on test case ' + tc.id + ': ' + err,
                      tc.result, 'valid');
  });
  return promise;
};


/**
 * Tests AES-GCM encryption implementation with test vectors from files
 *
 * @return {!Promise}
 */
function testAesGcmVectors() {
  var tv = TestUtil.readJsonTestVectorsFromFile(Constants.AES_GCM_VECTOR_FILE);
  var testCase = new goog.testing.TestCase();

  goog.array.forEach(tv['testGroups'], function(tg, i){
    var keySizeBit = parseInt(tg['keySize']);
    var tagSizeBit = parseInt(tg['tagSize']);
    var ivSizeBit = parseInt(tg['ivSize']);
    // Only run the tests if the key size is supported
    if (SUPPORTED_ALGORITHMS['aesgcm-key-size'].includes(keySizeBit)) {
      goog.array.forEach(tg['tests'], function(tc, j){
         var k = BigInteger.fromHex(tc['key']).toBase64Url(keySizeBit/8);
        var aad = TestUtil.hexToArrayBuffer(tc['aad']);
        var msg = TestUtil.hexToArrayBuffer(tc['msg']);
        console.log(keySizeBit + ' ' + ivSizeBit + ' ' + tc['iv']);
        var iv;
        if (ivSizeBit == 0) {
          iv = new Uint8Array([]).buffer;
        } else {
          iv = BigInteger.fromHex(tc['iv']).toArrayBuffer(ivSizeBit/8);
        }
        var ct = tc['ct'];
        var tag = tc['tag'];
        var result = tc['result'];
        var tcId = tc['tcId'];
        // Creates new Test Case object
        var test = new AesGcmTestCase(tcId, k, keySizeBit, tag, tagSizeBit,
            iv, ivSizeBit, aad, msg, ct, result, null);
        // Imports the key and adds it to the Test Case object
        testCase.addNewTest(tcId + '-importKey', AesGcm.testImportKey, test);
        // Uses the Test Case object for encryption test
        testCase.addNewTest(tcId + '-encrypt', AesGcm.testEncrypt, test);
      });
    }
  });

  return testCase.runTestsReturningPromise().then(function(result) {
    var failMsg = '';
    if (result.errors.length > 0) {
      goog.array.forEach(result.errors, function(err, i) {
        failMsg += err.message + '\n';
      });
      fail(failMsg);
    }
  });
}
