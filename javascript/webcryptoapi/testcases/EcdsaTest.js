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
 * Tests for ECDSA implementations of Web Crypto API.
 */
goog.provide('wycheproof.webcryptoapi.ECDSA');
goog.require('goog.testing.TestCase');
goog.require('goog.testing.asserts');
goog.require('goog.testing.jsunit');
goog.require('wycheproof.BigInteger');
goog.require('wycheproof.Constants');
goog.require('wycheproof.TestUtil');
goog.require('wycheproof.webcryptoapi.HashUtil');

var TestUtil = wycheproof.TestUtil;
var BigInteger = wycheproof.BigInteger;
var Constants = wycheproof.Constants;
var HashUtil = wycheproof.webcryptoapi.HashUtil;

const ECDSA_TEST_TIMEOUT = 30*1000;

/**
 * Initializes test settings before all the tests run.
 */
function setUpPage(){
  goog.testing.TestCase.getActiveTestCase().promiseTimeout = ECDSA_TEST_TIMEOUT;
}


/** ECDSA wrapper */
var Ecdsa = function() {};


/**
 * Verifies the given signature using the given ECDSA public key.
 * @param {!CryptoKey} pk The ECDSA public key
 * @param {!ArrayBuffer} msg The message to be verified
 * @param {!ArrayBuffer} sig The signature to be verified
 *
 * @return {!Promise}
 */
Ecdsa.verify = function(pk, msg, sig) {
  return crypto.subtle.verify(
    {name: 'ECDSA'},
    pk,
    sig,
    msg
  );
};


/**
 * Imports a ECDSA public key.
 * @param {!JSONObject} keyData The key data in JWK format
 * @param {!Array<string>} usages The usages of the key
 *
 * @return {!Promise}
 */
Ecdsa.importPublicKey = function(keyData, usages) {
  return crypto.subtle.importKey(
    'jwk',
    keyData,
    {name: 'ECDSA'},
    true,
    usages
  );
};


/**
 * Parameters of a ECDSA signature verification test.
 * @param {!number} id Test case's id
 * @param {!JSONObject} keyData The key data in JWK format
 * @param {!ArrayBuffer} msg The message that was signed
 * @param {!ArrayBuffer} sig The signature to be verified
 * @param {!string} result The expected result of the test case
 */
var EcdsaVerifyTestCase = function(id, keyData, msg, sig, result) {
  this.id = id;
  this.keyData = keyData;
  this.msg = msg;
  this.sig = sig;
  this.result = result;
};


/**
 * Tests ECDSA signature verification. The test case's parameters are passed
 * to 'this' variable of the function.
 *
 * @return {!Promise}
 */
Ecdsa.testVerify = function() {
  tc = this;
  var promise = new Promise((resolve, reject) => {
    Ecdsa.importPublicKey(tc.keyData, ['verify']).then(function(pk){
      Ecdsa.verify(pk, tc.msg, tc.sig).then(function(isValid){
        if (tc.result == 'valid') {
          assertTrue('Failed in test case ' + tc.id, isValid);
        } else if (tc.result == 'invalid') {
          assertFalse('Failed in test case ' + tc.id, isValid);
        }
        resolve();
      }).catch(function(err){
        assertNotEquals('Failed to verify in test case ' + tc.id,
              tc.result, 'valid');
        resolve();
      });
    }).catch(function(err){
      fail('Failed to import key in test case ' + tc.id + ': ' + err);
      resolve();
    });
  });
  return promise;
};


/**
 * Tests ECDSA signature implementation with a number of test vectors.
 *
 * @return {!Promise}
 */
function testEcdsaVectors() {
  var tv = TestUtil.readJsonTestVectorsFromFile(
      Constants.ECDSA_WEBCRYPTO_VECTOR_FILE);
  var testCase = new goog.testing.TestCase();

  for (var i = 0; i < tv['testGroups'].length; i++) {
    var tg = tv['testGroups'][i];
    var keyData = tg['jwk'];
    var curveName = keyData['crv'];
    if (SUPPORTED_ALGORITHMS['ecdsa-curve'].includes(curveName)) {
      for (var j = 0; j < tg['tests'].length; j++) {
        var tc = tg['tests'][j];
        var tcId = tc['tcId'];
        var result = tc['result'];
        var msg = TestUtil.hexToArrayBuffer(tc['message']);
        var sig = TestUtil.hexToArrayBuffer(tc['sig']);
        var test = new EcdsaVerifyTestCase(
            tcId, keyData, msg, sig, result);
        testCase.addNewTest(tcId + '-verify', Ecdsa.testVerify, test);
      }
    }
  }
  return testCase.runTestsReturningPromise().then(TestUtil.checkTestCaseResult);
}

