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
 * Tests for RSASSA-PKCS1-v1_5 signature scheme with Web Crypto APIs.
 */
goog.provide('wycheproof.webcryptoapi.RSASSA-PKCS1-V1_5');
goog.require('goog.array');
goog.require('goog.testing.TestCase');
goog.require('goog.testing.asserts');
goog.require('goog.testing.jsunit');
goog.require('wycheproof.BigInteger');
goog.require('wycheproof.Constants');
goog.require('wycheproof.TestUtil');
goog.require('wycheproof.webcryptoapi.HashUtil');
goog.require('wycheproof.webcryptoapi.RsaUtil');

var TestUtil = wycheproof.TestUtil;
var RsaUtil = wycheproof.webcryptoapi.RsaUtil;
var HashUtil = wycheproof.webcryptoapi.HashUtil;
var BigInteger = wycheproof.BigInteger;
var Constants = wycheproof.Constants;

function setUpPage(){
  goog.testing.TestCase.getActiveTestCase().promiseTimeout = 30*1000;
}

/**
 * Tests RSASSA-PKCS1-v1_5 signature implementation with a number of vectors.
 *
 * @return {!Promise}
 */
function testRsaSsaPkcs1Vectors() {
  var tv = TestUtil.readJsonTestVectorsFromFile(
      Constants.RSASSA_PKCS1_SIGNATURE_VECTOR_FILE);
  var testCase = new goog.testing.TestCase();

  goog.array.forEach(tv['testGroups'], function(tg, i){
    var e = BigInteger.fromHex(tg['e']).toBase64Url();
    var n = BigInteger.fromHex(tg['n']).toBase64Url();
    var hashAlg = tg['sha'];
    if (HashUtil.isSupported(hashAlg)) {
      goog.array.forEach(tg['tests'], function(tc, j){
        var msg = BigInteger.fromHex(tc['message']).toArrayBuffer();
        var sig = TestUtil.hexToArrayBuffer(tc['sig']);
        var result = tc['result'];
        var tcId = tc['tcId'];

        // Creates new Test Case object
        var test = new RsaUtil.RsaSignatureTestCase(tcId, e, n, hashAlg,
            RsaUtil.RSASSA_PKCS1, msg, sig, result);
        // Imports the key and adds it to the Test Case object
        testCase.addNewTest(tcId + '-importPK', RsaUtil.testImportPublicKey, test);
        // Uses the Test Case object for encryption test
        testCase.addNewTest(tcId + '-verify', RsaUtil.testVerification, test);
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

