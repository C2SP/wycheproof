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
goog.require('e2e.ecc.Ecdsa');
goog.require('goog.testing.TestCase');
goog.require('goog.testing.asserts');
goog.require('goog.testing.jsunit');
goog.require('wycheproof.BigInteger');
goog.require('wycheproof.EcUtil');
goog.require('wycheproof.TestUtil');
goog.require('wycheproof.webcryptoapi.HashUtil');

var TestUtil = wycheproof.TestUtil;
var EcUtil = wycheproof.EcUtil;
var BigInteger = wycheproof.BigInteger;
var HashUtil = wycheproof.webcryptoapi.HashUtil;

// Test vector files
var ECDSA_VECTOR_FILE = '../../testvectors/ecdsa_webcrypto_test.json';

/** ECDSA wrapper */
var Ecdsa = function() {};

/**
 * Verifies the given signature using the given ECDSA public key.
 * @param {!CryptoKey} pk The ECDSA public key
 * @param {string} hashAlg The hash algorithm
 * @param {!ArrayBuffer} msg The message to be verified
 * @param {!ArrayBuffer} sig The signature to be verified
 *
 * @return {!Promise}
 */
Ecdsa.verify = function(pk, hashAlg, msg, sig) {
  return crypto.subtle.verify(
      {name: 'ECDSA', hash: {name: hashAlg}}, pk, sig, msg);
};

/**
 * Signs a message using the given ECDSA private key and hash algorithm.
 * @param {!CryptoKey} sk The ECDSA private key
 * @param {!ArrayBuffer} msg The message to be signed
 * @param {string} hashAlg The hash algorithm
 *
 * @return {!Promise}
 */
Ecdsa.sign = function(sk, msg, hashAlg) {
  return crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: {name: hashAlg},
      },
      sk, msg);
};


/**
 * Imports a ECDSA public key.
 * @param {!JSONObject} keyData The key data in JWK format
 * @param {string} hashAlg The hash algorithm
 * @param {!Array<string>} usages The usages of the key
 *
 * @return {!Promise}
 */
Ecdsa.importPublicKey = function(keyData, hashAlg, usages) {
  return crypto.subtle.importKey(
      'jwk', keyData,
      {name: 'ECDSA', namedCurve: keyData['crv'], hash: {name: hashAlg}}, true,
      usages);
};

/**
 * Exports the given ECDSA key as a JSON object.
 * @param {!CryptoKey} key The ECDSA key to be exported
 *
 * @return {!Promise}
 */
Ecdsa.exportKey = function(key) {
  return crypto.subtle.exportKey('jwk', key);
};

/**
 * Generates an ECDSA key pair using the given hash algorithm and curve name.
 * @param {string} hashAlg The hash algorithm
 * @param {string} curveName The curve name
 *
 * @return {!Promise}
 */
Ecdsa.generateKey = function(hashAlg, curveName) {
  return crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: curveName,
      },
      true, ['sign', 'verify']);
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
    Ecdsa.importPublicKey(tc.keyData, tc.hashAlg, ['verify'])
        .then(function(pk) {
          Ecdsa.verify(pk, tc.hashAlg, tc.msg, tc.sig)
              .then(function(isValid) {
                if ((tc.result == 'valid' && !isValid) ||
                    (tc.result == 'invalid' && isValid)) {
                  reject('Failed in test case ' + tc.id);
                }
                resolve();
              })
              .catch(function(err) {
                // don't expect any exception in signature verification
                reject(
                    'Unexpected exception on test case ' + tc.id + ': ' + err);
              });
        })
        .catch(function(err) {
          reject('Failed to import key in test case ' + tc.id + ': ' + err);
        });
  });
  return promise;
};


/**
 * Parameters of a ECDSA signature verification test.
 * @param {!number} id Test case's id
 * @param {!JSONObject} keyData The key data in JWK format
 * @param {string} hashAlg The hash algorithm
 * @param {!ArrayBuffer} msg The message that was signed
 * @param {!ArrayBuffer} sig The signature to be verified
 * @param {string} result The expected result of the test case
 */
var EcdsaVerifyTestCase = function(id, keyData, hashAlg, msg, sig, result) {
  this.id = id;
  this.keyData = keyData;
  this.msg = msg;
  this.sig = sig;
  this.result = result;
  this.hashAlg = hashAlg;
};


/**
 * Tests ECDSA signature implementation with a number of test vectors.
 *
 * @return {!Promise}
 */
function testEcdsaVectors() {
  var tv = TestUtil.readJsonTestVectorsFromFile(ECDSA_VECTOR_FILE);
  var testCase = new goog.testing.TestCase();

  for (var i = 0; i < tv['testGroups'].length; i++) {
    var tg = tv['testGroups'][i];
    var keyData = tg['jwk'];
    var curveName = keyData['crv'];
    var hashAlg = tg['sha'];
    if (SUPPORTED['ecdsa-curve'].indexOf(curveName) == -1 ||
        SUPPORTED['hash'].indexOf(hashAlg) == -1) {
      continue;
    }
    for (var j = 0; j < tg['tests'].length; j++) {
      var tc = tg['tests'][j];
      var tcId = tc['tcId'];
      var result = tc['result'];
      var msg = TestUtil.hexToArrayBuffer(tc['msg']);
      var sig = TestUtil.hexToArrayBuffer(tc['sig']);
      var test =
          new EcdsaVerifyTestCase(tcId, keyData, hashAlg, msg, sig, result);
      testCase.addNewTest('Test ' + tcId, Ecdsa.testVerify, test);
    }
  }
  return testCase.runTestsReturningPromise().then(TestUtil.checkTestCaseResult);
}

/**
 * Extracts 'r' and 's' values from the given signature. The function assumes
 * that the given signature is the concatenation of 'r' and 's'.
 * @param {!ArrayBuffer} sig The signature
 *
 * @return {!Array<wycheproof.BigInteger>}
 */
Ecdsa.extractSig = function(sig) {
  var bytes = new Uint8Array(sig);
  var byteLen = bytes.length;
  var rBytes = bytes.subarray(0, byteLen / 2);
  var r = new BigInteger(rBytes);
  var sBytes = bytes.subarray(byteLen / 2, byteLen);
  var s = new BigInteger(sBytes);
  return [r, s];
};

/**
 * Extracts the random nonce that was used to calculate the given signature.
 * @param {!wycheproof.BigInteger} h The digest of the message
 * @param {!wycheproof.BigInteger} r The 'r' value of the signature
 * @param {!wycheproof.BigInteger} s The 's' value of the signature
 * @param {!wycheproof.BigInteger} d The private component of the ECDSA key
 * @param {!NistCurveSpec} curveSpec The specifications of the used curve
 *
 * @return {!wycheproof.BigInteger}
 */
Ecdsa.extractNonce = function(h, r, s, d, curveSpec) {
  var n = curveSpec.n;
  var k = d.multiply(r).add(h).multiply(n.modInverse(s)).mod(n);
  return k;
};

/**
 * Checks whether the given nonce was actually used during the signing process
 * of the given signature.
 * @param {!ArrayBuffer} msg The message that was signed
 * @param {!wycheproof.BigInteger} r The 'r' value of the signature
 * @param {!wycheproof.BigInteger} s The 's' value of the signature
 * @param {!wycheproof.BigInteger} d The private component of the ECDSA key
 * @param {!wycheproof.BigInteger} k The nonce that needs to be checked
 * @param {string} curveName The curve name
 */
Ecdsa.checkNonceCorrectness = function(msg, r, s, d, k, curveName) {
  var e2eCurveMap = {
    'P-256': 'P_256',
    'P-384': 'P_384',
    'P-521': 'P_521',
  };
  var e2eCurveName = e2eCurveMap[curveName];
  var key = new e2e.ecc.Ecdsa(e2eCurveName, {privKey: d.toByteArray()});
  var msgBytes = new Uint8Array(msg);
  var calSig = key.signForTestingOnly(msgBytes, k);
  var calR = new BigInteger(calSig['r']);
  var calS = new BigInteger(calSig['s']);
  assertTrue(
      'Nonce calculation was incorrect', r.isEqual(calR) && s.isEqual(calS));
};

/**
 * Tests whether there is bias in the nonce generation during
 * ECDSA signing process. The test case's parameters are passed
 * to 'this' variable of the function. The test is based on the fact that
 * if we throw a fair coin nTests times then the probability that
 * either heads or tails appears less than minCount is less than 2^{-32}.
 * Therefore the test below is not expected to fail unless the generation
 * of the one time keys is indeed biased.
 *
 * NOTE: This test only works correctly if the length of the output of the
 * hash function is equal to the bit length of the curve order.
 *
 * @return {!Promise}
 */
Ecdsa.testBias = function() {
  var tc = this;
  var countLsb = 0;
  var countMsb = 0;

  return Ecdsa.generateKey(tc.hashAlg, tc.curveName)
      .then(function(key) {
        return Ecdsa.exportKey(key.privateKey)
            .then(function(keyData) {
              var promises = [];

              for (var i = 0; i < tc.nTests; i++) {
                promises.push(
                    Ecdsa.sign(key.privateKey, tc.msg, tc.hashAlg)
                        .then(function(sig) {
                          return HashUtil.digest(tc.hashAlg, tc.msg)
                              .then(function(digest) {
                                var curveSpec =
                                    EcUtil.getCurveSpec(tc.curveName);
                                var h = new BigInteger(new Uint8Array(digest));
                                // private key value
                                var d = BigInteger.fromHex(
                                    TestUtil.base64UrlToHex(keyData['d']));
                                var r, s;
                                [r, s] = Ecdsa.extractSig(sig);
                                var k =
                                    Ecdsa.extractNonce(h, r, s, d, curveSpec);
                                // Uncomment this line to check correctness of
                                // nonce calculation
                                // Ecdsa.checkNonceCorrectness(tc.msg, r, s, d,
                                // k, tc.curveName);
                                var halfN = curveSpec.n.shiftRight(1);
                                if (k.isBitSet(0)) countLsb += 1;
                                if (k.compare(halfN) == 1) countMsb += 1;
                              });
                        }));
              }

              return Promise.all(promises).then(function() {
                if (countLsb < tc.minCount ||
                    countLsb > tc.nTests - tc.minCount) {
                  reject(
                      'Bias detected in the LSB of k' +
                      ', hash: ' + tc.hashAlg + ', curve: ' + tc.curveName +
                      ', countLSB: ' + countLsb + ', countMSB: ' + countMsb);
                }
                if (countMsb < tc.minCount ||
                    countMsb > tc.nTests - tc.minCount) {
                  reject(
                      'Bias detected in the MSB of k' +
                      ', hash: ' + tc.hashAlg + ', curve: ' + tc.curveName +
                      ', countLSB: ' + countLsb + ', countMSB: ' + countMsb);
                }
              });
            })
            .catch(function(err) {
              throw new Error('Failed to export private key: ' + err);
            });
      })
      .catch(function(err) {
        throw new Error('Failed to generate key: ' + err);
      });
};

/**
 * Parameters of a ECDSA bias test.
 * @param {string} hashAlg The hash algorithm
 * @param {string} curveName The curve name
 * @param {!ArrayBuffer} msg The message that was signed
 * @param {!number} nTests The number of key to be generated
 * @param {!number} minCount
 *   The expected number of times that a bit of the nonce should be 1 or 0
 */
var EcdsaBiasTestCase = function(hashAlg, curveName, msg, nTests, minCount) {
  this.msg = msg;
  this.hashAlg = hashAlg;
  this.curveName = curveName;
  this.nTests = nTests;
  this.minCount = minCount;
};

/**
 * Tests whether there is bias in the nonce generation during
 * ECDSA signing process. It considers three curves: secp256r1, secp384r1,
 * and secp521r1.
 *
 * @return {!Promise}
 */
function testEcdsaBiasAll() {
  var testCase = new goog.testing.TestCase();
  testCase.promiseTimeout = 120 * 1000;
  var msg = TestUtil.hexToArrayBuffer('48656c6c6f');  // msg = 'Hello'
  var nTests = 1024;
  var minCount = 410;
  var biasTest256 =
      new EcdsaBiasTestCase('SHA-256', 'P-256', msg, nTests, minCount);
  testCase.addNewTest('bias256', Ecdsa.testBias, biasTest256);
  var biasTest384 =
      new EcdsaBiasTestCase('SHA-384', 'P-384', msg, nTests, minCount);
  testCase.addNewTest('bias384', Ecdsa.testBias, biasTest384);
  var biasTest521 =
      new EcdsaBiasTestCase('SHA-512', 'P-521', msg, nTests, minCount);
  testCase.addNewTest('bias521', Ecdsa.testBias, biasTest521);
  return testCase.runTestsReturningPromise().then(
      wycheproof.TestUtil.checkTestCaseResult);
}
