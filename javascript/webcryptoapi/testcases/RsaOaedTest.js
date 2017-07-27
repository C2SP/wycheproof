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
 * Tests for RSA-OAEP encryption implementations of Web Crypto API.
 */
goog.provide('wycheproof.webcryptoapi.RSA-OAED');
goog.require('e2e.random');
goog.require('goog.testing.asserts');
goog.require('goog.testing.jsunit');
goog.require('wycheproof.TestUtil');
goog.require('wycheproof.webcryptoapi.RsaUtil');

var RsaUtil = wycheproof.webcryptoapi.RsaUtil;
var TestUtil = wycheproof.TestUtil;

/**
 * Tries decrypting random messages with a given algorithm. Counts the number of distinct error
 * messages and expects this number to be 1.
 *
 * <p><b>References:</b>
 *
 * <ul>
 *   <li>Bleichenbacher, "Chosen ciphertext attacks against protocols based on the RSA encryption
 *       standard PKCS# 1" Crypto 98
 *   <li>Manger, "A chosen ciphertext attack on RSA optimal asymmetric encryption padding (OAEP)
 *       as standardized in PKCS# 1 v2.0", Crypto 2001 This paper shows that OAEP is susceptible
 *       to a chosen ciphertext attack if error messages distinguish between different failure
 *       condidtions.
 *   <li>Bardou, Focardi, Kawamoto, Simionato, Steel, Tsay "Efficient Padding Oracle Attacks on
 *       Cryptographic Hardware", Crypto 2012 The paper shows that small differences on what
 *       information an attacker recieves can make a big difference on the number of chosen
 *       message necessary for an attack.
 *   <li>Smart, "Errors matter: Breaking RSA-based PIN encryption with thirty ciphertext validity
 *       queries" RSA conference, 2010 This paper shows that padding oracle attacks can be
 *       successful with even a small number of queries.
 * </ul>
 *
 * <p><b>Some recent bugs:</b> CVE-2012-5081: Java JSSE provider leaked information through
 * exceptions and timing. Both the PKCS #1 padding and the OAEP padding were broken:
 * http://www-brs.ub.ruhr-uni-bochum.de/netahtml/HSS/Diss/MeyerChristopher/diss.pdf
 *
 * <p><b>What this test does not (yet) cover:</b>
 *
 * <ul>
 *   <li> A previous version of one of the provider leaked the block type. (when was this fixed?)
 *   <li> Some attacks require a large number of ciphertexts to be detected if random ciphertexts
 *       are used. Such problems require specifically crafted ciphertexts to run in a unit test.
 *       E.g. "Attacking RSA-based Sessions in SSL/TLS" by V. Klima, O. Pokorny, and T. Rosa:
 *       https://eprint.iacr.org/2003/052/
 *   <li> Timing leakages because of differences in parsing the padding (e.g. CVE-2015-7827) Such
 *       differences are too small to be reliably detectable in unit tests.
 * </ul>
 *
 * @return {!Promise}
 */
function testRsaEncryptionException() {
  var promise = new Promise(function(resolve, reject){
    var scheme = RsaUtil.RSA_OAEP;
    var keySize = 1024;
    var e = RsaUtil.E_65537;
    var hashAlg = 'SHA-256';
    var usages = ['encrypt', 'decrypt'];
    var ctLen = keySize/8;
    var nTest = 1000;
    var nDone = 0;
    var exceptions = new Set();
    RsaUtil.generateKey(scheme, keySize, e, hashAlg, usages).then(function(key) {
      for (var i = 0; i < nTest; i++) {
        var ct = new Uint8Array(e2e.random.getRandomBytes(ctLen)).buffer;
        RsaUtil.decrypt(scheme, key.privateKey, ct).then(function(pt){
          reject('RSA-OAEP decryption should not succeed on random bytes');
        }).catch(function(err){
          exceptions.add(err.name + ': ' + err.message);
          nDone += 1;
          if (nDone == nTest) {
            if (exceptions.size > 1) {
              var msg = 'Exceptions leak information about the padding for ' + scheme + '\n';
              exceptions.forEach(function(e) {
                msg += e;
              });
              reject(msg);
            }
            resolve();
          }
        });
      }
    }).catch(function(err){
      reject('Failed to generate key: ' + err);
    });
  });
  return promise;
}
