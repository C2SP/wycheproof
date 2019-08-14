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
 * @fileoverview Defines interfaces for big numbers.
 * All arithmetic operations are inherits from e2e.BigNum.
 */
goog.provide('wycheproof.BigInteger');
goog.provide('wycheproof.BigPrimeInteger');
goog.require('e2e.BigNum');
goog.require('e2e.BigPrimeNum');
goog.require('goog.crypt');
goog.require('goog.crypt.base64');
goog.require('goog.testing.asserts');
goog.require('wycheproof.TestUtil');

var TestUtil = wycheproof.TestUtil;


/**
 * Non-negative arbitrary-precision integers.
 * @param {(!Array<Byte>|!Uint8Array)=} optValue
 *     The value of the BigInteger in big endian.
 * @constructor
 * @extends {e2e.BigNum}
 */
wycheproof.BigInteger = function(optValue) {
   wycheproof.BigInteger.base(this, 'constructor', optValue);
};
goog.inherits(wycheproof.BigInteger, e2e.BigNum);


/**
 * A factory method to create a BigInteger from a string that is
 * in big-endian, two's complement and hex representation.
 * @param {!string} s The string representation of the BigInteger
 *
 * @return {!BigInteger}
 */
wycheproof.BigInteger.fromHex = function(s) {
  assertTrue('Input is not a hex string', TestUtil.isHex(s));
  if (s.length % 2 == 1) {
    s = '0' + s;
  }
  var bytes = goog.crypt.hexToByteArray(s);
  var bigInt = new wycheproof.BigInteger(bytes);
  return bigInt.dropLeadingZeros();
};

/**
 * Converts this to a big-endian Base64URL string.
 * @param {!number} optValue An optional value that specifies the length in
 * bytes of the result. If it is bigger than the original length of this number,
 * zeros are added to its beginning.
 *
 * @return {!string}
 */
wycheproof.BigInteger.prototype.toBase64Url = function(optValue) {
  var bytes = this.toByteArray();
  if (optValue !== undefined && optValue > bytes.length) {
    var addingZeros = new Array(optValue-bytes.length).fill(0);
    bytes = addingZeros.concat(bytes);
  }
  var b64Str = goog.crypt.base64.encodeByteArray(bytes);
  return TestUtil.base64ToBase64Url(b64Str);
};


/**
 * Converts this to an ArrayBuffer of big-endian bytes
 * @param {!number} optValue An optional value that specifies the length in
 * bytes of the result. If it is bigger than the original length of this number,
 * zeros are added to its beginning.
 *
 * @return {!ArrayBuffer}
 */
wycheproof.BigInteger.prototype.toArrayBuffer = function(optValue) {
  var bytes = this.toByteArray();
  if (optValue !== undefined && optValue > bytes.length) {
    var addingZeros = new Array(optValue-bytes.length).fill(0);
    bytes = addingZeros.concat(bytes);
  }
  return new Uint8Array(bytes).buffer;
};


/**
 * Odd prime big integer that could be use as the modulus in modular arithmetic
 * operations in crypto schemes such as ECDSA or ECDH.
 * @param {!Array<Byte>|!Uint8Array} modulus The modulus to use.
 * @constructor
 * @extends {e2e.BigPrimeNum}
 */
wycheproof.BigPrimeInteger = function(modulus) {
   wycheproof.BigPrimeInteger.base(this, 'constructor', modulus);
};
goog.inherits(wycheproof.BigPrimeInteger, e2e.BigPrimeNum);


