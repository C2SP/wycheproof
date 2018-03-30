/**
 * @license
 * Copyright 2017 Google Inc. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Some utilities for testing Elliptic curve crypto.
 *
 */
goog.provide('wycheproof.EcUtil');
goog.require('wycheproof.BigInteger');
goog.require('wycheproof.BigPrimeInteger');

var BigInteger = wycheproof.BigInteger;
var BigPrimeInteger = wycheproof.BigPrimeInteger;

/**
 * Parameters of a NIST-recommended curve.
 * @param {!number} keySize The bit length of the order n
 * @param {!string} hexP The prime modulus p in hex format
 * @param {!string} hexN The order n in hex format
 * @param {!string} hexB The coefficient b in hex format
 * @param {!string} hexGX The x-coordinate of the public curve point
 * @param {!string} hexGY The y-coordinate of the public curve point
 */
var NistCurveSpec = function(keySize, hexP, hexN, hexB, hexGX, hexGY) {
  this.keySize = keySize;
  this.p = new BigPrimeInteger(BigInteger.fromHex(hexP).toByteArray());
  this.n = new BigPrimeInteger(BigInteger.fromHex(hexN).toByteArray());
  this.b = BigInteger.fromHex(hexB);
  this.gx = BigInteger.fromHex(hexGX);
  this.gy = BigInteger.fromHex(hexGY);
};


/**
 * Returns the NIST's recommended parameters of the given curve.
 * @param {!string} name The curve name
 *
 * @return {NistCurveSpec}
 */
wycheproof.EcUtil.getCurveSpec = function(name) {
  switch (name) {
    case 'P-256':
      return wycheproof.EcUtil.getNistP256Params();
    case 'P-384':
      return wycheproof.EcUtil.getNistP384Params();
    case 'P-521':
      return wycheproof.EcUtil.getNistP521Params();
    default:
      throw 'Curve not implemented:' + name;
  }
};

/**
 * Returns the NIST's recommended parameters of the secp256r1 curve.
 *
 * @return {NistCurveSpec}
 */
wycheproof.EcUtil.getNistP256Params = function() {
  return new NistCurveSpec(
      256,
      'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
      'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
      '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
      '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
      '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5');
};


/**
 * Returns the NIST's recommended parameters of the secp384r1 curve.
 *
 * @return {NistCurveSpec}
 */
wycheproof.EcUtil.getNistP384Params = function() {
  return new NistCurveSpec(
      384,
      'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
          + 'ffeffffffff0000000000000000ffffffff',
      'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372'
          + 'ddf581a0db248b0a77aecec196accc52973',
      'b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a'
          + 'c656398d8a2ed19d2a85c8edd3ec2aef',
      'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38'
          + '5502f25dbf55296c3a545e3872760ab7',
      '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0'
          + '0a60b1ce1d7e819d7a431d7c90ea0e5f');
};


/**
 * Returns the NIST's recommended parameters of the secp521r1 curve.
 *
 * @return {NistCurveSpec}
 */
wycheproof.EcUtil.getNistP521Params = function() {
return new NistCurveSpec(
    521,
    '1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
        + 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    '1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
        + 'a51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409',
    '051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef10'
        + '9e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00',
    'c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3d'
        + 'baa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66',
    '11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e6'
        + '62c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650');
};


