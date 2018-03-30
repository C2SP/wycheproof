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
 * @fileoverview Utilities for hash operations
 */
goog.provide('wycheproof.webcryptoapi.HashUtil');


// Hash function names
wycheproof.webcryptoapi.HashUtil.SHA256 = 'SHA-256';
wycheproof.webcryptoapi.HashUtil.SHA384 = 'SHA-384';
wycheproof.webcryptoapi.HashUtil.SHA512 = 'SHA-512';
wycheproof.webcryptoapi.HashUtil.SHA1 = 'SHA-1';


/**
 * Calculates a hash of the given message using the given hash algorithm.
 * @param {!string} hashAlg The hash algorithm
 * @param {!ArrayBuffer} msg The message to be hashed
 *
 * @return {!Promise}
 */
wycheproof.webcryptoapi.HashUtil.digest = function(hashAlg, msg) {
  return window.crypto.subtle.digest(hashAlg, msg);
};
