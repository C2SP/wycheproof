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
 * Some utilities for all Javascript tests.
 */
goog.provide('wycheproof.TestUtil');
goog.require('goog.crypt');
goog.require('goog.crypt.base64');
goog.require('goog.json');

/**
 * Reads test vectors in JSON format from a file.
 * @param {!string} filename
 *
 * @return {!JSONObject}
 */
wycheproof.TestUtil.readJsonTestVectorsFromFile = function(filename){
  var fileContent = goog.loadFileSync_(filename);
  assertTrue('Invalid file format (expected JSON)', goog.json.isValid(fileContent));
  return JSON.parse(fileContent);
};


/**
 * Analyzes the result from a goog.testing.TestCase execution.
 *
 * @param {!goog.testing.TestCase.Result} result
 */
wycheproof.TestUtil.checkTestCaseResult = function(result) {
  var failMsg = '';
  if (result.errors.length > 0) {
    for (var i = 0; i < result.errors.length; i++) {
      failMsg += result.errors[i].message + '\n';
    }
    fail(failMsg);
  }
};


/**
 * Checks whether the given string is in hex format.
 * @param {!string} s
 *
 * @return {!boolean}
 */
wycheproof.TestUtil.isHex = function(s) {
  return /(^[0-9A-F]*$)|(^[0-9a-f]*$)/.test(s);
};

/**
 * Converts a hex string to a ArrayBuffer.
 * @param {!string} s
 *
 * @return {!ArrayBuffer}
 */
wycheproof.TestUtil.hexToArrayBuffer = function(s) {
  var bytes = goog.crypt.hexToByteArray(s);
  return new Uint8Array(bytes).buffer;
};

/**
 * Converts an ArrayBuffer to hex string
 * @param {!ArrayBuffer} ab
 *
 * @return {!string}
 */
wycheproof.TestUtil.arrayBufferToHex = function(ab) {
  return goog.crypt.byteArrayToHex(new Uint8Array(ab));
};

/**
 * Converts a Base64URL string to hex format
 * @param {!string} s
 *
 * @return {!string}
 */
wycheproof.TestUtil.base64UrlToHex = function (s) {
  var b64str = wycheproof.TestUtil.base64UrlToBase64(s);
  return wycheproof.TestUtil.base64ToHex(b64str);
};

/**
 * Converts a hex string to Base64 format.
 * @param {!string} s
 *
 * @return {!string}
 */
wycheproof.TestUtil.hexToBase64 = function(s) {
  var bytes = goog.crypt.hexToByteArray(s);
  return goog.crypt.base64.encodeByteArray(bytes);
};

/**
 * Converts a base64 string to hex format.
 * @param {!string} s
 *
 * @return {!string}
 */
wycheproof.TestUtil.base64ToHex = function(s) {
  var bytes = goog.crypt.base64.decodeStringToByteArray(s);
  return goog.crypt.byteArrayToHex(bytes);
};

/**
 * Converts a Base64 string to Base64URL
 * @param {!string} s
 *
 * @return {!string}
 */
wycheproof.TestUtil.base64ToBase64Url = function(s) {
  return s.replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
};

/**
 * Converts a Base64Url string to Base64
 * @param {!string} s
 *
 * @return {!string}
 */
wycheproof.TestUtil.base64UrlToBase64 = function(s) {
  return (s + '==='.slice((s.length + 3) % 4))
      .replace(/\-/g, '+')
      .replace(/_/g, '/');
};
