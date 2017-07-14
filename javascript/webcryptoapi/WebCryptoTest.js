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
 * @fileoverview Tests for Web Crypto API
 */
goog.provide('wycheproof.webcryptoapi');
goog.require('goog.testing.TestCase');
goog.require('goog.userAgent.product');

const TEST_TIMEOUT = 120*1000;

// A dictionary containing the parameters that are supported by the current browser
var SUPPORTED;
// Parameters that are supported by Microsoft Edge
const EDGE_SUPPORTED = {
    'aesgcm-key-size': [128, 192, 256],
    'ecdsa-curve': ['P-256', 'P-384', 'P-521'],
    'hash': ['SHA-256', 'SHA-384', 'SHA-512']
};
// Parameters that are supported by Chrome
const CHROME_SUPPORTED = {
    'aesgcm-key-size': [128, 256],
    'ecdsa-curve': ['P-256', 'P-384', 'P-521'],
    'hash': ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']
};
// Parameters that are supported by Firefox
const FIREFOX_SUPPORTED = {
    'aesgcm-key-size': [128, 192, 256],
    'ecdsa-curve': ['P-256', 'P-384', 'P-521'],
    'hash': ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']
};

// Test names
const TEST_AES_GCM_VECTORS = 'testAesGcmVectors';
const TEST_ECDSA_VECTORS = 'testEcdsaVectors';
const TEST_ECDSA_BIAS = 'testEcdsaBiasAll';
const TEST_RSASSAPKCS1_VECTORS = 'testRsaSsaPkcs1Vectors';
const TEST_RSA_ENCRYPT = 'testRsaEncryptionException';
const TEST_ECDH_VECTORS = 'testEcdhVectors';

// Tests to run
var TESTS_ALL = {};
TESTS_ALL[TEST_AES_GCM_VECTORS] = true;
TESTS_ALL[TEST_ECDSA_VECTORS] = true;
TESTS_ALL[TEST_ECDSA_BIAS] = true;
TESTS_ALL[TEST_RSASSAPKCS1_VECTORS] = true;
TESTS_ALL[TEST_RSA_ENCRYPT] = true;
TESTS_ALL[TEST_ECDH_VECTORS] = true;

// Tests to run on Chrome
var TESTS_TO_RUN_CHROME_ALL = goog.cloneObject(TESTS_ALL);
var TESTS_TO_RUN_CHROME_PRESUBMIT = goog.cloneObject(TESTS_TO_RUN_CHROME_ALL);
TESTS_TO_RUN_CHROME_PRESUBMIT[TEST_AES_GCM_VECTORS] = false;
TESTS_TO_RUN_CHROME_PRESUBMIT[TEST_ECDSA_BIAS] = false;

// Tests to run on Firefox
var TESTS_TO_RUN_FIREFOX_ALL = goog.cloneObject(TESTS_ALL);
var TESTS_TO_RUN_FIREFOX_PRESUBMIT = goog.cloneObject(TESTS_TO_RUN_FIREFOX_ALL);
TESTS_TO_RUN_FIREFOX_PRESUBMIT[TEST_AES_GCM_VECTORS] = false;
TESTS_TO_RUN_FIREFOX_PRESUBMIT[TEST_ECDSA_BIAS] = false;

// Tests to run on MS Edge
// MS Edge doesn't support ECDSA
var TESTS_TO_RUN_EDGE_ALL = goog.cloneObject(TESTS_ALL);
TESTS_TO_RUN_EDGE_ALL[TEST_ECDSA_VECTORS] = false;
TESTS_TO_RUN_EDGE_ALL[TEST_ECDSA_BIAS] = false;
TESTS_TO_RUN_EDGE_ALL[TEST_ECDH_VECTORS] = false;
var TESTS_TO_RUN_EDGE_PRESUBMIT = goog.cloneObject(TESTS_TO_RUN_EDGE_ALL);

/**
 * Runs all tests.
 */
wycheproof.webcryptoapi.setupAllTests = function() {
  var testCase = goog.testing.TestCase.getActiveTestCase();
  testCase.promiseTimeout = TEST_TIMEOUT;
  if (goog.userAgent.product.CHROME) {
    testCase.setTestsToRun(TESTS_TO_RUN_CHROME_ALL);
    SUPPORTED = CHROME_SUPPORTED;
  } else if (goog.userAgent.product.FIREFOX) {
    testCase.setTestsToRun(TESTS_TO_RUN_FIREFOX_ALL);
    SUPPORTED = FIREFOX_SUPPORTED;
  } else if (goog.userAgent.product.EDGE) {
    testCase.setTestsToRun(TESTS_TO_RUN_EDGE_ALL);
    SUPPORTED = EDGE_SUPPORTED;
  }
};

/**
 * Runs tests that do not fail.
 */
wycheproof.webcryptoapi.setupPresubmitTests = function() {
  var testCase = goog.testing.TestCase.getActiveTestCase();
  testCase.promiseTimeout = TEST_TIMEOUT;
  if (goog.userAgent.product.CHROME) {
    testCase.setTestsToRun(TESTS_TO_RUN_CHROME_PRESUBMIT);
    SUPPORTED = CHROME_SUPPORTED;
  } else if (goog.userAgent.product.FIREFOX) {
    testCase.setTestsToRun(TESTS_TO_RUN_FIREFOX_PRESUBMIT);
    SUPPORTED = FIREFOX_SUPPORTED;
  } else if (goog.userAgent.product.EDGE) {
    testCase.setTestsToRun(TESTS_TO_RUN_EDGE_PRESUBMIT);
    SUPPORTED = EDGE_SUPPORTED;
  }
};


