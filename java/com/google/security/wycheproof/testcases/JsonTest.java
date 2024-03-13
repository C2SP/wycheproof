/**
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.security.wycheproof;


/**
 * JsonTest is a class that allows to run any set of test vectors.
 *
 * Test vectors contain a JSON schema that defines the structure of the test vectors. This schema
 * also defines the type of the test vectors and hence the tests for which the test vectors
 * were generated. Hence this information can be used to dispatch an adequate test given some
 * test vectors.
 * <p>One potential use case of this class is to rerun failing tests to check if bugs have been
 * fixed. In particular, testResult.failingTests() returns all the test vectors that fail a test.
 * Hence it may be possible to rerun such a subset against new versions of a library.
 * <p>A main goal is to distinguish between test failures caused by faulty proviers and
 * test failures caused by faulty test setups (such as missing or incorrect test vectors).
 * Incorrect setups should result in a failure of type TestResult.Type.WRONG_SETUP,
 * while other types are used for unexpected behavior of the tested provider.
 * If a test throws a RuntimeException then this should be treated as an invalid setup.
 */
public class JsonTest {

  /**
   * Verifies a set of test vectors.
   *
   * This method uses the JSON schema of the test vectors to dispatch the correct test.
   *
   * @param testVectors a set of test vectors
   * @return the test results.
   */
  public static TestResult run(TestVectors testVectors) {
    String schema = testVectors.getTest().get("schema").getAsString();
    switch (schema) {
      case "ecdsa_verify_schema.json":
      case "ecdsa_p1363_verify_schema.json":
      case "dsa_verify_schema.json":
      case "dsa_p1363_verify_schema.json":
      case "rsassa_pkcs1_verify_schema.json":
      case "rsassa_pss_verify_schema.json":
      case "eddsa_verify_schema.json":
        return JsonSignatureTest.allTests(testVectors);
      case "rsaes_oaep_decrypt_schema.json":
      case "rsaes_pkcs1_decrypt_schema.json":
        return JsonRsaEncryptionTest.allTests(testVectors);
      case "ecdh_test_schema.json":
        return JsonEcdhTest.allTests(testVectors);
      case "xdh_asn_comp_schema.json":
      case "xdh_comp_schema.json":
        return JsonXdhTest.allTests(testVectors);
      case "ind_cpa_test_schema.json":
        return JsonCipherTest.allTests(testVectors);
      case "aead_test_schema.json":
        return JsonAeadTest.allTests(testVectors);
      case "mac_test_schema.json":
      case "mac_with_iv_test_schema.json":
        return JsonMacTest.allTests(testVectors);
      case "keywrap_test_schema.json":
        return JsonKeyWrapTest.allTests(testVectors);
      case "fpe_list_test_schema.json":
        return JsonFpeTest.allTests(testVectors);
      case "pbkdf_test_schema.json":
        return JsonPbkdfTest.allTests(testVectors);
      case "primality_test_schema.json":
        return BigIntegerTest.probablePrimeTest(testVectors);
      default:
        TestResult failedTest = new TestResult(testVectors);
        failedTest.addFailure(TestResult.Type.WRONG_SETUP, "Unknown schema: " + schema);
        return failedTest;
    }
  }

  /**
   * Verifies a single test vector.
   *
   * @param testVectors a set of test vectors
   * @param tcId the tcId of the test vector to test
   * @return the test results.
   */
  public TestResult singleTest(TestVectors testVectors, int tcId) {
    TestVectors singleTest = testVectors.singleTest(tcId);
    return run(singleTest);
  }
}
