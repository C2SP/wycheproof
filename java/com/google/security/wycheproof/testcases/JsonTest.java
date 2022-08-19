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
  public static TestResult run(TestVectors testVectors) throws Exception {
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
      case "ecdh_test_schema.json":
        return JsonEcdhTest.allTests(testVectors);
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
  public TestResult singleTest(TestVectors testVectors, int tcId) throws Exception {
    TestVectors singleTest = testVectors.singleTest(tcId);
    return run(singleTest);
  }
}
