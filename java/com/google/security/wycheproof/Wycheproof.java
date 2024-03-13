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

import com.google.common.flags.Flag;
import com.google.common.flags.FlagSpec;
import com.google.common.flags.Flags;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.util.List;
import java.util.TreeSet;

/**
 * Command line tool for Wycheproof tests.
 *
 * <p>The main goal of this class is to provide a template for running tests against test vector
 * files. Ideally most of the changes necessary to run tests under different test environments
 * should be done here. Currently the test run under blaze. E.g., a test can be run as
 *
 * <pre>
 * PATH=third_party/wycheproof/testvectors_v1
 * blaze run Wycheproof -- --test_vector_file=$PATH/ecdh_secp256k1_test.json
 * </pre>
 *
 * <p>The tool can be used to generate a JSON file with failing tests as
 *
 * <pre>
 * blaze run Wycheproof -- --test_vector_file=$PATH/ecdh_secp256k1_test.json\
 *    --dump_json > failing_tests.json
 * </pre>
 *
 * <p>It would then be possible to rerun tests against failing tests. E.g.,
 *
 * <pre>
 * blaze run Wycheproof -- --test_vector-file=failing_test.json
 * </pre>
 *
 * <p>Alternatively it is possible to rerun a list of selected vector by tcid:
 *
 * <pre>blaze run Wycheproof -- --test_vector_file=$PATH/ecdh_secp256k1_test.json \
 *   --tcid=15,16,95
 * </pre>
 *
 * <p>This tool is in early development. It is not yet clear what information is helpful. Feedback
 * is of course welcome. The current output for
 *
 * <pre>
 * blaze run Wycheproof -- --test_vector_file=$PATH/ecdh_secp256k1_test.json
 * </pre>
 *
 * on jdk11 is as follows:
 *
 * <pre>
 * === Name : third_party/wycheproof/testvectors_v1/ecdh_secp256k1_test.json ===
 * Performed tests: 752
 * valid test vectors: 473
 * PASSED_VALID:473
 * PASSED_MALFORMED:1
 * REJECTED_VALID:2
 * REJECTED_INVALID:273
 * WRONG_RESULT:3
 * Total number of failed tests: 6
 * --- Possible explanations (by labels) ---
 * EdgeCaseSharedSecret:3
 * WrongCurve:1
 * EdgeCaseEphemeralKey:2
 * --- Failing tests ---
 * 15 WRONG_RESULT
 *   Incorrect result: 0000000000000000555555555555555555555555555555555555555555555550
 *   shared secret has x-coordinate with repeating bit-pattern of size 2; EdgeCaseSharedSecret
 * 16 WRONG_RESULT
 *   Incorrect result: 0000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 *   shared secret has x-coordinate with repeating bit-pattern of size 2; EdgeCaseSharedSecret
 * 41 WRONG_RESULT
 *   Incorrect result: 00000000000000005555555555555555555555555555555555555554fffffebc
 *   shared secret has an x-coordinate of approx p//3; EdgeCaseSharedSecret
 * 95 REJECTED_VALID
 *   java.security.InvalidKeyException: Public key must be on the private key's curve
 *   ephemeral key has an x-coordinate of approx p//3; EdgeCaseEphemeralKey
 * 98 REJECTED_VALID
 *   java.security.InvalidKeyException: Public key must be on the private key's curve
 *   ephemeral key has an x-coordinate of approx p//9; EdgeCaseEphemeralKey
 * 492 PASSED_MALFORMED
 *
 *   public key has invalid point of order 2 on secp256r1. The point of the public key is a valid
 *   on secp256k1.; WrongCurve
 * </pre>
 */
public final class Wycheproof {

  @FlagSpec(name = "test_vector_file", help = "A file with test vectors")
  private static final Flag<String> testVectorFile = Flag.value("");

  @FlagSpec(name = "dump_json", help = "Dumps a JSON file with failing test vectors to stdout")
  private static final Flag<Boolean> dumpJson = Flag.value(false);

  @FlagSpec(name = "tcid", help = "Selects a list of tcIds to test")
  private static final Flag<List<Integer>> tcIds = Flag.integerList();

  private static TestVectors getTestVectors(String path) throws IOException {
    if (path.isEmpty()) {
      throw new IllegalArgumentException("No file with test vectors specified");
    }
    JsonObject json = JsonUtil.getTestVectorsAbsolutePath(path);
    return new TestVectors(json, path);
  }

  private static void writeResult(TestResult result, boolean dumpJson) throws IOException {
    if (!dumpJson) {
      System.out.println(result.asString());
    } else {
      TestVectors failedTests = result.failingTests();
      if (failedTests.numTests() == 0) {
        return;
      }
      Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
      System.out.println(gson.toJson(failedTests.getTest()));
    }
  }

  public static void main(String[] args) throws Exception {
    Flags.parse(args);
    TestVectors testVectors = getTestVectors(testVectorFile.getNonNull());
    if (tcIds.get() != null) {
      TreeSet<Integer> tcids = new TreeSet<>(tcIds.get());
      if (!tcids.isEmpty()) {
        testVectors = testVectors.subSet(tcids);
      }
    }
    TestResult result = JsonTest.run(testVectors);
    writeResult(result, dumpJson.getNonNull());
  }

  private Wycheproof() {}
}
