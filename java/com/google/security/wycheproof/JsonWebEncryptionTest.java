/**
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
package com.google.security.wycheproof;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;

import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.testing.testsize.MediumTest;
import java.util.ArrayList;
import java.util.List;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/** Tests for <a href="https://tools.ietf.org/html/rfc7516">JSON Web Encryption RFC</a>. */
@MediumTest
@RunWith(Parameterized.class)
public class JsonWebEncryptionTest {

  private static ImmutableSet<String> allTestNames;

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private ImmutableSet<String> getSuppressedTests() {
    return ImmutableSet.of(
        // TODO(bleichen): b/261217218: the following test vectors fail under
        //   --config=java_runtime_head
        // "jwe_aes_acceptsValid_tcId50",
        // "jwe_ec_acceptsValid_tcId67",
        );
  }
  /** A JsonWebCryptoTestGroup that contains key information and tests against those keys. */
  @Parameter(value = 0)
  public JsonObject testGroup;

  /** A JsonWebCryptoTestVector that contains a single test in this {@link #testGroup}. */
  @Parameter(value = 1)
  public JsonObject testCase;

  @Parameter(value = 2)
  public String testName;

  @Parameters(name = "{2}")
  public static Iterable<Object[]> produceTestCases() throws Exception {
    JsonObject test = JsonUtil.getTestVectors("json_web_encryption_test.json");

    // Generate test cases.
    List<Object[]> testParams = new ArrayList<>();
    ImmutableSet.Builder<String> testNames = ImmutableSet.builder();
    for (JsonElement testGroupElement : test.getAsJsonArray("testGroups")) {
      // Contains group-level configuration as well as all of the tests for this group.
      JsonObject testGroup = testGroupElement.getAsJsonObject();

      String groupComment = testGroup.get("comment").getAsString();
      for (JsonElement testsElement : testGroup.getAsJsonArray("tests")) {
        JsonObject testCase = testsElement.getAsJsonObject();

        int testId = testCase.get("tcId").getAsInt();
        String testComment = testCase.get("comment").getAsString();
        String testName = String.format("%s_%s_tcId%d", groupComment, testComment, testId);
        testParams.add(new Object[] {testGroup, testCase, testName});
        testNames.add(testName);
      }
    }

    allTestNames = testNames.build();
    return testParams;
  }

  @Test
  public void jsonWebEncryptionTestVector() {
    // Housekeeping to make sure the implementation class wires things correctly.
    assertThat(allTestNames).containsAtLeastElementsIn(getSuppressedTests());

    String privateJwk = testGroup.getAsJsonObject("private").toString();
    String jwe = getFlattenedString(testCase, "jwe");
    boolean expectedResult = testCase.get("result").getAsString().equals("valid");
    boolean result = performDecryption(jwe, privateJwk);

    if (getSuppressedTests().contains(testName)) {
      // Inverting the assertion helps uncover tests that are needlessly suppressed.
      assertWithMessage("This test appears to be needlessly suppressed")
          .that(result)
          .isEqualTo(!expectedResult);
    } else {
      assertThat(result).isEqualTo(expectedResult);
    }
  }

  /** Reads the JWS/JWE field either in compact or JSON serialization form. */
  private static String getFlattenedString(JsonObject jsonObject, String fieldName) {
    JsonElement element = jsonObject.get(fieldName);
    if (element.isJsonPrimitive()) {
      // This is a compact representation of the JWE/JWS.
      return element.getAsString();
    }
    // This is a JSON representation of the JWE/JWS.
    return element.toString();
  }

  public boolean performDecryption(String compactJwe, String decryptionJwk) {
    JsonWebEncryption decrypter = new JsonWebEncryption();

    try {
      decrypter.setCompactSerialization(compactJwe);
      JsonWebKey parsedKey = JsonWebKey.Factory.newJwk(decryptionJwk);
      decrypter.setKey(
          parsedKey instanceof PublicJsonWebKey
              ? ((PublicJsonWebKey) parsedKey).getPrivateKey()
              : parsedKey.getKey());
      decrypter.getPlaintextBytes();
      return true;
    } catch (Exception e) {
      logger.atInfo().withCause(e).log(
          "Decryption was unsuccessful.\njwe: %s\njwk: %s", compactJwe, decryptionJwk);
      return false;
    }
  }
}
