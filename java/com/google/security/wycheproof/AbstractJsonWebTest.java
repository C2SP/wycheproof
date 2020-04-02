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

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableSet;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.testing.testsize.MediumTest;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * A test suite geared towards identifying security vulnerabilities in JWS/JWE libraries. This suite
 * focuses on problems at the library level, not at the underlying crypto primitive level. For help
 * with the latter, first identify which crypto subsystem your library uses and then test it
 * directly with <a href="https://github.com/google/wycheproof">Project Wycheproof</a>.
 *
 * <p>To integrate with this test suite, simply extend this abstract class and implement the methods
 * that take cryptographic payloads and associated keys and wire it to the library under test.
 *
 * <p>Unless otherwise stated, payloads are assumed to be JWS or JWE encoded with compact
 * serialization. Keys are encoded as single JSON Web Key objects (as opposed to keyset objects). If
 * the library under test doesn't work in terms of JSON strings represented as plain Java String
 * instances, you'll need to convert the input into a format it does accept.
 *
 * <p>In general, each JWS is an appropriately constructed/secure JWS created by signing the payload
 * {@code foo} with their associated key. The headers are appropriate for the given signing key
 * ({@code alg} and {@code kid} are set).
 *
 * <ul>
 *   <li><a href="https://tools.ietf.org/html/rfc7515">JSON Web Signature RFC</a>
 *   <li><a href="https://tools.ietf.org/html/rfc7516">JSON Web Encryption RFC</a>
 *   <li><a href="https://tools.ietf.org/html/rfc7517">JSON Web Key RFC</a>
 * </ul>
 */
@MediumTest
@RunWith(Parameterized.class)
public abstract class AbstractJsonWebTest {
  private static final String EXPECTED_VERSION = "0.2";

  private static ImmutableSet<String> allTestNames;

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
    JsonObject test = JsonUtil.getTestVectors("json_web_crypto_test.json");
    String generatorVersion = test.get("generatorVersion").getAsString();
    assertThat(generatorVersion).isEqualTo(EXPECTED_VERSION);

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
  public void jsonWebCryptoTestVector() {
    // Housekeeping to make sure the implementation class wires things correctly.
    assertThat(allTestNames).containsAtLeastElementsIn(getSuppressedTests());

    String privateJwk = testGroup.getAsJsonObject("private").toString();
    JsonObject publicJwk = testGroup.getAsJsonObject("public");

    String jws = getFlattenedString(testCase, "jws");
    String jwe = getFlattenedString(testCase, "jwe");
    boolean expectedResult = testCase.get("result").getAsString().equals("valid");

    boolean result;
    if (jws == null) {
      // Decryption is always done with the private/secret key.
      result = performDecryption(jwe, privateJwk);
    } else {
      // Verification is done with the public key if it exists (or the secret key if not).
      String verificationJwk = publicJwk == null ? privateJwk : publicJwk.toString();

      if (verificationJwk.contains("keys")) {
        result = performKeysetVerification(jws, verificationJwk);
      } else {
        result = performVerification(jws, verificationJwk);
      }
    }

    if (getSuppressedTests().contains(testName)) {
      // Inverting the assertion helps uncover tests that are needlessly suppressed.
      assertWithMessage("This test appears to be needlessly suppressed")
          .that(result)
          .isEqualTo(!expectedResult);
    } else {
      assertThat(result).isEqualTo(expectedResult);
    }
  }

  /** Reads the JWS/JWE field either in compact or JSON serialization form (if it exists). */
  @Nullable
  private static String getFlattenedString(JsonObject jsonObject, String fieldName) {
    JsonElement element = jsonObject.get(fieldName);
    if (element == null) {
      return null;
    }

    if (element.isJsonPrimitive()) {
      // This is a compact representation of the JWE/JWS.
      return element.getAsString();
    }
    // This is a JSON representation of the JWE/JWS.
    return element.toString();
  }

  /** The set of test names to @Ignore. */
  protected ImmutableSet<String> getSuppressedTests() {
    return ImmutableSet.of();
  }

  /**
   * Returns whether or not the payload verifies with the given key.
   *
   * @implNote this method shouldn't allow any exceptions that indicate unverifiable payloads to
   *     escape. Instead, the implementation should catch any such exceptions and return false
   * @implNote this method is implemented by deferring to {@link #performKeysetVerification} (with a
   *     1-element keyset)
   */
  public boolean performVerification(String compactJws, String verificationJwk) {
    return performKeysetVerification(compactJws, addToKeyset(verificationJwk));
  }

  /**
   * Returns whether or not the payload verifies with any of the given keys.
   *
   * @implNote this method shouldn't allow any exceptions that indicate unverifiable payloads to
   *     escape. Instead, the implementation should catch any such exceptions and return false
   */
  public boolean performKeysetVerification(String compactJws, String verificationKeyset) {
    return performVerification(compactJws, verificationKeyset);
  }

  /**
   * Returns whether or not the payload decrypts with the given key.
   *
   * @implNote this method shouldn't allow any exceptions that indicate corrupt payloads to escape.
   *     Instead, the implementation should catch any such exceptions and return false
   */
  public abstract boolean performDecryption(String compactJwe, String decryptionJwk);

  /** Adds the 0 or more specified keys to a JSON Web Keyset. */
  private static String addToKeyset(String... keys) {
    String joinedKeys = Joiner.on(",").join(keys);
    String keysetTemplate = "{\"keys\": [%s]}";
    return String.format(keysetTemplate, joinedKeys);
  }
}
