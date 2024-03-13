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
package com.google.security.wycheproof.nimbusjose;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.security.wycheproof.JsonUtil;
import com.google.security.wycheproof.TestUtil;
import com.google.testing.testsize.MediumTest;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * Tests for <a href="https://tools.ietf.org/html/rfc7517">JSON Web Key RFC</a>
 *
 * <p>The test checks key validation of Nimbus-Jose. The following issues are tested:
 *
 * <ul>
 *   <li>The key size of RSA keys must be at least 2048 bits. Specified in RFC 7518
 *   <li>e must not be 1. This is totally insecure but did happend before (CVE-2011-4121)
 *   <li>It would be nice if ROCA keys were rejected.
 *   <li>The key size of HMAC keys must be at least as big as the HMAC digest.
 *   <li>ECDSA algorithm and curve must match.
 *   <li>Key types must be suitable for the cryptographic primitive.
 * </ul>
 */
@MediumTest
@RunWith(Parameterized.class)
public class NimbusJoseJwkTest {

  private static ImmutableSet<String> allTestNames;

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private ImmutableSet<String> getSuppressedTests() {
    return ImmutableSet.of(
        // NimbusJose doesn't care if you mix inappropriate keys.
        // However, NimbusJose also does implement cryptographic operations
        // with key sets. The caller (e.g. here the test itself) has to do the key
        // managment.
        "jws_mixedSymmetryKeyset_rejectsValid_tcId1",
        // TODO(bleichen): determine if there is an expected behavior for keysets
        //   with duplicate keys.
        // RFC 7517 Section 4.5 defines kids. It says that kids should be distinct,
        // but that keysets with duplicate kids are acceptable if the keys can
        // be distinguished by "kty".
        // This test vector contains two keys with the same kid. The first key
        // is valid an verifies the MAC.
        "jws_duplicate_kid_rejectsDuplicateKid_tcId4",
        // NimbusJose does perform some simple key validations.
        // There is no test for the the ROCA vulnerability.
        // However, we do not consider such a check as a necessity.
        "jws_rsa_roca_key_rejectsKeyWithRocaVulnerability_tcId7",
        // RSA key sizes should not be smaller than 2048 bits.
        // NimbusJose accepts a 1024-bit key
        "keysize_too_small_rejects1024bitRsaKey_tcId8",
        // Hmac keys should be at least as long as the digest size.
        // NimbusJose accepts shorter HMAC keys.
        "HS384_key_too_short_tcId11",
        "HS512_key_too_short_tcId12");
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
  public static List<Object[]> produceTestCases() throws Exception {
    JsonObject test = JsonUtil.getTestVectors("json_web_key_test.json");

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
  public void jsonWebKeyTestVector() {
    // Housekeeping to make sure the implementation class wires things correctly.
    assertThat(allTestNames).containsAtLeastElementsIn(getSuppressedTests());

    String privateJwk = testGroup.getAsJsonObject("private").toString();
    JsonObject publicJwk = testGroup.getAsJsonObject("public");
    String verificationJwk = publicJwk == null ? privateJwk : publicJwk.toString();

    String jws = testCase.get("jws").getAsString();
    boolean expectedResult = testCase.get("result").getAsString().equals("valid");
    boolean result = performKeysetVerification(jws, verificationJwk);

    if (getSuppressedTests().contains(testName)) {
      // Inverting the assertion helps uncover tests that are needlessly suppressed.
      assertWithMessage("This test appears to be needlessly suppressed")
          .that(result)
          .isEqualTo(!expectedResult);
      // The test fails but is suppressed.
      TestUtil.skipTest("Suppressed test still fails");
    } else {
      assertThat(result).isEqualTo(expectedResult);
    }
  }


  /**
   * Returns a verifier for a given key.
   *
   * <p>Generally is is a good practice to select the type of the verifier based on the key type.
   * This practice helps to prevent type confusion attacks. One issue with this practice is that
   * RFC 7517, Section 4.4 defines the "alg" field in the key as optional. This is of course
   * a very unfortunate choice.
   *
   * <p>We consider it very reasonable if a library rejects ambiguous keys with no "alg" field.
   * Hence valid test vectors in Wycheproof have the "alg" field set. As a consequence constructing
   * a JWSVerifier as done below should work.
   *
   * @param key the JWK for which a decrypter is constructed.
   * @return the verifier
   * @throws NoSuchAlgorithmException if the algorithm in the key is missing or not supported.
   * @throws JOSEException if the verifier could not be constructed.
   */
  private JWSVerifier getVerifier(JWK key) throws NoSuchAlgorithmException, JOSEException {
    Algorithm alg = key.getAlgorithm();
    if (alg == null) {
      // This code requires verification key algorithm to create alogirthm specific verifiers.
      throw new NoSuchAlgorithmException("Verification key has no algorithm");
    }
    switch (alg.getName()) {
      case "HS256":
      case "HS384":
      case "HS512":
        return new MACVerifier(key.toOctetSequenceKey());
      case "ES256":
      case "ES384":
      case "ES521":
        return new ECDSAVerifier(key.toECKey());
      case "RS256":
      case "RS384":
      case "RS512":
      case "PS256":
      case "PS384":
      case "PS512":
        return new RSASSAVerifier(key.toRSAKey());
      default:
        throw new NoSuchAlgorithmException(alg.getName());
    }
  }

  public boolean performKeysetVerification(String compactJws, String verificationKeyset) {
    try {
      JWSObject jws = JWSObject.parse(compactJws);
      JWSHeader jwsHeader = jws.getHeader();
      JWKSet parsedKeySet = JWKSet.parse(verificationKeyset);
      JWK verificationKey;
      // TODO(bleichen): Consider to remove keysets from the test vectors.
      //   Here and in the jose4j test, the test itself must select the key.
      //   Hence, if a test fails then this is rather a bug in the test than a bug
      //   in the library.
      List<JWK> matches = new JWKSelector(JWKMatcher.forJWSHeader(jwsHeader)).select(parsedKeySet);
      if (matches == null) {
        // If there is exactly one key in the key set, then use this key.
        verificationKey = Iterables.getOnlyElement(parsedKeySet.getKeys());
      } else {
        verificationKey = matches.get(0);
      }

      JWSVerifier verifier = getVerifier(verificationKey);
      return jws.verify(verifier);
    } catch (Exception e) {
      logger.atInfo().withCause(e).log(
          "Verification was unsuccessful.\njws: %s\njwk: %s", compactJws, verificationKeyset);
      return false;
    }
  }
}
