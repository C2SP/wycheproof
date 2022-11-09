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

import static org.junit.Assert.assertEquals;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * This test uses test vectors in JSON format to test key wrapping.
 *
 * <p>This test is mainly for key wrappings such as RFC 3349 and RFC 5469. I.e. these algorithms
 * have the following properties:
 *
 * <ul>
 *   <li>The wrapping is deterministic. Hence wrapping can be compared against known results.
 *   <li>The wrapping has an integrity check. Modified wrapped keys can be detected with high
 *       probability.
 * </ul>
 *
 * <p>References:
 *
 * <ul>
 *   <li>RFC 3394 defines the key wrap algorithm for AES.
 *   <li>RFC 5649 defines the key wrap algroithm with padding for AES.
 *   <li>NIST SP 800-38F also define key wrap and key wrap with padding for AES. This document also
 *       includes similar algorithms for Triple DES. (However, triple DES not tested here.)
 *   <li>RFC 3657 generalizes RFC 3394 to Camellia. There is no version with padding.
 *   <li>RFC 4010 generalizes RFC 3394 to SEED.
 *   <li>RFC 5794 generalizes KW and KWP to ARIA.
 * </ul>
 *
 * <p><b>Algorithm names</b>: Unfortunately, the algorithm names for the various key wrapping
 * algorithms differ by provider. The code uses the algorithm names proposed by Oracle
 * https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html . I.e., the
 * proposed algorithm names are "AESWrap" and "AESWrapPad". Alternative names are:
 *
 * <ul>
 *   <li>OpenJdk also allows names with explicit key size (e.g. "AESWrap_128" or "AESWrapPad_128"
 *       etc.).
 *   <li>JDK-8261910 added the algorithm modes "KW" and "KWP". Hence "AES/KW/NoPadding" and
 *       "AES/KWP/NoPadding" are options. This change also added "AES/KW/Pkcs5Padding". This
 *       algorithm is not tested here.
 *   <li>BouncyCastle knows "AESWRAP" and "AESWRAPPAD". Alternatively, the algorithm name
 *       AESRFC5649WRAP is possible. AESRFC3211WRAP is an unrelated algorithm not tested here.
 *       BouncyCastle also implements key wrappings using Aria, Camellia and Seed. (There are also
 *       implementations using RC2 and DesEDE. These are not tested here.)
 *   <li>IAIK allows algorithm names such as "AESWrap/ECB/RFC5649Padding" and "AESWrapWithPadding".
 *       https://javadoc.iaik.tugraz.at/iaik_jce/current/iaik/security/cipher/AESKeyWrap.html
 *   <li>Other names that can be found are "AESWrap/ECB/ZeroPadding" or AESWrap/ECB/PKCS5Padding.
 * </ul>
 *
 * The algorithm names used in the test vectors Are <cipher>-WRAP and <cipher>-KWP.
 */
@RunWith(JUnit4.class)
public class JsonKeyWrapTest {

  /** Convenience method to get a byte array from a JsonObject. */
  protected static byte[] getBytes(JsonObject object, String name) throws Exception {
    return JsonUtil.asByteArray(object.get(name));
  }

  protected static Cipher getCipher(String algorithm) throws Exception {
    switch (algorithm) {
      case "AES-WRAP":
        try {
          return Cipher.getInstance("AESWRAP");
        } catch (NoSuchAlgorithmException ex) {
          // AESWRAP is not known, but the encryption mode KW might be supported.
        }
        return Cipher.getInstance("AES/KW/NoPadding");
      case "AES-KWP":
        try {
          return Cipher.getInstance("AESWRAPPAD");
        } catch (NoSuchAlgorithmException ex) {
          // AESWRAPPAD is not known, but the encryption mode KWP might be supported.
        }
        return Cipher.getInstance("AES/KWP/NoPadding");
      case "ARIA-WRAP":
        return Cipher.getInstance("ARIAWRAP");
      case "ARIA-KWP":
        return Cipher.getInstance("ARIAWRAPPAD");
      case "CAMELLIA-WRAP":
        return Cipher.getInstance("CAMELLIAWRAP");
      case "SEED-WRAP":
        return Cipher.getInstance("SEEDWRAP");
      default:
        throw new NoSuchAlgorithmException(algorithm);
    }
  }

  protected static SecretKeySpec getSecretKeySpec(String algorithm, byte[] key) throws Exception {
    switch (algorithm) {
      case "AES-WRAP":
      case "AES-KWP":
        return new SecretKeySpec(key, "AES");
      case "ARIA-WRAP":
      case "ARIA-KWP":
        return new SecretKeySpec(key, "ARIA");
      case "CAMELLIA-WRAP":
        return new SecretKeySpec(key, "CAMELLIA");
      case "SEED-WRAP":
        return new SecretKeySpec(key, "SEED");
      default:
        throw new NoSuchAlgorithmException(algorithm);
    }
  }

  /**
   * The test also determines whether different paddings lead to different exceptions. Generally it
   * is preferable when unwrapping keys with incorrect paddings does not leak information about
   * invalid paddings through exceptions. Such information could be used for an attack. Ideally,
   * providers should not include any distinguishing features in the exception.
   *
   * <p>However, such an observation does not necessarily imply a vulnerability. For example the
   * algorithm KW (NIST SP 800 38f) is designed with the idea that the underlying algorithm W is a
   * strong pseudorandom permuation. This would imply that the algorithm is resistant against
   * attacks even if the attacker get access to all the byte of W^-1 in the case of a failure. For
   * such primitives the exceptions thrown during the test are printed, but distinct execeptions do
   * not fail the test.
   *
   * @param filename the local filename with the test vectors
   * @param algorithm the algorithm name for the key wrapping (e.g. "AESWrap")
   * @param wrappedAlgorithm the algorithm name for the secret key that is wrapped (e.g.
   *     "HMACSHA256"). The key wrap primitives wrap and unwrap byte arrays. However, the JCE
   *     interface requires an instance of java.security.Key with key material. The key wrap
   *     primitive does not depend on wrappedAlgorithm and hence neither does the test. "HMACSHA256"
   *     is used for this parameter in the tests below, simply because HMAC allows arbitrary key
   *     sizes.
   * @param paddingAttacks determines whether the test fails if exceptions leak information about
   *     the padding.
   */
  // This is a false positive, since errorprone cannot track values passed into a method.
  @SuppressWarnings("InsecureCryptoUsage")
  public void testKeywrap(String filename, String wrappedAlgorithm, boolean paddingAttacks)
      throws Exception {
    // Testing with old test vectors may a reason for a test failure.
    // Version number have the format major.minor[status].
    // Versions before 1.0 are experimental and  use formats that are expected to change.
    // Versions after 1.0 change the major number if the format changes and change
    // the minor number if only the test vectors (but not the format) changes.
    // Versions meant for distribution have no status.
    JsonObject test = JsonUtil.getTestVectorsV1(filename);
    Set<String> exceptions = new TreeSet<String>();
    String algorithm = test.get("algorithm").getAsString();

    int errors = 0;
    Cipher cipher;
    try {
      cipher = getCipher(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest("Algorithm " + algorithm + " is not supported.");
      return;
    }
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        int tcid = testcase.get("tcId").getAsInt();
        String tc = "tcId: " + tcid + " " + testcase.get("comment").getAsString();
        byte[] key = getBytes(testcase, "key");
        byte[] data = getBytes(testcase, "msg");
        byte[] expected = getBytes(testcase, "ct");
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext, ciphertext and tag.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
        // "acceptable" are test vectors with weak parameters or legacy formats.
        String result = testcase.get("result").getAsString();

        // Test wrapping
        try {
          SecretKeySpec keySpec = getSecretKeySpec(algorithm, key);
          cipher.init(Cipher.WRAP_MODE, keySpec);
          SecretKeySpec keyToWrap = new SecretKeySpec(data, wrappedAlgorithm);
          byte[] wrapped = cipher.wrap(keyToWrap);
          boolean eq = Arrays.equals(expected, wrapped);
          if (result.equals("invalid")) {
            if (eq) {
              // Some test vectors use invalid parameters that should be rejected.
              System.out.printf("Wrapped test case:%s", tc);
              errors++;
            }
          } else {
            if (!eq) {
              System.out.printf("Incorrect wrapping for test case:%s wrapped butes:%s",
                                tc, TestUtil.bytesToHex(wrapped));
              errors++;
            }
          }
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
          // IllegalArgumentException can be thrown by new SecretKeySpec
          if (result.equals("valid")) {
            System.out.printf("Failed to wrap test case:%s", tc);
            errors++;
          }
        } catch (Exception ex) {
          // Other exceptions are violating the interface.
          System.out.printf("Test case %s throws %s.", tc, ex);
          errors++;
        }

        // Test unwrapping
        // The algorithms tested in this class are typically malleable. Hence, it is in possible
        // that modifying ciphertext randomly results in some other valid ciphertext.
        // However, all the test vectors in Wycheproof are constructed such that they have
        // invalid padding. If this changes then the test below is too strict.
        try {
          SecretKeySpec keySpec = getSecretKeySpec(algorithm, key);
          cipher.init(Cipher.UNWRAP_MODE, keySpec);
          Key wrappedKey = cipher.unwrap(expected, wrappedAlgorithm, Cipher.SECRET_KEY);
          byte[] unwrapped = wrappedKey.getEncoded();
          boolean eq = Arrays.equals(data, unwrapped);
          if (result.equals("invalid")) {
            System.out.printf("Unwrapped invalid test case:%s unwrapped:%s", tc,
                              TestUtil.bytesToHex(unwrapped));
            errors++;
          } else {
            if (!eq) {
              System.out.printf("Incorrect unwrap. Excepted:%s actual:%s",
                                unwrapped, TestUtil.bytesToHex(unwrapped));
              errors++;
            }
          }
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
          // The JCE interface specifies that an incorrect wrapping should throw an
          // InvalidKeyException. IllegalArgumentException is thrown by the SecretKeySpec
          // constructor if the unwrapped key is empty. It is unclear whether this is a bug
          // in the code or just should be documented.
          exceptions.add(ex.toString());
          if (result.equals("valid")) {
            System.out.printf("Failed to unwrap:%s", tc);
            errors++;
          }
        } catch (Exception ex) {
          // Other exceptions may indicate a programming error.
          System.out.printf("Test case:%s throws %s", tc, ex);
          exceptions.add(ex.toString());
          errors++;
        }
      }
    }
    System.out.printf("Number of distinct exceptions of %s:%d", algorithm, exceptions.size());
    for (String ex : exceptions) {
      System.out.println(ex);
    }
    assertEquals(0, errors);
    if (paddingAttacks) {
      assertEquals(1, exceptions.size());
    }
  }

  // BouncyCastle 1.64 tries to do unwrapping in constant time, but the code forgets to
  // do a number of range checks. This results in a number of runtime exceptions, which
  // is of course worse than timing differences.
  // There are fixes in version 1.67, that may fix the issues.
  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/77572633"})
  @Test
  public void testAesWrap() throws Exception {
    testKeywrap("aes_wrap_test.json", "HMACSHA256", false);
  }

  @Test
  public void testAesKwp() throws Exception {
    testKeywrap("aes_kwp_test.json", "HMACSHA256", false);
  }

  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/77572633"})
  @Test
  public void testAriaWrap() throws Exception {
    testKeywrap("aria_wrap_test.json", "HMACSHA256", false);
  }

  @Test
  public void testAriaKwp() throws Exception {
    testKeywrap("aria_kwp_test.json", "HMACSHA256", false);
  }

  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/77572633"})
  @Test
  public void testCamelliaWrap() throws Exception {
    testKeywrap("camellia_wrap_test.json", "HMACSHA256", false);
  }

  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/77572633"})
  @Test
  public void testSeedWrap() throws Exception {
    testKeywrap("seed_wrap_test.json", "HMACSHA256", false);
  }
}
