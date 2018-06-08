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
import static org.junit.Assert.fail;

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
 * <p>This test is mainly for key wrappings such as RFC 3349 and RFC 5469.
 * I.e. these algorithms have the following properties:
 * <ul>
 *   <li>The wrapping is deterministic. Hence wrapping can be compared against known
 *   results.
 *   <li>The wrapping has an integrity check. Modified wrapped keys can be detected
 *   with high probability.
 * </ul>
 * This test does not cover key wrapping with AEAD algorithms such as AES-GCM.
 * Testing such algorithms would require an additional test vector type. 
 * I.e., the JCE interface requires that the caller himself handles the IV.
 * I.e. each wrapping has to use a new unique IV. This IV has to be stored additionally
 * with the wrapped key and has to be passed as parameter to unwrap.
 */
@RunWith(JUnit4.class)
public class JsonKeyWrapTest {

  /** Convenience method to get a byte array from a JsonObject. */
  protected static byte[] getBytes(JsonObject object, String name) throws Exception {
    return JsonUtil.asByteArray(object.get(name));
  }

  /**
   * Initialize a Cipher instance for key wrapping.
   *
   * @param cipher an instance of a symmetric cipher that will be initialized.
   * @param algorithm the name of the algorithm used (e.g. 'KW')
   * @param opmode either Cipher.WRAP_MODE or Cipher.UNWRAP_MODE
   * @param key raw key bytes
   */
  protected static void initCipher(Cipher cipher, String algorithm, int opmode, byte[] key)
      throws Exception {
    if (algorithm.toUpperCase().equals("AESWRAP")
            || algorithm.toUpperCase().equals("AESRFC5649WRAP")) {
      cipher.init(opmode, new SecretKeySpec(key, "AES"));
    } else {
      fail("Unsupported algorithm:" + algorithm);
    }
  }

  /**
   * <p> The test also determines whether different paddings lead to different exceptions.
   * Generally it is preferable when unwrapping keys with incorrect paddings does not leak
   * information about invalid paddings through exceptions. Such information could be used
   * for an attack. Ideally, providers should not include any distinguishing features in the
   * exception.
   *
   * <p>However, such an observation does not necessarily imply a vulnerability.
   * For example the algorithm KW (NIST SP 800 38f) is designed with the idea that the
   * underlying algorithm W is a strong pseudorandom permuation. This would imply that the
   * algorithm is resistant against attacks even if the attacker get access to all the
   * byte of W^-1 in the case of a failure. For such primitives the exceptions thrown during
   * the test are printed, but distinct execeptions do not fail the test.
   *
   * @param filename the local filename with the test vectors
   * @param algorithm the algorithm name for the key wrapping (e.g. "AESWrap")
   * @param wrappedAlgorithm the algorithm name for the secret key that is wrapped 
   *    (e.g. "HMACSHA256"). The key wrap primitives wrap and unwrap byte arrays.
   *    However, the JCE interface requires an instance of java.security.Key with
   *    key material. The key wrap primitive does not depend on wrappedAlgorithm and hence
   *    neither does the test. "HMACSHA256" is used for this parameter in the tests below, 
   *    simply because HMAC allows arbitrary key sizes.
   * @param paddingAttacks determines whether the test fails if exceptions leak information
   *    about the padding.
   */
  // This is a false positive, since errorprone cannot track values passed into a method.
  @SuppressWarnings("InsecureCryptoUsage")
  public void testKeywrap(String filename, String algorithm, String wrappedAlgorithm,
      boolean paddingAttacks) throws Exception {
    // Testing with old test vectors may a reason for a test failure.
    // Version number have the format major.minor[status].
    // Versions before 1.0 are experimental and  use formats that are expected to change.
    // Versions after 1.0 change the major number if the format changes and change
    // the minor number if only the test vectors (but not the format) changes.
    // Versions meant for distribution have no status.
    final String expectedVersion = "0.4.1";
    JsonObject test = JsonUtil.getTestVectors(filename);
    Set<String> exceptions = new TreeSet<String>();
    String generatorVersion = test.get("generatorVersion").getAsString();
    if (!generatorVersion.equals(expectedVersion)) {
      System.out.printf("%s expects test vectors with version %s found version %s.",
                        algorithm, expectedVersion, generatorVersion);
    }
    int errors = 0;
    Cipher cipher;
    try {
      cipher = Cipher.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("Algorithm is not supported. Skipping test for " + algorithm);
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
          initCipher(cipher, algorithm, Cipher.WRAP_MODE, key);
        } catch (GeneralSecurityException ex) {
          // Some libraries may restrict key size.
          // Because of this the initialization of the cipher might fail.
          System.out.println(ex.toString());
          continue;
        }
        try {
          SecretKeySpec keyspec = new SecretKeySpec(data, wrappedAlgorithm);
          byte[] wrapped = cipher.wrap(keyspec);
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
          initCipher(cipher, algorithm, Cipher.UNWRAP_MODE, key);
        } catch (GeneralSecurityException ex) {
          System.out.printf("Parameters accepted for wrapping but not unwrapping:%s", tc);
          errors++;
          continue;
        }
        try {
          Key keyspec = cipher.unwrap(expected, wrappedAlgorithm, Cipher.SECRET_KEY);
          byte[] unwrapped = keyspec.getEncoded();
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

  @NoPresubmitTest(
    providers = {ProviderType.BOUNCY_CASTLE},
    bugs = {"b/77572633"}
  )
  @Test
  public void testAesWrap() throws Exception {
    testKeywrap("kw_test.json", "AESWRAP", "HMACSHA256", false);
  }

  @NoPresubmitTest(
    providers = {ProviderType.BOUNCY_CASTLE},
    bugs = {"b/77572633"}
  )
  @Test
  public void testAesRFC5649Wrap() throws Exception {
    testKeywrap("kwp_test.json", "AESRFC5649WRAP", "HMACSHA256", false);
  }
  
  
}
