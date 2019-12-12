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

import static org.junit.Assert.assertEquals;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** This test uses test vectors in JSON format to test MAC primitives. */
@RunWith(JUnit4.class)
public class JsonMacTest {

  /** Convenience method to get a byte array from an JsonObject */
  protected static byte[] getBytes(JsonObject obj, String name) throws Exception {
    return JsonUtil.asByteArray(obj.get(name));
  }

  protected static boolean arrayEquals(byte[] a, byte[] b) {
    if (a.length != b.length) {
      return false;
    }
    byte res = 0;
    for (int i = 0; i < a.length; i++) {
      res |= (byte) (a[i] ^ b[i]);
    }
    return res == 0;
  }

  /**
   * Computes a MAC.
   *
   * @param algorithm the algorithm.
   * @param key the key bytes
   * @param msg the message to MAC.
   * @param tagSize the expected size of the tag in bits.
   * @return the tag
   * @throws GeneralSecurityException if the algorithm or the parameter sizes are not supported or
   *     if the initialization failed. For example one case are GMACs with a tag size othe than 128
   *     bits, since the JCE interface does not seem to support such a specification.
   */
  protected static byte[] computeMac(String algorithm, byte[] key, byte[] msg, int tagSize)
      throws GeneralSecurityException {
    Mac mac = Mac.getInstance(algorithm);
    algorithm = algorithm.toUpperCase(Locale.ENGLISH);
    if (algorithm.startsWith("HMAC")) {
      SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
      // TODO(bleichen): Is there a provider independent truncation?
      //   The class javax.xml.crypto.dsig.spec.HMACParameterSpec would allow to
      //   truncate HMAC tags as follows:
      //   <pre>
      //     HMACParameterSpec params = new HMACParameterSpec(tagSize);
      //     mac.init(keySpec, params);
      //     mac.update(msg);
      //     return mac.doFinal();
      //   </pre>
      //   But this class is often not supported. Hence the computation here, just computes a
      //   full length tag and truncates it. The drawback of having to truncate tags is that
      //   the caller has to compare truncated tags during verification.
      mac.init(keySpec);
      mac.update(msg);
      byte[] tag = mac.doFinal();
      return Arrays.copyOf(tag, tagSize / 8);
    } else {
      throw new NoSuchAlgorithmException(algorithm);
    }
  }

  /**
   * Tests a randomized MAC (i.e. a message authetication that takes an additional IV as parameter)
   * against test vectors.
   *
   * @param filename the JSON file with the test vectors.
   */
  public void testMac(String filename) throws Exception {
    // Checking preconditions.
    JsonObject test = JsonUtil.getTestVectors(filename);
    String algorithm = test.get("algorithm").getAsString();
    try {
      Mac.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("Algorithm is not supported. Skipping test for " + algorithm);
      return;
    }

    int numTests = test.get("numberOfTests").getAsInt();
    int cntTests = 0;
    int passedTests = 0;
    int errors = 0;
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      int tagSize = group.get("tagSize").getAsInt();
      for (JsonElement t : group.getAsJsonArray("tests")) {
        cntTests++;
        JsonObject testcase = t.getAsJsonObject();
        int tcid = testcase.get("tcId").getAsInt();
        String tc = "tcId: " + tcid + " " + testcase.get("comment").getAsString();
        byte[] key = getBytes(testcase, "key");
        byte[] msg = getBytes(testcase, "msg");
        byte[] expectedTag = getBytes(testcase, "tag");
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext, ciphertext and tag.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
        // "acceptable" are test vectors with weak parameters or legacy formats.
        String result = testcase.get("result").getAsString();

        byte[] computedTag = null;
        try {
          computedTag = computeMac(algorithm, key, msg, tagSize);
        } catch (GeneralSecurityException ex) {
          // Some libraries restrict key size or tag size. Hence valid MACs might be
          // rejected.
          continue;
        } catch (IllegalArgumentException ex) {
          // Thrown by javax.crypto.spec.SecretKeySpec (e.g. when the key is empty).
          continue;
        }

        boolean eq = arrayEquals(expectedTag, computedTag);
        if (result.equals("invalid")) {
          if (eq) {
            // Some test vectors use invalid parameters that should be rejected.
            // E.g. an implementation must not allow AES-GMAC with an IV of length 0,
            // since this leaks the authentication key.
            System.out.println("Computed mac for test case " + tc);
            errors++;
          }
        } else {
          if (eq) {
            passedTests++;
          } else {
            System.out.println(
                "Incorrect tag for "
                    + tc
                    + " expected:"
                    + TestUtil.bytesToHex(expectedTag)
                    + " computed:"
                    + TestUtil.bytesToHex(computedTag));
            errors++;
          }
        }
      }
    }
    System.out.println("passed Tests for " + algorithm + ":" + passedTests);
    assertEquals(0, errors);
    assertEquals(numTests, cntTests);
  }

  /**
   * Returns an initialized instance of a randomized MAC.
   *
   * @param algorithm the algorithm.
   * @param key the key bytes
   * @param iv the bytes of the initialization vector
   * @param tagSize the expected size of the tag in bits.
   * @return an initialized instance of a MAC.
   * @throws GeneralSecurityException if the algorithm or the parameter sizes are not supported or
   *     if the initialization failed. For example one case are GMACs with a tag size othe than 128
   *     bits, since the JCE interface does not seem to support such a specification.
   */
  protected static Mac getInitializedMacWithIv(String algorithm, byte[] key, byte[] iv, int tagSize)
      throws GeneralSecurityException {
    Mac mac = Mac.getInstance(algorithm);
    algorithm = algorithm.toUpperCase(Locale.ENGLISH);
    if (algorithm.equals("AES-GMAC")) {
      SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
      if (tagSize != 128) {
        throw new InvalidAlgorithmParameterException("only 128-bit tag is supported");
      }
      IvParameterSpec params = new IvParameterSpec(iv);
      // TODO(bleichen): I'm unaware of a method that allows to specify the tag size in JCE.
      //   E.g. the following parameter specification does not work (at least not in BC):
      //   GCMParameterSpec params = new GCMParameterSpec(tagSize, iv);
      mac.init(keySpec, params);
      return mac;
    } else {
      throw new NoSuchAlgorithmException(algorithm);
    }
  }

  /**
   * Tests a randomized MAC (i.e. a message authetication that takes an additional IV as
   * parameter) against test vectors.
   *
   * @param filename the JSON file with the test vectors.
   * @param algorithm the JCE name of the algorithm to test.
   */
  public void testMacWithIv(String filename, String algorithm) throws Exception {
    // Checking preconditions.
    try {
      Mac.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("Algorithm is not supported. Skipping test for " + algorithm);
      return;
    }

    JsonObject test = JsonUtil.getTestVectors(filename);
    int numTests = test.get("numberOfTests").getAsInt();
    int cntTests = 0;
    int passedTests = 0;
    int errors = 0;
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      int tagSize = group.get("tagSize").getAsInt();
      for (JsonElement t : group.getAsJsonArray("tests")) {
        cntTests++;
        JsonObject testcase = t.getAsJsonObject();
        int tcid = testcase.get("tcId").getAsInt();
        String tc = "tcId: " + tcid + " " + testcase.get("comment").getAsString();
        byte[] key = getBytes(testcase, "key");
        byte[] iv = getBytes(testcase, "iv");
        byte[] msg = getBytes(testcase, "msg");
        byte[] expectedTag = getBytes(testcase, "tag");
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext, ciphertext and tag.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
        // "acceptable" are test vectors with weak parameters or legacy formats.
        String result = testcase.get("result").getAsString();

        Mac mac;
        try {
          mac = getInitializedMacWithIv(algorithm, key, iv, tagSize);
        } catch (GeneralSecurityException ex) {
          // Some libraries restrict key size, iv size and tag size.
          // Because of the initialization of the Mac might fail.
          continue;
        } catch (IllegalArgumentException ex) {
          // Thrown by javax.crypto.spec.SecretKeySpec (e.g. when the key is empty).
          continue;
        }

        byte[] computedTag = mac.doFinal(msg);
        boolean eq = arrayEquals(expectedTag, computedTag);
        if (result.equals("invalid")) {
          if (eq) {
            // Some test vectors use invalid parameters that should be rejected.
            // E.g. an implementation must not allow AES-GMAC with an IV of length 0,
            // since this leaks the authentication key.
            System.out.println("Computed mac for test case " + tc);
            errors++;
          }
        } else {
          if (eq) {
            passedTests++;
          } else {
            System.out.println(
                "Incorrect tag for "
                    + tc
                    + " expected:"
                    + TestUtil.bytesToHex(expectedTag)
                    + " computed:"
                    + TestUtil.bytesToHex(computedTag));
            errors++;
          }
        }
      }
    }
    System.out.println("passed Tests for " + algorithm + ":" + passedTests);
    assertEquals(0, errors);
    assertEquals(numTests, cntTests);
  }

  @Test
  public void testHmacSha1() throws Exception {
    testMac("hmac_sha1_test.json");
  }

  @Test
  public void testHmacSha224() throws Exception {
    testMac("hmac_sha224_test.json");
  }

  @Test
  public void testHmacSha256() throws Exception {
    testMac("hmac_sha256_test.json");
  }

  @Test
  public void testHmacSha384() throws Exception {
    testMac("hmac_sha384_test.json");
  }

  @Test
  public void testHmacSha512() throws Exception {
    testMac("hmac_sha512_test.json");
  }

  @Test
  public void testHmacSha3_224() throws Exception {
    testMac("hmac_sha3_224_test.json");
  }

  @Test
  public void testHmacSha3_256() throws Exception {
    testMac("hmac_sha3_256_test.json");
  }

  @Test
  public void testHmacSha3_384() throws Exception {
    testMac("hmac_sha3_384_test.json");
  }

  @Test
  public void testHmacSha3_512() throws Exception {
    testMac("hmac_sha3_512_test.json");
  }

  @Test
  public void testAesGmac() throws Exception {
    testMacWithIv("gmac_test.json", "AES-GMAC");
  }
}
