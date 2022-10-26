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
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
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
  private static byte[] getBytes(JsonObject obj, String name) throws Exception {
    return JsonUtil.asByteArray(obj.get(name));
  }

  private static Mac getMac(String algorithmName) throws NoSuchAlgorithmException {
    try {
      return Mac.getInstance(algorithmName);
    } catch (NoSuchAlgorithmException ex) {
      // Some provider use alternative algorithm names.
    }
    switch (algorithmName) {
      case "AES-CMAC":
        // BouncyCastle generally uses a hyphen for CMAC algorithms.
        // However, AES-CMAC is an exception.
        return Mac.getInstance("AESCMAC");
      case "SipHashX-2-4":
        // Try the name used by BouncyCastle.
        return Mac.getInstance("SIPHASH128-2-4");
      case "SipHashX-4-8":
        // Try the name used by BouncyCastle.
        return Mac.getInstance("SIPHASH128-4-8");
      default:
        break;
    }
    throw new NoSuchAlgorithmException(algorithmName);
  }

  /**
   * Computes a MAC.
   *
   * @param algorithm the algorithm.
   * @param key the key bytes
   * @param msg the message to MAC.
   * @param tagSize the expected size of the tag in bits.
   * @return the tag
   * @throws NoSuchAlgorithmException if truncation is not supported. The JCE interface is not well
   *     defined for truncating MACs, hence this test does not try to call a MAC with specific
   *     parameter. For MACs where truncation is well defined, (e.g., HMAC), truncation is done in
   *     this function. Otherwise a NoSuchAlgorithmException is thrown.
   * @throws InvalidKeyException if the key is invalid
   */
  private static byte[] computeMac(String algorithm, byte[] key, byte[] msg, int tagSize)
      throws NoSuchAlgorithmException, InvalidKeyException {
    Mac mac = getMac(algorithm);
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
    //   But this class is often not supported. Hence the computation here just computes a
    //   full length tag and truncates the tag in some known cases.
    mac.init(keySpec);
    mac.update(msg);
    byte[] tag = mac.doFinal();
    if (tag.length == tagSize / 8) {
      return tag;
    } else if (algorithm.startsWith("HMAC")) {
      return Arrays.copyOf(tag, tagSize / 8);
    } else {
      throw new NoSuchAlgorithmException("Truncation not supported for " + algorithm);
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
    JsonObject test = JsonUtil.getTestVectorsV1(filename);
    String algorithm = test.get("algorithm").getAsString();
    try {
      Mac unused = getMac(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest("Algorithm is not supported. Skipping test for " + algorithm);
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

        boolean eq = MessageDigest.isEqual(expectedTag, computedTag);
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
    // It is possible that an algorithm is implemented, but that the implementation
    // is so specialized that no valid test vectors passed the test.
    // For example, boringSSL used to implement AES-CCM only for the parameter sizes
    // used in bluetooth. This generated no overlap with the test vectors from
    // Wycheproof.
    // In such cases the test is marked as skipped.
    if (passedTests == 0) {
      TestUtil.skipTest("No test passed");
    }
  }

  /**
   * Computes a randomized MAC.
   *
   * <p>Randomized MACs are MACs that require a nonce for their security. A typical example are
   * Carter-Wegman constructions. These MACs are often used in AEAD constructions that have to be
   * randomized anyway. They are seldom used as a standalone MAC, because the requirement of a
   * nonce makes them more difficult to use and results in longer digests.
   *
   * @param algorithm the algorithm.
   * @param key the key bytes
   * @param iv the bytes of the initialization vector
   * @param tagSize the expected size of the tag in bits.
   * @return the mac
   * @throws NoSuchAlgorithmException if the algorithm or the parameter sizes are not supported or
   *     if the initialization failed. For example one case are GMACs with a tag size other than 128
   *     bits, since the JCE interface does not seem to support such a specification.
   * @throws InvalidKeyException if the key is invalid
   * @throws InvalidAlgorithmParameterException if algorithm parameters are invalid
   */
  private static byte[] computeMacWithIv(
      String algorithm, byte[] key, byte[] iv, byte[] msg, int tagSize)
      throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
    Mac mac = getMac(algorithm);
    switch (algorithm) {
      case "AES-GMAC":
        // GMAC is defined in NIST SP 800-38d, Section 3. It is simply a GCM encryption
        // where the message is empty and only the AD is authenticated.
        // Hence the most portable way to implement AES-GMAC appears to be using AES-GCM.
        // GMAC like GCM requires that each call uses a unique IV.
        //
        // AES-GMAC as a MAC is to our knowledge only implemented by BouncyCastle.
        // Additionally the implementation in BouncyCastle is further restricted as we have not
        // been able to find a way to specify the tagSize.
        // E.g., using parameters defined as
        // <code>
        //   GCMParameterSpec params = new GCMParameterSpec(tagSize, iv);
        // </code>
        // only works for AES-GCM but not nor AES-GMAC.
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        AlgorithmParameterSpec params = new IvParameterSpec(iv);
        if (tagSize != 128) {
          throw new NoSuchAlgorithmException("Only 128-bit tags supported for " + algorithm);
        }
        mac.init(keySpec, params);
        return mac.doFinal(msg);
      default:
        throw new NoSuchAlgorithmException("Not supported:" + algorithm);
    }
  }

  /**
   * Tests a randomized MAC (i.e. a message authetication that takes an additional IV as parameter)
   * against test vectors.
   *
   * @param filename the JSON file with the test vectors.
   */
  public void testMacWithIv(String filename) throws Exception {
    JsonObject test = JsonUtil.getTestVectorsV1(filename);
    String algorithm = test.get("algorithm").getAsString();

    // Checking preconditions.
    try {
      Mac.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest("Algorithm is not supported. Skipping test for " + algorithm);
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
        byte[] iv = getBytes(testcase, "iv");
        byte[] msg = getBytes(testcase, "msg");
        byte[] expectedTag = getBytes(testcase, "tag");
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext, ciphertext and tag.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
        // "acceptable" are test vectors with weak parameters or legacy formats.
        String result = testcase.get("result").getAsString();
        byte[] computedTag;
        try {
          computedTag = computeMacWithIv(algorithm, key, iv, msg, tagSize);
        } catch (GeneralSecurityException ex) {
          // Some libraries restrict key size, iv size and tag size.
          // Because of the initialization of the Mac might fail.
          continue;
        } catch (IllegalArgumentException ex) {
          // Thrown by javax.crypto.spec.SecretKeySpec (e.g. when the key is empty).
          continue;
        }
        boolean eq = MessageDigest.isEqual(expectedTag, computedTag);
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
    if (passedTests == 0) {
      TestUtil.skipTest("No test passed");
    }
  }

  @Test
  public void testAesCmac() throws Exception {
    testMac("aes_cmac_test.json");
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
  public void testHmacSha512_224() throws Exception {
    testMac("hmac_sha512_224_test.json");
  }

  @Test
  public void testHmacSha512_256() throws Exception {
    testMac("hmac_sha512_256_test.json");
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
  public void testSipHash24() throws Exception {
    testMac("siphash_2_4_test.json");
  }

  @Test
  public void testSipHash48() throws Exception {
    testMac("siphash_4_8_test.json");
  }

  @Test
  public void testSipHashX24() throws Exception {
    testMac("siphashx_2_4_test.json");
  }

  @Test
  public void testSipHashX48() throws Exception {
    testMac("siphashx_4_8_test.json");
  }

  @Test
  public void testAesGmac() throws Exception {
    testMacWithIv("aes_gmac_test.json");
  }
}
