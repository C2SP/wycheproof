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
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** This test uses test vectors in JSON format to test AEAD schemes. */
@RunWith(JUnit4.class)
public class JsonAeadTest {


  /** Joins two bytearrays. */
  protected static byte[] join(byte[] head, byte[] tail) {
    byte[] res = new byte[head.length + tail.length];
    System.arraycopy(head, 0, res, 0, head.length);
    System.arraycopy(tail, 0, res, head.length, tail.length);
    return res;
  }

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

  protected static void initCipher(Cipher cipher, int opmode, byte[] key, byte[] iv, int tagSize)
      throws Exception {
    String algorithm = cipher.getAlgorithm();
    if (algorithm.equalsIgnoreCase("AES/GCM/NoPadding")) {
      SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
      GCMParameterSpec parameters = new GCMParameterSpec(tagSize, iv);
      cipher.init(opmode, keySpec, parameters);
    } else if (algorithm.equalsIgnoreCase("AES/EAX/NoPadding")) {
      SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
      // TODO(bleichen): This works for BouncyCastle but looks non-standard.
      //   org.bouncycastle.crypto.params.AEADParameters works too, but would add a dependency that
      //   we want to avoid.
      GCMParameterSpec parameters = new GCMParameterSpec(tagSize, iv);
      cipher.init(opmode, keySpec, parameters);
    } else {
      fail("Algorithm not supported:" + algorithm);
    }
  }

  /** Example format for test vectors
   * {
   *   "algorithm" : "AES-EAX",
   *   "generatorVersion" : "0.0a14",
   *   "numberOfTests" : 143,
   *   "testGroups" : [
   *     {
   *       "ivSize" : 128,
   *       "keySize" : 128,
   *       "tagSize" : 128,
   *       "type" : "AES-EAX",
   *       "tests" : [
   *         {
   *           "aad" : "6bfb914fd07eae6b",
   *           "comment" : "eprint.iacr.org/2003/069",
   *           "ct" : "",
   *           "iv" : "62ec67f9c3a4a407fcb2a8c49031a8b3",
   *           "key" : "233952dee4d5ed5f9b9c6d6ff80ff478",
   *           "msg" : "",
   *           "result" : "valid",
   *           "tag" : "e037830e8389f27b025a2d6527e79d01",
   *           "tcId" : 1
   *         },
   *        ...
   **/
  // This is a false positive, since errorprone cannot track values passed into a method.
  @SuppressWarnings("InsecureCryptoUsage")
  public void testAead(String filename, String algorithm) throws Exception {
    // Testing with old test vectors may a reason for a test failure.
    // Version number have the format major.minor[status].
    // Versions before 1.0 are experimental and  use formats that are expected to change.
    // Versions after 1.0 change the major number if the format changes and change
    // the minor number if only the test vectors (but not the format) changes.
    // Versions meant for distribution have no status.
    final String expectedVersion = "0.4";
    JsonObject test = JsonUtil.getTestVectors(filename);
    String generatorVersion = test.get("generatorVersion").getAsString();
    if (!generatorVersion.equals(expectedVersion)) {
      System.out.println(
          algorithm
              + ": expecting test vectors with version "
              + expectedVersion
              + " found vectors with version "
              + generatorVersion);
    }
    int numTests = test.get("numberOfTests").getAsInt();
    int cntTests = 0;
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
      int tagSize = group.get("tagSize").getAsInt();
      for (JsonElement t : group.getAsJsonArray("tests")) {
        cntTests++;
        JsonObject testcase = t.getAsJsonObject();
        int tcid = testcase.get("tcId").getAsInt();
        String tc = "tcId: " + tcid + " " + testcase.get("comment").getAsString();
        byte[] key = getBytes(testcase, "key");
        byte[] iv = getBytes(testcase, "iv");
        byte[] msg = getBytes(testcase, "msg");
        byte[] aad = getBytes(testcase, "aad");
        byte[] ciphertext = join(getBytes(testcase, "ct"), getBytes(testcase, "tag"));
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext, ciphertext and tag.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
        // "acceptable" are test vectors with weak parameters or legacy formats.
        String result = testcase.get("result").getAsString();

        // Test encryption
        try {
          initCipher(cipher, Cipher.ENCRYPT_MODE, key, iv, tagSize);
        } catch (GeneralSecurityException ex) {
          // Some libraries restrict key size, iv size and tag size.
          // Because of the initialization of the cipher might fail.
          continue;
        }
        try {
          cipher.updateAAD(aad);
          byte[] encrypted = cipher.doFinal(msg);
          boolean eq = arrayEquals(ciphertext, encrypted);
          if (result.equals("invalid")) {
            if (eq) {
              // Some test vectors use invalid parameters that should be rejected.
              // E.g. an implementation must never encrypt using AES-GCM with an IV of length 0,
              // since this leaks the authentication key.
              System.out.println("Encrypted " + tc);
              errors++;
            }
          } else {
            if (!eq) {
              System.out.println(
                  "Incorrect ciphertext for "
                      + tc
                      + " ciphertext:"
                      + TestUtil.bytesToHex(encrypted));
              errors++;
            }
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            System.out.println("Failed to encrypt " + tc);
            errors++;
          }
        }

        // Test decryption
        try {
          initCipher(cipher, Cipher.DECRYPT_MODE, key, iv, tagSize);
        } catch (GeneralSecurityException ex) {
          System.out.println("Parameters accepted for encryption but not decryption " + tc);
          errors++;
          continue;
        }
        try {
          cipher.updateAAD(aad);
          byte[] decrypted = cipher.doFinal(ciphertext);
          boolean eq = arrayEquals(decrypted, msg);
          if (result.equals("invalid")) {
            System.out.println("Decrypted invalid ciphertext " + tc + " eq:" + eq);
            errors++;
          } else {
            if (!eq) {
              System.out.println(
                  "Incorrect decryption " + tc + " decrypted:" + TestUtil.bytesToHex(decrypted));
            }
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            System.out.println("Failed to decrypt " + tc);
            errors++;
          }
        }
      }
    }
    assertEquals(0, errors);
    assertEquals(numTests, cntTests);
  }

  @Test
  public void testAesGcm() throws Exception {
    testAead("aes_gcm_test.json", "AES/GCM/NoPadding");
  }

  @Test
  public void testAesEax() throws Exception {
    testAead("aes_eax_test.json", "AES/EAX/NoPadding");
  }
}
