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
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * This test uses test vectors in JSON format to test symmetric ciphers.
 *
 * <p>Ciphers tested in this class are unauthenticated ciphers (i.e. don't have additional data) and
 * are randomized using an initialization vector as long as the JSON test vectors are represented
 * with the type "IndCpaTest".
 */
@RunWith(JUnit4.class)
public class JsonCipherTest {

  /** Convenience method to get a byte array from a JsonObject. */
  protected static byte[] getBytes(JsonObject object, String name) throws Exception {
    return JsonUtil.asByteArray(object.get(name));
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
   * Initialize a Cipher instance.
   *
   * @param cipher an instance of a symmetric cipher that will be initialized.
   * @param algorithm the name of the algorithm used (e.g. 'AES')
   * @param opmode either Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
   * @param key raw key bytes
   * @param iv the initialisation vector
   */
  protected static void initCipher(
      Cipher cipher, String algorithm, int opmode, byte[] key, byte[] iv) throws Exception {
    SecretKeySpec keySpec = null;
    if (algorithm.startsWith("AES/")) {
      keySpec = new SecretKeySpec(key, "AES");
    } else {
      fail("Unsupported algorithm:" + algorithm);
    }
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    cipher.init(opmode, keySpec, ivSpec);
  }


  /** Example format for test vectors
   * {
   *   "algorithm" : "AES-CBC-PKCS5",
   *   "generatorVersion" : "0.2.1",
   *   "numberOfTests" : 183,
   *   "header" : [
   *   ],
   *   "testGroups" : [
   *     {
   *       "ivSize" : 128,
   *       "keySize" : 128,
   *       "type" : "IndCpaTest",
   *       "tests" : [
   *         {
   *           "tcId" : 1,
   *           "comment" : "empty message",
   *           "key" : "e34f15c7bd819930fe9d66e0c166e61c",
   *           "iv" : "da9520f7d3520277035173299388bee2",
   *           "msg" : "",
   *           "ct" : "b10ab60153276941361000414aed0a9d",
   *           "result" : "valid"
   *         },
   *         ...
   **/
  // This is a false positive, since errorprone cannot track values passed into a method.
  @SuppressWarnings("InsecureCryptoUsage")
  public void testCipher(String filename, String algorithm) throws Exception {
    // Testing with old test vectors may a reason for a test failure.
    // Version number have the format major.minor[status].
    // Versions before 1.0 are experimental and  use formats that are expected to change.
    // Versions after 1.0 change the major number if the format changes and change
    // the minor number if only the test vectors (but not the format) changes.
    // Versions meant for distribution have no status.
    final String expectedVersion = "0.4";
    JsonObject test = JsonUtil.getTestVectors(filename);
    Set<String> exceptions = new TreeSet<String>();
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
      for (JsonElement t : group.getAsJsonArray("tests")) {
        cntTests++;
        JsonObject testcase = t.getAsJsonObject();
        int tcid = testcase.get("tcId").getAsInt();
        String tc = "tcId: " + tcid + " " + testcase.get("comment").getAsString();
        byte[] key = getBytes(testcase, "key");
        byte[] iv = getBytes(testcase, "iv");
        byte[] msg = getBytes(testcase, "msg");
        byte[] ciphertext = getBytes(testcase, "ct");
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext, ciphertext and tag.
        // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
        // "acceptable" are test vectors with weak parameters or legacy formats.
        String result = testcase.get("result").getAsString();

        // Test encryption
        try {
          initCipher(cipher, algorithm, Cipher.ENCRYPT_MODE, key, iv);
        } catch (GeneralSecurityException ex) {
          // Some libraries restrict key size, iv size and tag size.
          // Because of the initialization of the cipher might fail.
          System.out.println(ex.toString());
          continue;
        }
        try {
          byte[] encrypted = cipher.doFinal(msg);
          boolean eq = arrayEquals(ciphertext, encrypted);
          if (result.equals("invalid")) {
            if (eq) {
              // Some test vectors use invalid parameters that should be rejected.
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
        // The algorithms tested in this class are typically malleable. Hence, it is in possible
        // that modifying ciphertext randomly results in some other valid ciphertext.
        // However, all the test vectors in Wycheproof are constructed such that they have
        // invalid padding. If this changes then the test below is too strict.
        try {
          initCipher(cipher, algorithm, Cipher.DECRYPT_MODE, key, iv);
        } catch (GeneralSecurityException ex) {
          System.out.println("Parameters accepted for encryption but not decryption " + tc);
          errors++;
          continue;
        }
        try {
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
          exceptions.add(ex.getMessage());
          if (result.equals("valid")) {
            System.out.println("Failed to decrypt " + tc);
            errors++;
          }
        }
      }
    }
    assertEquals(0, errors);
    assertEquals(numTests, cntTests);
    // Generally it is preferable if trying to decrypt ciphertexts with incorrect paddings
    // does not leak information about invalid paddings through exceptions.
    // Such information could simplify padding attacks. Ideally, providers should not include
    // any distinguishing features in the exception. Hence, we expect just one exception here.
    //
    // Seeing distinguishable exception, doesn't necessarily mean that protocols using
    // AES/CBC/PKCS5Padding with the tested provider are vulnerable to attacks. Rather it means
    // that the provider might simplify attacks if the protocol is using AES/CBC/PKCS5Padding
    // incorrectly.
    System.out.println("Number of distinct exceptions:" + exceptions.size());
    for (String ex : exceptions) {
      System.out.println(ex);
    }
    assertEquals(1, exceptions.size());
  }

  @Test
  public void testAesCbcPkcs5() throws Exception {
    testCipher("aes_cbc_pkcs5_test.json", "AES/CBC/PKCS5Padding");
  }
}
