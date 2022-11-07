/**
 * Copyright 2022 Google LLC
 *
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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import java.lang.reflect.Constructor;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** This class tests format preserving encryptions. */
@RunWith(JUnit4.class)
public class JsonFpeTest {

  /** Wycheproof represents byte arrays as hexadeciamal strings. */
  private static byte[] getBytes(JsonObject object, String name) throws Exception {
    String hex = object.get(name).getAsString();
    return TestUtil.hexToBytes(hex);
  }

  /**
   * Plaintext and ciphertexts are represented as list of integers in the range 0 .. radix-1.
   * BouncyCastle uses bytes.
   */
  private static byte[] getMessage(JsonObject object, String name, int radix) throws Exception {
    JsonArray ba = object.get(name).getAsJsonArray();
    byte[] res = new byte[ba.size()];
    for (int i = 0; i < ba.size(); i++) {
      int val = ba.get(i).getAsInt();
      if (val < 0 || val >= radix) {
        return null;
      }
      res[i] = (byte) val;
    }
    return res;
  }

  /**
   * Returns the algorithm parameters for encrypting and decrypting with a given radix and tweak.
   *
   * @param radix the radix of plaintext and ciphertext
   * @param tweak the tweak for encryption and decryption.
   * @return algorithm parameters for encryption and decryption.
   * @throws NoSuchAlgorithmException if no suitable class for the algorithm parameters was found.
   * @throws java.lang.ReflectiveOperationException if reflection was incorrectly used. This should
   *     not happen unless the code here is incorrect or incomplete.
   */
  private static AlgorithmParameterSpec algorithmParameters(int radix, byte[] tweak)
      throws Exception {
    try {
      // Tries the parameter specification from BouncyCastle.
      // This code uses reflection, because there appears to be no way to use the JCA interface.
      Class<?> clazz = Class.forName("org.bouncycastle.jcajce.spec.FPEParameterSpec");
      Constructor<?> ctor = clazz.getDeclaredConstructor(int.class, byte[].class);
      return (AlgorithmParameterSpec) ctor.newInstance(radix, tweak);
    } catch (ClassNotFoundException ex) {
      // org.bouncycastle.jcajce.spec.FPEParameterSpec was not found
    }
    throw new NoSuchAlgorithmException("Can't construct an AlgorithmParameterSpec");
  }

  protected static byte[] encrypt(Cipher cipher, byte[] key, byte[] tweak, byte[] pt, int radix)
      throws Exception {
    AlgorithmParameterSpec fpeParameterSpec = algorithmParameters(radix, tweak);
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, fpeParameterSpec);
    return cipher.doFinal(pt);
  }

  protected static byte[] decrypt(Cipher cipher, byte[] key, byte[] tweak, byte[] ct, int radix)
      throws Exception {
    AlgorithmParameterSpec fpeParameterSpec = algorithmParameters(radix, tweak);
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    cipher.init(Cipher.DECRYPT_MODE, keySpec, fpeParameterSpec);
    return cipher.doFinal(ct);
  }

  private static Cipher getCipher(String algorithmName)
      throws NoSuchAlgorithmException, NoSuchPaddingException {
    if (algorithmName.equals("AES-FF1")) {
      return Cipher.getInstance("AES/FF1/NoPadding");
    } else {
      throw new NoSuchAlgorithmException(algorithmName + " not supported");
    }
  }

  /**
   * Example:
   *
   * <pre>
   * "algorithm" : "AES-FF1",
   * "generatorVersion" : "0.9rc5",
   * "numberOfTests" : 1852,
   * "header" : [
   *   "Test vectors of type FpeListTest are intended for format preserving encryption."
   * ],
   * "notes" : { ... },
   * "schema" : "fpe_list_test_schema.json",
   *  "testGroups" : [
   * {
   *   "keySize" : 128,
   *   "msgSize" : 0,
   *   "radix" : 85,
   *   "type" : "FpeListTest",
   *   "tests" : [
   *     {
   *       "tcId" : 1,
   *       "comment" : "Invalid message size",
   *       "flags" : [
   *         "InvalidMessageSize"
   *       ],
   *       "key" : "fb9fc869af3e4828da6efa18b5fa71a0",
   *       "tweak" : "379f81cab6ed2517",
   *       "msg" : [],
   *       "ct" : [],
   *       "result" : "invalid"
   *     }
   *   ]
   * },
   * </pre>
   */
  public void testFpe(String filename) throws Exception {
    // Testing with old test vectors may a reason for a test failure.
    // Version number have the format major.minor[status].
    // Versions before 1.0 are experimental and  use formats that are expected to change.
    // Versions after 1.0 change the major number if the format changes and change
    // the minor number if only the test vectors (but not the format) changes.
    // Versions meant for distribution have no status.
    JsonObject test = JsonUtil.getTestVectorsV1(filename);
    String algorithm = test.get("algorithm").getAsString();
    Cipher cipher;
    try {
      cipher = getCipher(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest(algorithm + " not implemented");
      return;
    }

    int errors = 0;
    int validEncryptions = 0;
    int validDecryptions = 0;
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      int radix = group.get("radix").getAsInt();
      if (radix > 256) {
        continue;
      }
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        int tcid = testcase.get("tcId").getAsInt();
        String comment = testcase.get("comment").getAsString();
        String tc = "tcId: " + tcid + " " + comment;
        byte[] key = getBytes(testcase, "key");
        byte[] tweak = getBytes(testcase, "tweak");
        byte[] msg = getMessage(testcase, "msg", radix);
        byte[] ct = getMessage(testcase, "ct", radix);
        if (msg == null || ct == null) {
          continue;
        }
        String result = testcase.get("result").getAsString();
        // Test encryption
        byte[] encrypted;
        try {
          encrypted = encrypt(cipher, key, tweak, msg, radix);
          boolean eq = Arrays.equals(ct, encrypted);
          if (result.equals("invalid")) {
            if (eq) {
              // Some test vectors use invalid parameters that should be rejected.
              // E.g. an implementation must never encrypt using AES-GCM with an IV of length 0,
              // since this leaks the authentication key.
              System.out.println("Encryted " + tc);
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
            } else {
              validEncryptions++;
            }
          }

          // BouncyCastle throws IllegalArgumentException when IVs are 0 bytes.
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
          // Encryption can fail for a number of reasons:
          // <ul>
          // <li>There is no support for generating an instance of AlgorithmParameterSpec.
          //     This typically result in a NoSuchAlgorithmException. </li>
          // <li>Implementations of Fpe often restrict the input sizes. Lower limits for
          //    the message sizes differ between versions of the NIST standard. Upper limits
          //    may depend on the integer types used in the implementation.</li>
          // <li>The radix is not supported.</li>
          // </ul>
          // Because of these limits tests will not fail if an implementation does not encrypt
          // some message. However, if a message is encrypted then the test expects that the
          // ciphertext can be decrypted.
          continue;
        }
        // Test decryption
        try {
          byte[] decrypted = decrypt(cipher, key, tweak, ct, radix);
          boolean eq = Arrays.equals(decrypted, msg);
          if (result.equals("invalid")) {
            System.out.println("Decrypted invalid ciphertext " + tc + " eq:" + eq);
            errors++;
          } else {
            if (!eq) {
              System.out.println(
                  "Incorrect decryption " + tc + " decrypted:" + TestUtil.bytesToHex(decrypted));
            } else {
              validDecryptions++;
            }
          }
          // BouncyCastle throws IllegalArgumentException when the IV is of size 0.
          // Unfortunately, CryptoException is not a subclass of GeneralSecurityException.
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
          System.out.println("Failed to decrypt " + tc);
          errors++;
        }
      }
    }
    if (errors == 0 && validEncryptions == 0 && validDecryptions == 0) {
      TestUtil.skipTest("No messages encrypted or decrypted");
      return;
    }
    System.out.println(
        filename
            + " validEncryptions:"
            + validEncryptions
            + " validDecryptions:"
            + validDecryptions);
    assertEquals(0, errors);
  }

  @Test
  public void testAesFf1Radix10() throws Exception {
    testFpe("aes_ff1_radix10_test.json");
  }

  @Test
  public void testAesFf1Radix16() throws Exception {
    testFpe("aes_ff1_radix16_test.json");
  }

  @Test
  public void testAesFf1Radix26() throws Exception {
    testFpe("aes_ff1_radix26_test.json");
  }

  @Test
  public void testAesFf1Radix32() throws Exception {
    testFpe("aes_ff1_radix32_test.json");
  }

  @Test
  public void testAesFf1Radix36() throws Exception {
    testFpe("aes_ff1_radix36_test.json");
  }

  @Test
  public void testAesFf1Radix45() throws Exception {
    testFpe("aes_ff1_radix45_test.json");
  }

  @Test
  public void testAesFf1Radix62() throws Exception {
    testFpe("aes_ff1_radix62_test.json");
  }

  @Test
  public void testAesFf1Radix64() throws Exception {
    testFpe("aes_ff1_radix64_test.json");
  }

  @Test
  public void testAesFf1Radix85() throws Exception {
    testFpe("aes_ff1_radix85_test.json");
  }

  @Test
  public void testAesFf1Radix255() throws Exception {
    testFpe("aes_ff1_radix255_test.json");
  }

  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/257491344"})
  @Test
  public void testAesFf1Radix256() throws Exception {
    testFpe("aes_ff1_radix256_test.json");
  }
}
