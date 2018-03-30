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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** CipherOutputStream tests */
@RunWith(JUnit4.class)
public class CipherOutputStreamTest {
  static final SecureRandom rand = new SecureRandom();

  static byte[] randomBytes(int size) {
    byte[] bytes = new byte[size];
    rand.nextBytes(bytes);
    return bytes;
  }

  static SecretKeySpec randomKey(String algorithm, int keySizeInBytes) {
    return new SecretKeySpec(randomBytes(keySizeInBytes), "AES");
  }

  static AlgorithmParameterSpec randomParameters(
      String algorithm, int ivSizeInBytes, int tagSizeInBytes) {
    if ("AES/GCM/NoPadding".equals(algorithm) || "AES/EAX/NoPadding".equals(algorithm)) {
      return new GCMParameterSpec(8 * tagSizeInBytes, randomBytes(ivSizeInBytes));
    }
    return null;
  }

  /** Test vectors */
  @SuppressWarnings("InsecureCryptoUsage")
  public static class TestVector {
    public String algorithm;
    public SecretKeySpec key;
    public AlgorithmParameterSpec params;
    public byte[] pt;
    public byte[] aad;
    public byte[] ct;

    public TestVector(
        String algorithm, int keySize, int ivSize, int tagSize, int ptSize, int aadSize)
        throws Exception {
      this.algorithm = algorithm;
      this.key = randomKey(algorithm, keySize);
      this.params = randomParameters(algorithm, ivSize, tagSize);
      this.pt = randomBytes(ptSize);
      this.aad = randomBytes(aadSize);
      Cipher cipher = Cipher.getInstance(algorithm);
      cipher.init(Cipher.ENCRYPT_MODE, this.key, this.params);
      cipher.updateAAD(aad);
      this.ct = cipher.doFinal(pt);
    }
  }

  Iterable<TestVector> getTestVectors(
      String algorithm,
      int[] keySizes,
      int[] ivSizes,
      int[] tagSizes,
      int[] ptSizes,
      int[] aadSizes)
      throws Exception {
    ArrayList<TestVector> result = new ArrayList<TestVector>();
    for (int keySize : keySizes) {
      for (int ivSize : ivSizes) {
        for (int tagSize : tagSizes) {
          for (int ptSize : ptSizes) {
            for (int aadSize : aadSizes) {
              result.add(new TestVector(algorithm, keySize, ivSize, tagSize, ptSize, aadSize));
            }
          }
        }
      }
    }
    return result;
  }

  @SuppressWarnings("InsecureCryptoUsage")
  public void testEncrypt(Iterable<TestVector> tests) throws Exception {
    for (TestVector t : tests) {
      Cipher cipher = Cipher.getInstance(t.algorithm);
      cipher.init(Cipher.ENCRYPT_MODE, t.key, t.params);
      cipher.updateAAD(t.aad);
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      CipherOutputStream cos = new CipherOutputStream(os, cipher);
      cos.write(t.pt);
      cos.close();
      assertEquals(TestUtil.bytesToHex(t.ct), TestUtil.bytesToHex(os.toByteArray()));
    }
  }

  @SuppressWarnings("InsecureCryptoUsage")
  public void testDecrypt(Iterable<TestVector> tests) throws Exception {
    for (TestVector t : tests) {
      Cipher cipher = Cipher.getInstance(t.algorithm);
      cipher.init(Cipher.DECRYPT_MODE, t.key, t.params);
      cipher.updateAAD(t.aad);
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      CipherOutputStream cos = new CipherOutputStream(os, cipher);
      cos.write(t.ct);
      cos.close();
      assertEquals(TestUtil.bytesToHex(t.pt), TestUtil.bytesToHex(os.toByteArray()));
    }
  }

  @SuppressWarnings("InsecureCryptoUsage")
  public void testCorruptDecrypt(Iterable<TestVector> tests) throws Exception {
    for (TestVector t : tests) {
      Cipher cipher = Cipher.getInstance(t.algorithm);
      cipher.init(Cipher.DECRYPT_MODE, t.key, t.params);
      cipher.updateAAD(t.aad);
      byte[] ct = Arrays.copyOf(t.ct, t.ct.length);
      ct[ct.length - 1] ^= (byte) 1;
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      CipherOutputStream cos = new CipherOutputStream(os, cipher);
      cos.write(ct);
      try {
        // cos.close() should call cipher.doFinal().
        cos.close();
        byte[] decrypted = os.toByteArray();
        // Unfortunately Oracle thinks that returning an empty array is valid behaviour.
        // We accept empty results here, but flag them in the next test, so that we can distinguish
        // between beheviour considered acceptable by Oracle and more serious flaws.
        if (decrypted.length > 0) {
          fail(
              "this should fail; decrypted:"
                  + TestUtil.bytesToHex(decrypted)
                  + " pt: "
                  + TestUtil.bytesToHex(t.pt));
        }
      } catch (IOException ex) {
        // expected
      }
    }
  }

  @SuppressWarnings("InsecureCryptoUsage")
  public void testCorruptDecryptEmpty(Iterable<TestVector> tests) throws Exception {
    for (TestVector t : tests) {
      Cipher cipher = Cipher.getInstance(t.algorithm);
      cipher.init(Cipher.DECRYPT_MODE, t.key, t.params);
      cipher.updateAAD(t.aad);
      byte[] ct = Arrays.copyOf(t.ct, t.ct.length);
      ct[ct.length - 1] ^= (byte) 1;
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      CipherOutputStream cos = new CipherOutputStream(os, cipher);
      cos.write(ct);
      try {
        // cos.close() should call cipher.doFinal().
        cos.close();
        byte[] decrypted = os.toByteArray();
        fail(
            "this should fail; decrypted:"
                + TestUtil.bytesToHex(decrypted)
                + " pt: "
                + TestUtil.bytesToHex(t.pt));
      } catch (IOException ex) {
        // expected
      }
    }
  }

  @Test
  public void testAesGcm() throws Exception {
    final int[] keySizes = {16, 32};
    final int[] ivSizes = {12};
    final int[] tagSizes = {12, 16};
    final int[] ptSizes = {8, 16, 65, 8100};
    final int[] aadSizes = {0, 8, 24};
    Iterable<TestVector> v =
        getTestVectors("AES/GCM/NoPadding", keySizes, ivSizes, tagSizes, ptSizes, aadSizes);
    testEncrypt(v);
    testDecrypt(v);
    testCorruptDecrypt(v);
  }

  /**
   * Unfortunately Oracle thinks that returning an empty array is valid behaviour for corrupt
   * ciphertexts. Because of this we test empty plaintext separately to distinguish behaviour
   * considered acceptable by Oracle from other behaviour.
   */
  @Test
  public void testEmptyPlaintext() throws Exception {
    final int[] keySizes = {16, 32};
    final int[] ivSizes = {12};
    final int[] tagSizes = {12, 16};
    final int[] ptSizes = {0};
    final int[] aadSizes = {0, 8, 24};
    Iterable<TestVector> v =
        getTestVectors("AES/GCM/NoPadding", keySizes, ivSizes, tagSizes, ptSizes, aadSizes);
    testEncrypt(v);
    testDecrypt(v);
    testCorruptDecryptEmpty(v);
  }

  /** Tests CipherOutputStream with AES-EAX if AES-EAS is supported by the provider. */
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testAesEax() throws Exception {
    final String algorithm = "AES/EAX/NoPadding";
    final int[] keySizes = {16, 32};
    final int[] ivSizes = {12, 16};
    final int[] tagSizes = {12, 16};
    final int[] ptSizes = {8, 16, 65, 8100};
    final int[] aadSizes = {0, 8, 24};
    try {
      Cipher.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("Skipping testAesEax");
      return;
    }
    Iterable<TestVector> v =
        getTestVectors(algorithm, keySizes, ivSizes, tagSizes, ptSizes, aadSizes);
    testEncrypt(v);
    testDecrypt(v);
    testCorruptDecrypt(v);
  }
}
