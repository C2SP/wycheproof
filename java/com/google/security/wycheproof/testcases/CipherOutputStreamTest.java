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

import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
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

/**
 * CipherOutputStream tests
 *
 * <p>CipherOutputStream is a class that is unsuitable for authenticated encryption and hence should
 * not be used. CipherOutputStream does not provide a method to tell the caller when decryption
 * failed. I.e. the specification now explicitly claims that it catches exceptions thrown by the
 * Cipher class such as BadPaddingException and that it does not rethrow them.
 * http://www.oracle.com/technetwork/java/javase/8u171-relnotes-4308888.html
 *
 * <p>The Jdk implementation has the property that no unauthenticated plaintext is released. In the
 * case of an authentication failure the implementation simply returns an empty plaintext. This
 * allows a trivial attack where the attacker substitutes any message with an empty message.
 *
 * <p>Ignoring the issue also has the consequence that changes of the underlying code can have
 * negative consequences for various providers. For example using CipherOutputStream with
 * BouncyCastle starts leaking unverified plaintext with jdk20.
 *
 * <p>Some provider add special classes to deal with this situation. For example BouncyCastle has
 * the class org.bouncycastle.crypto.io.CipherOutputStream. Uses such classes has the disadvantage
 * that code become provider dependent.
 *
 * <p>The tests in this class have been adapted to this unfortunate situation. They only pass if
 * exceptions are thrown in the case of an incorrect tag. But they can be called so that they are
 * merely skipped as long as no partial plaintext is leaked.
 */
@RunWith(JUnit4.class)
public class CipherOutputStreamTest {

  static byte[] randomBytes(int size) {
    byte[] bytes = new byte[size];
    try {
      SecureRandom rand = new SecureRandom();
      rand.nextBytes(bytes);
    } catch (java.lang.InternalError ex) {
      // This happens when SecureRandom is misconfigured.
      // E.g., when SHA1PRNG is default, but no provider supports SHA-1.
      TestUtil.skipTest("Could generate random bytes");
    }
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
        String algorithm, int keySize, int ivSize, int aadSize, int ptSize, int tagSize)
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
      int[] aadSizes,
      int[] ptSizes,
      int[] tagSizes)
      throws Exception {
    try {
      Cipher.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest(algorithm + " is not implemented");
      return null;
    }
    ArrayList<TestVector> result = new ArrayList<TestVector>();
    for (int keySize : keySizes) {
      for (int ivSize : ivSizes) {
        for (int aadSize : aadSizes) {
          for (int ptSize : ptSizes) {
            for (int tagSize : tagSizes) {
              result.add(new TestVector(algorithm, keySize, ivSize, aadSize, ptSize, tagSize));
            }
          }
        }
      }
    }
    return result;
  }

  Iterable<TestVector> getAesGcmTestVectors() throws Exception {
    final int[] keySizes = {16, 32};
    final int[] ivSizes = {12};
    final int[] aadSizes = {0, 8, 24};
    final int[] ptSizes = {0, 8, 16, 65, 8100};
    final int[] tagSizes = {12, 16};
    return getTestVectors("AES/GCM/NoPadding", keySizes, ivSizes, aadSizes, ptSizes, tagSizes);
  }

  Iterable<TestVector> getAesEaxTestVectors() throws Exception {
    final int[] keySizes = {16, 32};
    final int[] ivSizes = {12, 16};
    final int[] aadSizes = {0, 8, 24};
    final int[] ptSizes = {0, 8, 16, 65, 8100};
    final int[] tagSizes = {12, 16};
    return getTestVectors("AES/EAX/NoPadding", keySizes, ivSizes, aadSizes, ptSizes, tagSizes);
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

  /**
   * Tests decryption of corrupted ciphertext. The expected behaviour is to see an Exception.
   * Returning partial plaintext is a serious error. Unfortunately Oracle simply returns an empty
   * result (http://www.oracle.com/technetwork/java/javase/8u171-relnotes-4308888.html). Such a
   * result can be ambiguous. The main purpose of the test is to check if partial plaintext is
   * leaked in the case of an incorrect tag.
   *
   * @param tests an iterable with valid test vectors, that will be corrupted for the test
   * @param acceptEmptyPlaintext if true then an returning empty plaintext will simply skip the
   *     test, if false then the test fails.
   */
  @SuppressWarnings("InsecureCryptoUsage")
  public void testCorruptDecrypt(Iterable<TestVector> tests, boolean acceptEmptyPlaintext)
      throws Exception {
    boolean emptyPlaintext = false;
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
        // The test fails if decryption returns partial plaintext.
        if (decrypted.length > 0) {
          fail(
              "this should fail; decrypted:"
                  + TestUtil.bytesToHex(decrypted)
                  + " pt: "
                  + TestUtil.bytesToHex(t.pt));
        } else {
          // If decryption returns empty plaintext then the test will be skipped.
          emptyPlaintext = true;
        }
      } catch (IOException ex) {
        // expected
      }
    }
    if (emptyPlaintext) {
      if (acceptEmptyPlaintext) {
        TestUtil.skipTest("Decrypting corrupt ciphertext returns empty plaintext");
      } else {
        fail("Decrypting corrupt ciphertext returns empty plaintext");
      }
    }
  }

  @Test
  public void testAesGcmEncrypt() throws Exception {
    testEncrypt(getAesGcmTestVectors());
  }

  @Test
  public void testAesGcmDecrypt() throws Exception {
    testDecrypt(getAesGcmTestVectors());
  }

  @Test
  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/261217218"})
  public void testAesGcmCorruptDecrypt() throws Exception {
    testCorruptDecrypt(getAesGcmTestVectors(), /* acceptEmptyPlaintext= */ true);
  }

  @Test
  @NoPresubmitTest(
      providers = {ProviderType.ALL},
      bugs = {"b/261217218"})
  public void testAesGcmCorruptDecryptStrict() throws Exception {
    testCorruptDecrypt(getAesGcmTestVectors(), /* acceptEmptyPlaintext= */ false);
  }

  @Test
  public void testAesEaxEncrypt() throws Exception {
    testEncrypt(getAesEaxTestVectors());
  }

  @Test
  public void testAesEaxDecrypt() throws Exception {
    testDecrypt(getAesEaxTestVectors());
  }

  @Test
  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/261217218"})
  public void testAesEaxCorruptDecrypt() throws Exception {
    testCorruptDecrypt(getAesEaxTestVectors(), /* acceptEmptyPlaintext= */ true);
  }
}
