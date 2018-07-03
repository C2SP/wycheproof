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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** 
 * CipherInputStream tests
 *
 * <p>CipherInputStream is a class that is basically unsuitable for authenticated encryption
 * and hence should be avoided whenever possible. The class is unsuitable, because the interface
 * does not provide a method to tell the caller when decryption failed. I.e. the specification
 * now explicitly claims that it catches exceptions thrown by the Cipher class such as
 * BadPaddingException and that it does not rethrow them.
 * http://www.oracle.com/technetwork/java/javase/8u171-relnotes-4308888.html
 *
 * <p>The Jdk implementation still has the property that no unauthenticated plaintext is released.
 * In the case of an authentication failure the implementation simply returns an empty plaintext.
 * This allows a trivial attack where the attacker substitutes any message with an empty message. 
 *
 * <p>The tests in this class have been adapted to this unfortunate situation. testEmptyPlaintext 
 * checks whether corrupting the tag of an empty message is detected. This test currently fails.
 * All other tests run under the assumption that returning an empty plaintext is acceptable
 * behaviour, so that the tests are able to catch additional problems.
 */
@RunWith(JUnit4.class)
public class CipherInputStreamTest {
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
  public static class TestVector {
    public String algorithm;
    public SecretKeySpec key;
    public AlgorithmParameterSpec params;
    public byte[] pt;
    public byte[] aad;
    public byte[] ct;

    @SuppressWarnings("InsecureCryptoUsage")
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
      InputStream is = new ByteArrayInputStream(t.pt);
      CipherInputStream cis = new CipherInputStream(is, cipher);
      byte[] result = new byte[t.ct.length];
      int totalLength = 0;
      int length = 0;
      do {
        length = cis.read(result, totalLength, result.length - totalLength);
        if (length > 0) {
          totalLength += length;
        }
      } while (length >= 0 && totalLength != result.length);
      assertEquals(-1, cis.read());
      assertEquals(TestUtil.bytesToHex(t.ct), TestUtil.bytesToHex(result));
      cis.close();
    }
  }

  /** JDK-8016249: CipherInputStream in decrypt mode fails on close with AEAD ciphers */
  @SuppressWarnings("InsecureCryptoUsage")
  public void testDecrypt(Iterable<TestVector> tests) throws Exception {
    for (TestVector t : tests) {
      Cipher cipher = Cipher.getInstance(t.algorithm);
      cipher.init(Cipher.DECRYPT_MODE, t.key, t.params);
      cipher.updateAAD(t.aad);
      InputStream is = new ByteArrayInputStream(t.ct);
      CipherInputStream cis = new CipherInputStream(is, cipher);
      byte[] result = new byte[t.pt.length];
      int totalLength = 0;
      int length = 0;
      do {
        length = cis.read(result, totalLength, result.length - totalLength);
        if (length > 0) {
          totalLength += length;
        }
      } while (length >= 0 && totalLength != result.length);
      assertEquals(-1, cis.read());
      cis.close();
      assertEquals(TestUtil.bytesToHex(t.pt), TestUtil.bytesToHex(result));
    }
  }

  /**
   * JDK-8016171 : CipherInputStream masks ciphertext tampering with AEAD ciphers in decrypt mode
   * Further description of the bug is here:
   * https://blog.heckel.xyz/2014/03/01/cipherinputstream-for-aead-modes-is-broken-in-jdk7-gcm/
   * BouncyCastle claims that this bug is fixed in version 1.51. However, the test below still fails
   * with BouncyCastle v 1.52. A possible explanation is that BouncyCastle has its own
   * implemenatation of CipherInputStream (org.bouncycastle.crypto.io.CipherInputStream).
   *
   * @param tests an iterable with valid test vectors, that will be corrupted for the test
   * @param acceptEmptyPlaintext determines whether an empty plaintext instead of an exception
   *     is acceptable.
   */
  @SuppressWarnings("InsecureCryptoUsage")
  public void testCorruptDecrypt(Iterable<TestVector> tests, boolean acceptEmptyPlaintext)
      throws Exception {
    for (TestVector t : tests) {
      Cipher cipher = Cipher.getInstance(t.algorithm);
      cipher.init(Cipher.DECRYPT_MODE, t.key, t.params);
      cipher.updateAAD(t.aad);
      byte[] ct = Arrays.copyOf(t.ct, t.ct.length);
      ct[ct.length - 1] ^= (byte) 1;
      InputStream is = new ByteArrayInputStream(ct);
      CipherInputStream cis = new CipherInputStream(is, cipher);
      try {
        byte[] result = new byte[t.pt.length];
        int totalLength = 0;
        int length = 0;
        do {
          length = cis.read(result, totalLength, result.length - totalLength);
          if (length > 0) {
            totalLength += length;
          }
        } while (length >= 0 && totalLength != result.length);
        cis.close();
        if (result.length > 0) {
          fail(
              "this should fail; decrypted:"
                  + TestUtil.bytesToHex(result)
                  + " pt: "
                  + TestUtil.bytesToHex(t.pt));
        } else if (result.length == 0 && !acceptEmptyPlaintext) {
          fail("Corrupted ciphertext returns empty plaintext");
        }
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
    final int[] ptSizes = {0, 8, 16, 65, 8100};
    final int[] aadSizes = {0, 8, 24};
    Iterable<TestVector> v =
        getTestVectors("AES/GCM/NoPadding", keySizes, ivSizes, tagSizes, ptSizes, aadSizes);
    testEncrypt(v);
    testDecrypt(v);
  }

  @Test
  public void testCorruptAesGcm() throws Exception {
    final int[] keySizes = {16, 32};
    final int[] ivSizes = {12};
    final int[] tagSizes = {12, 16};
    final int[] ptSizes = {8, 16, 65, 8100};
    final int[] aadSizes = {0, 8, 24};
    Iterable<TestVector> v =
        getTestVectors("AES/GCM/NoPadding", keySizes, ivSizes, tagSizes, ptSizes, aadSizes);
    boolean acceptEmptyPlaintext = true;
    testCorruptDecrypt(v, acceptEmptyPlaintext);
  }

  /**
   * Tests the behaviour for corrupt plaintext more strictly than in the tests above.
   * This test does not accept that an implementation returns an empty plaintext when the
   * ciphertext has been corrupted.
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
    boolean acceptEmptyPlaintext = false;
    testCorruptDecrypt(v, acceptEmptyPlaintext);
  }

  /** Tests CipherOutputStream with AES-EAX if this algorithm is supported by the provider. */
  @Test
  public void testAesEax() throws Exception {
    final String algorithm = "AES/EAX/NoPadding";
    final int[] keySizes = {16, 32};
    final int[] ivSizes = {12, 16};
    final int[] tagSizes = {12, 16};
    final int[] ptSizes = {0, 8, 16, 65, 8100};
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
    boolean acceptEmptyPlaintext = true;
    testCorruptDecrypt(v, acceptEmptyPlaintext);
  }
}
