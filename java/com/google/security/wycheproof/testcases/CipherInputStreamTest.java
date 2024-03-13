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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * CipherInputStream tests
 *
 * <p>CipherInputStream is a class that is basically unsuitable for authenticated encryption and
 * hence should be avoided whenever possible. The class is unsuitable, because the interface does
 * not provide a method to tell the caller when decryption failed. I.e. the specification now
 * explicitly claims that it catches exceptions thrown by the Cipher class such as
 * BadPaddingException and that it does not rethrow them.
 * http://www.oracle.com/technetwork/java/javase/8u171-relnotes-4308888.html
 *
 * <p>The Jdk implementation still has the property that no unauthenticated plaintext is released.
 * In the case of an authentication failure the implementation simply returns an empty plaintext.
 * This allows a trivial attack where the attacker substitutes any message with an empty message.
 *
 * <p>The tests in this class have been adapted to this unfortunate situation. testEmptyPlaintext
 * checks whether corrupting the tag of an empty message is detected. This test currently fails. All
 * other tests run under the assumption that returning an empty plaintext is acceptable behaviour,
 * so that the tests are able to catch additional problems.
 */
@RunWith(JUnit4.class)
public class CipherInputStreamTest {

  static byte[] randomBytes(int size) {
    byte[] bytes = new byte[size];
    try {
      SecureRandom rand = new SecureRandom();
      rand.nextBytes(bytes);
    } catch (InternalError ex) {
      // This happens when SecureRandom is misconfigured.
      // E.g., when SHA1PRNG is default, but no provider supports SHA-1.
      // Such configurations can happen when providers are being tested
      // in isolation.
      TestUtil.skipTest("Could generate random bytes");
    }
    return bytes;
  }

  static SecretKeySpec randomKey(String algorithm, int keySizeInBytes) {
    return new SecretKeySpec(randomBytes(keySizeInBytes), "AES");
  }

  static AlgorithmParameterSpec randomParameters(
      String algorithm, int ivSizeInBytes, int tagSizeInBytes) throws NoSuchAlgorithmException {
    switch (algorithm) {
      case "AES/GCM/NoPadding":
      case "AES/EAX/NoPadding":
      case "AES/CCM/NoPadding":
        return new GCMParameterSpec(8 * tagSizeInBytes, randomBytes(ivSizeInBytes));
      case "AES/GCM-SIV/NoPadding":
        return new IvParameterSpec(randomBytes(ivSizeInBytes));
      default:
        throw new NoSuchAlgorithmException("Unsupported algorithm: " + algorithm);
    }
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

  Iterable<TestVector> getAesCcmTestVectors() throws Exception {
    final int[] keySizes = {16, 32};
    final int[] ivSizes = {12};
    final int[] aadSizes = {0, 8, 24};
    final int[] ptSizes = {0, 8, 16, 65, 8100};
    final int[] tagSizes = {12};
    return getTestVectors("AES/CCM/NoPadding", keySizes, ivSizes, aadSizes, ptSizes, tagSizes);
  }

  Iterable<TestVector> getAesGcmSivTestVectors() throws Exception {
    final int[] keySizes = {16, 32};
    final int[] ivSizes = {12};
    final int[] aadSizes = {0, 8, 24};
    final int[] ptSizes = {0, 8, 16, 65, 8100};
    final int[] tagSizes = {16};
    return getTestVectors("AES/GCM-SIV/NoPadding", keySizes, ivSizes, aadSizes, ptSizes, tagSizes);
  }

  @SuppressWarnings("InsecureCryptoUsage")
  public void testEncrypt(Iterable<TestVector> tests) throws Exception {
    assertNotNull(tests);
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
    assertNotNull(tests);
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
    boolean emptyPlaintext = false;
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
        // The test fails if decryption returns partial plaintext.
        if (result.length > 0) {
          fail(
              "this should fail; decrypted:"
                  + TestUtil.bytesToHex(result)
                  + " pt: "
                  + TestUtil.bytesToHex(t.pt));
        } else {
          // If decryption returns empty plaintext and acceptEmptyPlaintext == true then the test
          // will be skipped.
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
  public void testAesGcm() throws Exception {
    Iterable<TestVector> v = getAesGcmTestVectors();
    testEncrypt(v);
    testDecrypt(v);
  }

  @Test
  @NoPresubmitTest(
      providers = {ProviderType.ALL},
      bugs = {"b/261217218"})
  public void testCorruptAesGcm() throws Exception {
    testCorruptDecrypt(getAesGcmTestVectors(), /* acceptEmptyPlaintext= */ true);
  }

  /**
   * Tests the behaviour for corrupt plaintext more strictly than in the tests above. This test does
   * not accept that an implementation returns an empty plaintext when the ciphertext has been
   * corrupted.
   */
  @Test
  @NoPresubmitTest(
      providers = {ProviderType.ALL},
      bugs = {"b/261217218"})
  public void testCorruptAesGcmStrict() throws Exception {
    testCorruptDecrypt(getAesGcmTestVectors(), /* acceptEmptyPlaintext= */ false);
  }


  /** Tests CipherOutputStream with AES-EAX if this algorithm is supported by the provider. */
  @Test
  public void testAesEax() throws Exception {
    Iterable<TestVector> v = getAesEaxTestVectors();
    testEncrypt(v);
    testDecrypt(v);
  }

  /** Tests CipherOutputStream with AES-EAX if this algorithm is supported by the provider. */
  @Test
  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/261217218"})
  public void testCorruptAesEax() throws Exception {
    testCorruptDecrypt(getAesEaxTestVectors(), /* acceptEmptyPlaintext= */ true);
  }

  /**
   * Tests CipherOutputStream with AES-CCM if this algorithm is supported by the provider.
   *
   * <p>One difficulty with AES-CCM is that CCM is not online.
   */
  @Test
  public void testAesCcm() throws Exception {
    Iterable<TestVector> v = getAesCcmTestVectors();
    testEncrypt(v);
    testDecrypt(v);
    testCorruptDecrypt(v, /* acceptEmptyPlaintext= */ true);
  }

  /**
   * Tests CipherOutputStream with AES-GCM-SIV if this algorithm is supported by the provider.
   *
   * <p>AES-GCM-SIV uses the tag as the IV. Hence the algorithm is not online.
   */
  @Test
  public void testAesGcmSiv() throws Exception {
    Iterable<TestVector> v = getAesGcmSivTestVectors();
    testEncrypt(v);
    testDecrypt(v);
    testCorruptDecrypt(v, /* acceptEmptyPlaintext= */ true);
  }
}
