/**
 * @license
 * Copyright 2016 Google Inc. All rights reserved.
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

import com.google.security.wycheproof.WycheproofRunner.ExcludedTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import com.google.security.wycheproof.WycheproofRunner.SlowTest;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import junit.framework.TestCase;

// TODO(bleichen):
//   - For EAX I was able to derive some special cases by inverting OMAC.
//     Not sure if that is possible here.
/**
 * Testing AES-GCM
 *
 * <p>Other tests using AES-GCM are: CipherInputStreamTest.java CipherOuputStreamTest.java
 */
public class AesGcmTest extends TestCase {

  /** Test vectors */
  public static class GcmTestVector {
    final byte[] pt;
    final byte[] aad;
    final byte[] ct;
    final String ptHex;
    final String ctHex;
    final GCMParameterSpec parameters;
    final SecretKeySpec key;
    final int nonceLengthInBits;
    final int tagLengthInBits;

    public GcmTestVector(
        String message,
        String keyMaterial,
        String nonce,
        String aad,
        String ciphertext,
        String tag) {
      this.ptHex = message;
      this.pt = TestUtil.hexToBytes(message);
      this.aad = TestUtil.hexToBytes(aad);
      this.ct = TestUtil.hexToBytes(ciphertext + tag);
      this.ctHex = ciphertext + tag;
      this.tagLengthInBits = 4 * tag.length();
      this.nonceLengthInBits = 4 * nonce.length();
      this.parameters = new GCMParameterSpec(tagLengthInBits, TestUtil.hexToBytes(nonce));
      this.key = new SecretKeySpec(TestUtil.hexToBytes(keyMaterial), "AES");
    }
  };

  private static final GcmTestVector[] GCM_TEST_VECTORS = {
    new GcmTestVector(
        "001d0c231287c1182784554ca3a21908",
        "5b9604fe14eadba931b0ccf34843dab9",
        "028318abc1824029138141a2",
        "",
        "26073cc1d851beff176384dc9896d5ff",
        "0a3ea7a5487cb5f7d70fb6c58d038554"),
    new GcmTestVector(
        "001d0c231287c1182784554ca3a21908",
        "5b9604fe14eadba931b0ccf34843dab9",
        "921d2507fa8007b7bd067d34",
        "00112233445566778899aabbccddeeff",
        "49d8b9783e911913d87094d1f63cc765",
        "1e348ba07cca2cf04c618cb4"),
    new GcmTestVector(
        "2035af313d1346ab00154fea78322105",
        "aa023d0478dcb2b2312498293d9a9129",
        "0432bc49ac34412081288127",
        "aac39231129872a2",
        "eea945f3d0f98cc0fbab472a0cf24e87",
        "4bb9b4812519dadf9e1232016d068133"),
    new GcmTestVector(
        "2035af313d1346ab00154fea78322105",
        "aa023d0478dcb2b2312498293d9a9129",
        "0432bc49ac344120",
        "aac39231129872a2",
        "64c36bb3b732034e3a7d04efc5197785",
        "b7d0dd70b00d65b97cfd080ff4b819d1"),
    new GcmTestVector(
        "02efd2e5782312827ed5d230189a2a342b277ce048462193",
        "2034a82547276c83dd3212a813572bce",
        "3254202d854734812398127a3d134421",
        "1a0293d8f90219058902139013908190bc490890d3ff12a3",
        "64069c2d58690561f27ee199e6b479b6369eec688672bde9",
        "9b7abadd6e69c1d9ec925786534f5075"),
  };

  /**
   * Returns the GCM test vectors supported by the current provider.
   * This is necessary since not every provider supports all parameters sizes.
   * For example SUNJCE does not support 8 byte tags and Conscrypt only supports
   * 12 byte nonces.
   * Such restrictions are often made because AES-GCM is a relatively weak algorithm and
   * especially small parameter sizes can lead to easy attacks.
   * Avoiding such small parameter sizes should not be seen as a bug in the library.
   *
   * <p>The only assumption we make here is that all test vectors with 128 bit tags and nonces
   * with at least 96 bits are supported.
   */
  private Iterable<GcmTestVector> getTestVectors() throws Exception {
    ArrayList<GcmTestVector> supported = new ArrayList<GcmTestVector>();
    for (GcmTestVector test : GCM_TEST_VECTORS) {
      if (test.nonceLengthInBits != 96 || test.tagLengthInBits != 128) {
        try {
          // Checks whether the parameter size is supported.
          // It would be nice if there was a way to check this without trying to encrypt.
          Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
          cipher.init(Cipher.ENCRYPT_MODE, test.key, test.parameters);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
          // Not supported
          continue;
        }
      }
      supported.add(test);
    }
    return supported;
  }

  public void testVectors() throws Exception {
    for (GcmTestVector test : getTestVectors()) {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, test.key, test.parameters);
      cipher.updateAAD(test.aad);
      byte[] ct = cipher.doFinal(test.pt);
      assertEquals(test.ctHex, TestUtil.bytesToHex(ct));
    }
  }

  /**
   * Typically one should always call updateAAD before any call to update. This test checks what
   * happens if the order is reversed. The test expects that a correct implementation either
   * computes the tag correctly or throws an exception.
   *
   * <p>For example, OpenJdk did compute incorrect tags in this case. The bug has been fixed in
   * http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/89c06ca1e6cc
   *
   * <p>For example BouncyCastle computes correct tags if the calls are reversed, SunJCE and OpenJdk
   * now throw exceptions.
   */
  public void testLateUpdateAAD() throws Exception {
    for (GcmTestVector test : getTestVectors()) {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, test.key, test.parameters);
      byte[] c0 = cipher.update(test.pt);
      try {
        cipher.updateAAD(test.aad);
      } catch (java.lang.IllegalStateException ex) {
        // Throwing an exception is valid behaviour.
        continue;
      }
      byte[] c1 = cipher.doFinal();
      String result = TestUtil.bytesToHex(c0) + TestUtil.bytesToHex(c1);
      assertEquals(test.ctHex, result);
    }
  }

  /**
   * JCE has a dangerous feature: after a doFinal the cipher is typically reinitialized using the
   * previous IV. This "feature" can easily break AES-GCM usages, because encrypting twice with
   * the same key and IV leaks the authentication key. Hence any reasonable implementation of
   * AES-GCM should not allow this. The expected behaviour of OpenJDK can be derived from the tests
   * in jdk/test/com/sun/crypto/provider/Cipher/AES/TestGCMKeyAndIvCheck.java.
   * OpenJDK does not allow two consecutive initializations for encryption with the same key and IV.
   *
   * <p>The test here is weaker than the restrictions in OpenJDK. The only requirement here is that
   * reusing a Cipher without an explicit init() is caught.
   *
   * <p>BouncyCastle 1.52 failed this test
   *
   * <p>Conscrypt failed this test
   */
  public void testIvReuse() throws Exception {
    for (GcmTestVector test : getTestVectors()) {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, test.key, test.parameters);
      cipher.updateAAD(test.aad);
      byte[] ct1 = cipher.doFinal(test.pt);
      try {
        byte[] ct2 = cipher.doFinal(test.pt);
        fail(
            "It should not possible to reuse an IV."
                + " ct1:"
                + TestUtil.bytesToHex(ct1)
                + " ct2:"
                + TestUtil.bytesToHex(ct2));
      } catch (java.lang.IllegalStateException ex) {
        // This is expected.
      }
    }
  }

  /** Encryption with ByteBuffers. */
  public void testByteBuffer() throws Exception {
    for (GcmTestVector test : getTestVectors()) {
      // Encryption
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      ByteBuffer ptBuffer = ByteBuffer.wrap(test.pt);
      cipher.init(Cipher.ENCRYPT_MODE, test.key, test.parameters);
      int outputSize = cipher.getOutputSize(test.pt.length);
      ByteBuffer ctBuffer = ByteBuffer.allocate(outputSize);
      cipher.updateAAD(test.aad);
      cipher.doFinal(ptBuffer, ctBuffer);
      assertEquals(test.ctHex, TestUtil.byteBufferToHex(ctBuffer));

      // Decryption
      ctBuffer.flip();
      cipher.init(Cipher.DECRYPT_MODE, test.key, test.parameters);
      outputSize = cipher.getOutputSize(test.ct.length);
      ByteBuffer decrypted = ByteBuffer.allocate(outputSize);
      cipher.updateAAD(test.aad);
      cipher.doFinal(ctBuffer, decrypted);
      assertEquals(test.ptHex, TestUtil.byteBufferToHex(decrypted));
    }
  }

  /** Encryption with ByteBuffers should be copy-safe. */
  public void testByteBufferAlias() throws Exception {
    for (GcmTestVector test : getTestVectors()) {
      // Encryption
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, test.key, test.parameters);
      int outputSize = cipher.getOutputSize(test.pt.length);
      byte[] backingArray = new byte[outputSize];
      ByteBuffer ptBuffer = ByteBuffer.wrap(backingArray);
      ptBuffer.put(test.pt);
      ptBuffer.flip();
      ByteBuffer ctBuffer = ByteBuffer.wrap(backingArray);
      cipher.updateAAD(test.aad);
      cipher.doFinal(ptBuffer, ctBuffer);
      assertEquals(test.ctHex, TestUtil.byteBufferToHex(ctBuffer));

      // Decryption
      ByteBuffer decrypted = ByteBuffer.wrap(backingArray);
      ctBuffer.flip();
      cipher.init(Cipher.DECRYPT_MODE, test.key, test.parameters);
      cipher.updateAAD(test.aad);
      cipher.doFinal(ctBuffer, decrypted);
      assertEquals(test.ptHex, TestUtil.byteBufferToHex(decrypted));
    }
  }

  public void testReadOnlyByteBuffer() throws Exception {
    for (GcmTestVector test : getTestVectors()) {
      // Encryption
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      ByteBuffer ptBuffer = ByteBuffer.wrap(test.pt).asReadOnlyBuffer();
      cipher.init(Cipher.ENCRYPT_MODE, test.key, test.parameters);
      int outputSize = cipher.getOutputSize(test.pt.length);
      ByteBuffer ctBuffer = ByteBuffer.allocate(outputSize);
      cipher.updateAAD(test.aad);
      cipher.doFinal(ptBuffer, ctBuffer);
      assertEquals(test.ctHex, TestUtil.byteBufferToHex(ctBuffer));

      // Decryption
      ctBuffer.flip();
      ctBuffer = ctBuffer.asReadOnlyBuffer();
      cipher.init(Cipher.DECRYPT_MODE, test.key, test.parameters);
      outputSize = cipher.getOutputSize(test.ct.length);
      ByteBuffer decrypted = ByteBuffer.allocate(outputSize);
      cipher.updateAAD(test.aad);
      cipher.doFinal(ctBuffer, decrypted);
      assertEquals(test.ptHex, TestUtil.byteBufferToHex(decrypted));
    }
  }

  /**
   * If a ByteBuffer is backed by an array and not readonly, then it is possible to access the data
   * through the .array() method. An implementation using this possiblity must ensure that it
   * considers the offset.
   */
  public void testByteBufferWithOffset() throws Exception {
    for (GcmTestVector test : getTestVectors()) {
      // Encryption
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      ByteBuffer ptBuffer = ByteBuffer.wrap(new byte[test.pt.length + 50]);
      ptBuffer.position(5);
      ptBuffer = ptBuffer.slice();
      ptBuffer.put(test.pt);
      ptBuffer.flip();

      ByteBuffer ctBuffer = ByteBuffer.wrap(new byte[test.ct.length + 50]);
      ctBuffer.position(8);
      ctBuffer = ctBuffer.slice();
      cipher.init(Cipher.ENCRYPT_MODE, test.key, test.parameters);
      cipher.updateAAD(test.aad);
      cipher.doFinal(ptBuffer, ctBuffer);
      assertEquals(test.ctHex, TestUtil.byteBufferToHex(ctBuffer));
      ctBuffer.flip();

      // Decryption
      ByteBuffer decBuffer = ByteBuffer.wrap(new byte[test.pt.length + 50]);
      decBuffer.position(6);
      decBuffer = decBuffer.slice();
      cipher.init(Cipher.DECRYPT_MODE, test.key, test.parameters);
      cipher.updateAAD(test.aad);
      cipher.doFinal(ctBuffer, decBuffer);
      assertEquals(test.ptHex, TestUtil.byteBufferToHex(decBuffer));
    }
  }

  public void testByteBufferTooShort() throws Exception {
    for (GcmTestVector test : getTestVectors()) {
      // Encryption
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      ByteBuffer ptBuffer = ByteBuffer.wrap(test.pt);
      ByteBuffer ctBuffer = ByteBuffer.allocate(test.ct.length - 1);
      cipher.init(Cipher.ENCRYPT_MODE, test.key, test.parameters);
      cipher.updateAAD(test.aad);
      try {
        cipher.doFinal(ptBuffer, ctBuffer);
        fail("This should not work");
      } catch (ShortBufferException ex) {
        // expected
      }

      // Decryption
      ctBuffer = ByteBuffer.wrap(test.ct);
      ByteBuffer decrypted = ByteBuffer.allocate(test.pt.length - 1);
      cipher.init(Cipher.DECRYPT_MODE, test.key, test.parameters);
      cipher.updateAAD(test.aad);
      try {
        cipher.doFinal(ctBuffer, decrypted);
        fail("This should not work");
      } catch (ShortBufferException ex) {
        // expected
      }
    }
  }

  /**
   * The default authentication tag size should be 128-bit by default for the following reasons:
   * <br>
   * (1) Security: Ferguson, N., Authentication Weaknesses in GCM, Natl. Inst. Stand. Technol. [Web
   * page], http://www.csrc.nist.gov/groups/ST/toolkit/BCM/documents/comments/
   * CWC-GCM/Ferguson2.pdf, May 20, 2005. This paper points out that a n-bit tag has lower strength
   * than expected. <br>
   * (2) Compatibility: Assume an implementer tests some code using one provider than switches to
   * another provider. Such a switch should ideally not lower the security. <br>
   * Conscrypt used to have only 12-byte authentication tag (b/26186727).
   */
  public void testDefaultTagSizeIvParameterSpec() throws Exception {
    byte[] counter = new byte[12];
    byte[] input = new byte[16];
    byte[] key = new byte[16];
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    try {
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(counter));
    } catch (InvalidAlgorithmParameterException ex) {
      // OpenJDK8 does not support IvParameterSpec for GCM.
      System.out.println("testDefaultTagSizeIvParameterSpec:" + ex.toString());
      return;
    }
    byte[] output = cipher.doFinal(input);
    assertEquals(input.length + 16, output.length);
  }

  /**
   * The default authentication tag size should be 128-bit by default for the following reasons:
   * <br>
   * (1) Security: Ferguson, N., Authentication Weaknesses in GCM, Natl. Inst. Stand. Technol. [Web
   * page], http://www.csrc.nist.gov/groups/ST/toolkit/BCM/documents/comments/
   * CWC-GCM/Ferguson2.pdf, May 20, 2005. This paper points out that a n-bit tag has lower strength
   * than expected. <br>
   * (2) Compatibility: Assume an implementer tests some code using one provider than switches to
   * another provider. Such a switch should ideally not lower the security. <br>
   * BouncyCastle used to have only 12-byte authentication tag (b/26186727).
   */
  public void testDefaultTagSizeAlgorithmParameterGenerator() throws Exception {
    byte[] input = new byte[10];
    byte[] key = new byte[16];
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    try {
      AlgorithmParameterGenerator.getInstance("GCM");
    } catch (NoSuchAlgorithmException ex) {
      // Conscrypt does not support AlgorithmParameterGenerator for GCM.
      System.out.println("testDefaultTagSizeAlgorithmParameterGenerator:" + ex.toString());
      return;
    }
    AlgorithmParameters param = AlgorithmParameterGenerator.getInstance("GCM").generateParameters();
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), param);
    byte[] output = cipher.doFinal(input);
    assertEquals(input.length + 16, output.length);
  }

  /**
   * Test AES-GCM wrapped around counter bug which leaks plaintext and authentication key. Let's
   * consider 12-byte IV, counter = IV || 0^31 || 1. For each encryption block, the last 4 bytes of
   * the counter is increased by 1. After 2^32 blocks, the counter will be wrapped around causing
   * counter collision and hence, leaking plaintext and authentication key as explained below. The
   * library must make a check to make sure that the plaintext's length never exceeds 2^32 - 2
   * blocks. Note that this is different from usual IV collisions because it happens even if users
   * use different IVs. <br>
   * We have: <br>
   * J0 = IV || 0^31 || 1 <br>
   * Plaintext: P[0], P[1], P[2], .... <br>
   * Ciphertext: <br>
   * C[0] = Enc(K, (J0 + 1) % 2^32) XOR P[0] <br>
   * C[1] = Enc(K, (J0 + 2) % 2^32) XOR P[1] <br>
   * C[2] = Enc(K, (J0 + 3) % 2^32) XOR P[2] <br>
   * ... <br>
   * C[2^32 - 1] = Enc(K, J0) XOR P[2^32 - 1] <br>
   * C[2^32] = Enc(K, (J0 + 1)% 2^32) XOR P[2^32] <br>
   * It means that after 2^32 blocks, the counter is wrapped around causing counter collisions. In
   * counter mode, once the counter is collided then it's reasonable to assume that the plaintext is
   * leaked. As the ciphertext is already known to attacker, Enc(K, J0) is leaked. <br>
   * Now, as the authentication tag T is computed as GHASH(H, {}, C) XOR E(K, J0), the attacker can
   * learn GHASH(H, {}, C}. It essentially means that the attacker finds a polynomial where H is the
   * root (see Joux attack http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/Joux_comments.pdf).
   * Solving polynomial equation in GF(2^128) is enough to extract the authentication key.
   *
   * <p>BouncyCastle used to have this bug (CVE-2015-6644).
   *
   * <p>OpenJDK8 used to have this bug (http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/0c3ed12cdaf5)
   *
   * <p>The test is slow as we have to encrypt 2^32 blocks.
   */
  // TODO(quannguyen): Is there a faster way to test it?
/*
  @ExcludedTest(
    providers = {ProviderType.CONSCRYPT},
    comment = "Conscrypt doesn't support streaming, would crash")
  @SlowTest(
    providers = {ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE, ProviderType.OPENJDK})
  public void testWrappedAroundCounter() throws Exception {
    try {
      byte[] iv = new byte[12];
      byte[] input = new byte[16];
      byte[] key = new byte[16];
      (new SecureRandom()).nextBytes(key);
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(16 * 8, iv));
      byte[] output = cipher.update(input);
      for (long i = 0; i < 4294967296L + 2; i++) {
        byte[] output1 = cipher.update(input);
        assertFalse("GCM Wrapped Around Counter" + i, Arrays.equals(output, output1));
      }
      fail("Expected Exception");
    } catch (Exception expected) {
      System.out.println("testWrappedAroundcounter:" + expected.toString());
    }
  }
*/
}
