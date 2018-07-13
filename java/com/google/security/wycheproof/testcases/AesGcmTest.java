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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import com.google.security.wycheproof.WycheproofRunner.ExcludedTest;
import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import com.google.security.wycheproof.WycheproofRunner.SlowTest;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
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
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

// TODO(bleichen):
//   - For EAX I was able to derive some special cases by inverting OMAC.
//     Not sure if that is possible here.
/**
 * Testing AES-GCM
 *
 * <p>Other tests using AES-GCM are: CipherInputStreamTest.java CipherOuputStreamTest.java
 */
@RunWith(JUnit4.class)
public class AesGcmTest {

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
    // GCM uses GHASH to compute the initial counter J0 if the nonce is not 12 bytes long.
    // The counter is incremented modulo 2^32 in counter mode. The following test vectors verify
    // the behavior of an implementation for initial counter values J0 close to a 2^32 limit.
    // J0:00000000000000000000000000000000
    new GcmTestVector(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00112233445566778899aabbccddeeff",
        "7b95b8c356810a84711d68150a1b7750",
        "",
        "84d4c9c08b4f482861e3a9c6c35bc4d91df927374513bfd49f436bd73f325285daef4ff7e13d46a6",
        "213a3cb93855d18e69337eee66aeec07"),
    // J0:ffffffffffffffffffffffffffffffff
    new GcmTestVector(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00112233445566778899aabbccddeeff",
        "1a552e67cdc4dc1a33b824874ebf0bed",
        "",
        "948ca37a8e6649e88aeffb1c598f3607007702417ea0e0bc3c60ad5a949886de968cf53ea6462aed",
        "99b381bfa2af9751c39d1b6e86d1be6a"),
    // J0:000102030405060708090a0bffffffff
    new GcmTestVector(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00112233445566778899aabbccddeeff",
        "99821c2dd5daecded07300f577f7aff1",
        "",
        "127af9b39ecdfc57bb11a2847c7c2d3d8f938f40f877e0c4af37d0fe9af033052bd537c4ae978f60",
        "07eb2fe4a958f8434d40684899507c7c"),
    // J0:000102030405060708090a0bfffffffe
    new GcmTestVector(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00112233445566778899aabbccddeeff",
        "5e4a3900142358d1c774d8d124d8d27d",
        "",
        "0cf6ae47156b14dce03c8a07a2e172b1127af9b39ecdfc57bb11a2847c7c2d3d8f938f40f877e0c4",
        "f145c2dcaf339eede427be934357eac0"),
  };

  /**
   * Returns the GCM test vectors supported by the current provider. This is necessary since not
   * every provider supports all parameters sizes. For example SUNJCE does not support 8 byte tags
   * and Conscrypt only supports 12 byte nonces. Such restrictions are often made because AES-GCM is
   * a relatively weak algorithm and especially small parameter sizes can lead to easy attacks.
   * Avoiding such small parameter sizes should not be seen as a bug in the library.
   *
   * <p>The only assumption we make here is that all test vectors with 128 bit tags and nonces with
   * at least 96 bits are supported.
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

  @Test
  public void testVectors() throws Exception {
    for (GcmTestVector test : getTestVectors()) {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, test.key, test.parameters);
      cipher.updateAAD(test.aad);
      byte[] ct = cipher.doFinal(test.pt);
      assertEquals(test.ctHex, TestUtil.bytesToHex(ct));
    }
  }

  /** Test encryption when update and doFinal are done with empty byte arrays. */
  @Test
  public void testEncryptWithEmptyArrays() throws Exception {
    for (GcmTestVector test : getTestVectors()) {
      // Encryption
      byte[] empty = new byte[0];
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, test.key, test.parameters);
      int outputSize = cipher.getOutputSize(test.pt.length);
      ByteBuffer ctBuffer = ByteBuffer.allocate(outputSize);
      cipher.updateAAD(empty);
      cipher.updateAAD(test.aad);
      byte[] res = cipher.update(empty);
      if (res != null) {
        ctBuffer.put(res);
      }
      res = cipher.update(test.pt);
      if (res != null) {
        ctBuffer.put(res);
      }
      res = cipher.doFinal(empty);
      if (res != null) {
        ctBuffer.put(res);
      }
      assertEquals(test.ctHex, TestUtil.byteBufferToHex(ctBuffer));
    }
  }

  @Test
  public void testDecryptWithEmptyArrays() throws Exception {
    for (GcmTestVector test : getTestVectors()) {
      byte[] empty = new byte[0];
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, test.key, test.parameters);
      int outputSize = cipher.getOutputSize(test.ct.length);
      ByteBuffer ptBuffer = ByteBuffer.allocate(outputSize);
      cipher.updateAAD(empty);
      cipher.updateAAD(test.aad);
      byte[] res = cipher.update(empty);
      if (res != null) {
        ptBuffer.put(res);
      }
      res = cipher.update(test.ct);
      if (res != null) {
        ptBuffer.put(res);
      }
      res = cipher.doFinal(empty);
      if (res != null) {
        ptBuffer.put(res);
      }
      assertEquals(test.ptHex, TestUtil.byteBufferToHex(ptBuffer));

      // Simple test that a modified ciphertext fails.
      ptBuffer.clear();
      cipher.init(Cipher.DECRYPT_MODE, test.key, test.parameters);
      cipher.updateAAD(empty);
      cipher.updateAAD(test.aad);
      cipher.updateAAD(new byte[1]);
      res = cipher.update(empty);
      if (res != null) {
        ptBuffer.put(res);
      }
      res = cipher.update(test.ct);
      if (res != null) {
        ptBuffer.put(res);
      }
      try {
        cipher.doFinal(empty);
        fail("Accepted modified ciphertext.");
      } catch (GeneralSecurityException ex) {
        // Expected
      }
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
  @Test
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
   * previous IV. This "feature" can easily break AES-GCM usages, because encrypting twice with the
   * same key and IV leaks the authentication key. Hence any reasonable implementation of AES-GCM
   * should not allow this. The expected behaviour of OpenJDK can be derived from the tests in
   * jdk/test/com/sun/crypto/provider/Cipher/AES/TestGCMKeyAndIvCheck.java. OpenJDK does not allow
   * two consecutive initializations for encryption with the same key and IV.
   *
   * <p>The test here is weaker than the restrictions in OpenJDK. The only requirement here is that
   * reusing a Cipher without an explicit init() is caught.
   *
   * <p>BouncyCastle 1.52 failed this test
   *
   * <p>Conscrypt failed this test
   */
  @Test
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

  /**
   * Checks whether the implementation requires larger ByteBuffers than necessary. This test has
   * been added mostly for debugging. E.g., conscrypt failed during decryption with ByteBuffers
   * simply because the necessary outputSize was computed incorrectly.
   */
  @Test
  public void testByteBufferSize() throws Exception {
    for (GcmTestVector test : getTestVectors()) {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      // Encryption
      cipher.init(Cipher.ENCRYPT_MODE, test.key, test.parameters);
      int outputSize = cipher.getOutputSize(test.pt.length);
      assertEquals("plaintext size:" + test.pt.length, test.ct.length, outputSize);
      // Decryption
      cipher.init(Cipher.DECRYPT_MODE, test.key, test.parameters);
      outputSize = cipher.getOutputSize(test.ct.length);
      assertEquals("ciphertext size:" + test.ct.length, test.pt.length, outputSize);
    }
  }

  /** Encryption with ByteBuffers. */
  @Test
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
  @Test
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

  /** Encryption and decryption with large arrays should be copy-safe. */
  @NoPresubmitTest(
    providers = {ProviderType.BOUNCY_CASTLE},
    bugs = {"b/64378943"}
  )
  @Test
  public void testLargeArrayAlias() throws Exception {
    byte[] ptVector = new byte[8192];

    // this offset is relative to the start of the input, not the start of the buffer.
    for (int outputOffset = -32; outputOffset <= 32; outputOffset++) {
      // try with doFinal directly as well as with update followed by doFinal
      for (int useUpdate = 0; useUpdate <= 1; useUpdate++) {
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec parameters = new GCMParameterSpec(128, new byte[12]);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameters);

        // these offsets are relative to the start of the buffer
        int inputOffsetInBuffer = 32;
        int outputOffsetInBuffer = inputOffsetInBuffer + outputOffset;
        int sliceLength = cipher.getOutputSize(ptVector.length);

        byte[] inBuf = new byte[sliceLength + Math.max(inputOffsetInBuffer, outputOffsetInBuffer)];
        byte[] outBuf = inBuf;

        System.arraycopy(ptVector, 0, inBuf, inputOffsetInBuffer, ptVector.length);

        try {
          int ctLength = 0;
          if (useUpdate > 0) {
            ctLength +=
                cipher.update(
                    inBuf, inputOffsetInBuffer, ptVector.length, outBuf, outputOffsetInBuffer);
            ctLength += cipher.doFinal(inBuf, 0, 0, outBuf, outputOffsetInBuffer + ctLength);
          } else {
            ctLength +=
                cipher.doFinal(
                    inBuf, inputOffsetInBuffer, ptVector.length, outBuf, outputOffsetInBuffer);
          }

          System.arraycopy(outBuf, outputOffsetInBuffer, inBuf, inputOffsetInBuffer, ctLength);

          cipher = Cipher.getInstance("AES/GCM/NoPadding");
          cipher.init(Cipher.DECRYPT_MODE, key, parameters);

          int resultPtLength = 0;
          if (useUpdate > 0) {
            resultPtLength +=
                cipher.update(inBuf, inputOffsetInBuffer, ctLength, outBuf, outputOffsetInBuffer);
            resultPtLength +=
                cipher.doFinal(inBuf, 0, 0, outBuf, outputOffsetInBuffer + resultPtLength);
          } else {
            resultPtLength +=
                cipher.doFinal(inBuf, inputOffsetInBuffer, ctLength, outBuf, outputOffsetInBuffer);
          }

          assertEquals(resultPtLength, ptVector.length);
          assertArrayEquals(
              ptVector,
              Arrays.copyOfRange(
                  outBuf, outputOffsetInBuffer, outputOffsetInBuffer + resultPtLength));
        } catch (Throwable t) {
          throw new AssertionError(
              "testLargeByteBufferAlias failed with outputOffset=" + outputOffset, t);
        }
      }
    }
  }

  /**
   * Encryption with ByteBuffers should be copy-safe even if the buffers have different starting
   * offsets and/or do not make the backing array visible.
   *
   * <p>Note that bugs in this often require a sizeable input to reproduce; the default
   * implementation of engineUpdate(ByteBuffer, ByteBuffer) copies through 4KB bounce buffers, so we
   * need to use something larger to see any problems - 8KB is what we use here.
   *
   * @see https://bugs.openjdk.java.net/browse/JDK-8181386
   */
  @NoPresubmitTest(
    providers = {ProviderType.BOUNCY_CASTLE, ProviderType.OPENJDK},
    bugs = {"b/64378943"}
  )
  @Test
  public void testByteBufferShiftedAlias() throws Exception {
    byte[] ptVector = new byte[8192];

    for (int i = 0; i < 3; i++) {
      // outputOffset = offset relative to start of input.
      for (int outputOffset = -1; outputOffset <= 1; outputOffset++) {

        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec parameters = new GCMParameterSpec(128, new byte[12]);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameters);

        ByteBuffer output, input, inputRO;

        // We'll try three scenarios: Ordinary array backed buffers, array backed buffers where one
        // is read-only, and direct byte buffers.
        String mode;
        // offsets relative to start of buffer
        int inputOffsetInBuffer = 1;
        int outputOffsetInBuffer = inputOffsetInBuffer + outputOffset;
        int sliceLength = cipher.getOutputSize(ptVector.length);
        int bufferSize = sliceLength + Math.max(inputOffsetInBuffer, outputOffsetInBuffer);
        switch (i) {
          case 0:
          case 1:
            {
              byte[] buffer = new byte[bufferSize];
              // It's important to slice() here as otherwise later when we flip() position will be
              // reset to 0.
              output = ByteBuffer.wrap(buffer, outputOffsetInBuffer, sliceLength).slice();
              input = ByteBuffer.wrap(buffer, inputOffsetInBuffer, sliceLength).slice();

              if (i == 1) {
                mode = "array backed buffers with RO buffer";
                inputRO = input.asReadOnlyBuffer();
              } else {
                mode = "array backed buffers";
                inputRO = input.duplicate();
              }

              break;
            }
          case 2:
            {
              mode = "direct buffers";
              ByteBuffer buf = ByteBuffer.allocateDirect(bufferSize);
              output = buf.duplicate();
              output.position(outputOffsetInBuffer);
              output.limit(sliceLength + outputOffsetInBuffer);
              output = output.slice();

              input = buf.duplicate();
              input.position(inputOffsetInBuffer);
              input.limit(sliceLength + inputOffsetInBuffer);
              input = input.slice();

              inputRO = input.duplicate();
              break;
            }
          default:
            {
              throw new AssertionError("Unknown test index " + i);
            }
        }

        // Now that we have our overlapping 'input' and 'output' buffers, we can write our plaintext
        // into the input buffer.
        input.put(ptVector);
        input.flip();
        // Make sure the RO input buffer has the same limit in case the plaintext is shorter than
        // sliceLength (which it generally will be for anything other than ECB or CTR mode)
        inputRO.limit(input.limit());

        try {
          int ctSize = cipher.doFinal(inputRO, output);

          // Now flip the buffers around and undo everything
          byte[] tmp = new byte[ctSize];
          output.flip();
          output.get(tmp);

          output.clear();
          input.clear();
          inputRO.clear();

          input.put(tmp);
          input.flip();
          inputRO.limit(input.limit());

          cipher.init(Cipher.DECRYPT_MODE, key, parameters);
          cipher.doFinal(inputRO, output);

          output.flip();
          assertEquals(ByteBuffer.wrap(ptVector), output);
        } catch (Throwable t) {
          throw new AssertionError(
              "Overlapping buffers test failed with buffer type: "
                  + mode
                  + " and output offset "
                  + outputOffset,
              t);
        }
      }
    }
  }

  @Test
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
  @Test
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

  @Test
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
   * Test encryption when update and doFinal are done with empty ByteBuffers. Conscrypt ignored
   * calls to doFinal() when the ByteBuffer was empty.
   */
  @Test
  public void testEncryptWithEmptyByteBuffer() throws Exception {
    for (GcmTestVector test : getTestVectors()) {
      // Encryption
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      ByteBuffer empty = ByteBuffer.allocate(0);
      ByteBuffer ptBuffer = ByteBuffer.wrap(test.pt);
      cipher.init(Cipher.ENCRYPT_MODE, test.key, test.parameters);
      int outputSize = cipher.getOutputSize(test.pt.length);
      ByteBuffer ctBuffer = ByteBuffer.allocate(outputSize);
      cipher.updateAAD(empty);
      cipher.updateAAD(test.aad);
      cipher.update(empty, ctBuffer);
      cipher.update(ptBuffer, ctBuffer);
      cipher.doFinal(empty, ctBuffer);
      assertEquals(test.ctHex, TestUtil.byteBufferToHex(ctBuffer));
    }
  }

  @Test
  public void testDecryptWithEmptyBuffer() throws Exception {
    for (GcmTestVector test : getTestVectors()) {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      ByteBuffer empty = ByteBuffer.allocate(0);
      ByteBuffer ctBuffer = ByteBuffer.wrap(test.ct);
      cipher.init(Cipher.DECRYPT_MODE, test.key, test.parameters);
      int outputSize = cipher.getOutputSize(test.ct.length);
      ByteBuffer ptBuffer = ByteBuffer.allocate(outputSize);
      cipher.updateAAD(empty);
      cipher.updateAAD(test.aad);
      cipher.update(empty, ptBuffer);
      cipher.update(ctBuffer, ptBuffer);
      cipher.doFinal(empty, ptBuffer);
      assertEquals(test.ptHex, TestUtil.byteBufferToHex(ptBuffer));

      // Simple test that a modified ciphertext fails.
      ctBuffer.flip();
      ptBuffer.clear();
      cipher.init(Cipher.DECRYPT_MODE, test.key, test.parameters);
      cipher.updateAAD(empty);
      cipher.updateAAD(test.aad);
      cipher.updateAAD(new byte[1]);
      cipher.update(empty, ptBuffer);
      cipher.update(ctBuffer, ptBuffer);
      try {
        cipher.doFinal(empty, ptBuffer);
        fail("Accepted modified ciphertext.");
      } catch (GeneralSecurityException ex) {
        // Expected
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
  @Test
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
  @Test
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
  @ExcludedTest(
    providers = {ProviderType.CONSCRYPT, ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE},
    comment = "Conscrypt doesn't support streaming, would crash. BouncyCastle needs > 1h."
  )
  @SlowTest(
    providers = {
      ProviderType.BOUNCY_CASTLE,
      ProviderType.CONSCRYPT,
      ProviderType.OPENJDK,
      ProviderType.SPONGY_CASTLE
    }
  )
  @Test
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

  /**
   * AES-GCM allows IVs of bit length 1 .. 2^64-1. See NIST SP 800 38d, Section 5.2.1.1
   * http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
   *
   * <p>Disallowing IVs of length 0 is necessary for the following reason: if an empty IV is used
   * then the tag is an evaluation of a polynomial with the hash subkey as the value. Since the
   * polynomial can be derived from the ciphertext it is known to an attacker. Therefore, any
   * message encrypted with an empty IV leaks the hash subkey. In particular, encrypting an empty
   * plaintext with an empty IV results in a ciphertext having a tag that is equal to the hash
   * subkey used in AES-GCM. I.e. both are the same as encrypting an all zero block.
   *
   * <p>OpenJDK fails this test.
   */
  @NoPresubmitTest(
    providers = {ProviderType.OPENJDK},
    bugs = {"b/35746778"}
  )
  @Test
  public void testEncryptEmptyPlaintextWithEmptyIv() throws Exception {
    byte[] emptyIv = new byte[0];
    byte[] input = new byte[0];
    byte[] key = TestUtil.hexToBytes("56aae7bd5cbefc71d31c4338e6ddd6c5");
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    Cipher block = Cipher.getInstance("AES/ECB/NoPadding");
    block.init(Cipher.ENCRYPT_MODE, keySpec);
    byte[] hashkey = block.doFinal(new byte[16]);
    try {
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(16 * 8, emptyIv));
      byte[] ct = cipher.doFinal(input);
      // If the encryption above is not rejected then the hash key and the ciphertext are the same.
      // Both are d1bdd948ddc5a7f7a9250cf78229b84d.
      System.out.println("testEncryptEmptyPlaintextWithEmptyIv:");
      System.out.println("Encrypt with empty IV:" + TestUtil.bytesToHex(ct));
      System.out.println("Hash subkey          :" + TestUtil.bytesToHex(hashkey));
      fail("Encrypting with an empty IV leaks the hash subkey.");
    } catch (GeneralSecurityException expected) {
      System.out.println("testEncryptWithEmptyIv:" + expected.toString());
      // expected behavior
    }
  }

  @NoPresubmitTest(
    providers = {ProviderType.OPENJDK},
    bugs = {"b/35746778"}
  )
  @Test
  public void testDecryptWithEmptyIv() throws Exception {
    byte[] emptyIv = new byte[0];
    byte[] key = TestUtil.hexToBytes("56aae7bd5cbefc71d31c4338e6ddd6c5");
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    try {
      cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(16 * 8, emptyIv));
      String ciphertext = "2b65876c00d77facf8f3d0e5be792b129bab10b25bcb739b92d6e2eab241245ff449";
      String tag = "c2b2d7086e7fa84ca795a881b540";
      byte[] pt1 = cipher.update(TestUtil.hexToBytes(ciphertext));
      byte[] pt2 = cipher.doFinal(TestUtil.hexToBytes(tag));
      // We shouldn't get here. If a provider releases unverified plaintext additionally to
      // accepting empty IVs then chosen ciphertext attacks might be possible.
      System.out.println("testDecryptWithEmptyIv:");
      System.out.println("pt1:" + TestUtil.bytesToHex(pt1));
      System.out.println("pt2:" + TestUtil.bytesToHex(pt2));
      fail("AES-GCM must not accept an IV of size 0.");
    } catch (GeneralSecurityException expected) {
      System.out.println("testDecryptWithEmptyIv:" + expected.toString());
    }
  }
}
