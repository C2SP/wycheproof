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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import com.google.security.wycheproof.WycheproofRunner.SlowTest;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for MACs.
 *
 * <p>TODO(bleichen): The tests are quite incomplete. Some of the missing stuff: More test vectors
 * with known results are necessary. So far only simple test vectors for long messages are
 * available.
 */
@RunWith(JUnit4.class)
public class MacTest {

  /**
   * Computes the maximum of an array with at least one element.
   *
   * @param values the values from which the max is computed.
   * @return the maximum
   * @throws IllegalArgumentException if values is empty of null.
   */
  private static int max(int[] values) {
    if (values == null || values.length == 0) {
      throw new IllegalArgumentException("Expecting an array with at least one element");
    }
    int result = Integer.MIN_VALUE;
    for (int value : values) {
      result = Math.max(result, value);
    }
    return result;
  }

  /**
   * Returns an Mac instance for an algorithm name.
   *
   * <p>The main purpose of this method is to try alternative algorithm names.
   */
  private static Mac getMac(String algorithmName) throws NoSuchAlgorithmException {
    try {
      return Mac.getInstance(algorithmName);
    } catch (NoSuchAlgorithmException ex) {
      // Some provider use alternative algorithm names.
    }
    algorithmName = algorithmName.toUpperCase(Locale.ENGLISH);
    switch (algorithmName) {
      case "AES-CMAC":
        // BouncyCastle generally uses a hyphen for CMAC algorithms.
        // However, AES-CMAC is an exception.
        return Mac.getInstance("AESCMAC");
      case "SIPHASHX-2-4":
        // Try the name used by BouncyCastle.
        return Mac.getInstance("SIPHASH128-2-4");
      case "SIPHASHX-4-8":
        // Try the name used by BouncyCastle.
        return Mac.getInstance("SIPHASH128-4-8");
      default:
        break;
    }
    throw new NoSuchAlgorithmException(algorithmName);
  }

  /**
   * Tests computing a MAC by computing it multiple times. The test passes all the results are the
   * same in all cases.
   *
   * @param mac an intialized instance of MAC.
   * @param data input data for the MAC. The size of the data must be at least as long as the sum of
   *     all chunkSizes.
   * @param chunkSizes the sizes of the chunks used in the calls of update
   */
  private void testUpdateWithChunks(Mac mac, byte[] data, int... chunkSizes) {
    // First evaluation: compute MAC in one piece.
    int totalLength = 0;
    for (int chunkSize : chunkSizes) {
      totalLength += chunkSize;
    }
    mac.reset();
    mac.update(data, 0, totalLength);
    byte[] mac1 = mac.doFinal();

    // Second evaluation: using multiple chunks
    mac.reset();
    int start = 0;
    for (int chunkSize : chunkSizes) {
      mac.update(data, start, chunkSize);
      start += chunkSize;
    }
    byte[] mac2 = mac.doFinal();
    if (!MessageDigest.isEqual(mac1, mac2)) {
      fail(
          "Different MACs for same input:"
              + " computed as one piece:"
              + TestUtil.bytesToHex(mac1)
              + " computed with multiple array segments:"
              + TestUtil.bytesToHex(mac2));
    }
    // Third evaluation: using ByteBuffers
    mac.reset();
    start = 0;
    for (int chunkSize : chunkSizes) {
      ByteBuffer chunk = ByteBuffer.wrap(data, start, chunkSize);
      mac.update(chunk);
      start += chunkSize;
    }
    byte[] mac3 = mac.doFinal();
    if (!MessageDigest.isEqual(mac1, mac3)) {
      fail(
          "Different MACs for same input:"
              + " computed as one piece:"
              + TestUtil.bytesToHex(mac1)
              + " computed with wrapped chunks:"
              + TestUtil.bytesToHex(mac3));
    }
    // Forth evaluation: using ByteBuffer slices.
    // The effect of using slice() is that the resulting ByteBuffer has
    // position 0, but possibly an non-zero value for arrayOffset().
    mac.reset();
    start = 0;
    for (int chunkSize : chunkSizes) {
      ByteBuffer chunk = ByteBuffer.wrap(data, start, chunkSize).slice();
      mac.update(chunk);
      start += chunkSize;
    }
    byte[] mac4 = mac.doFinal();
    if (!MessageDigest.isEqual(mac1, mac4)) {
      fail(
          "Different MACs for same input:"
              + " computed as one piece:"
              + TestUtil.bytesToHex(mac1)
              + " computed with ByteBuffer slices:"
              + TestUtil.bytesToHex(mac4));
    }
  }

  /**
   * The paper "Finding Bugs in Cryptographic Hash Function Implementations" by Mouha, Raunak, Kuhn,
   * and Kacker, https://eprint.iacr.org/2017/891.pdf contains an analysis of implementations
   * submitted to the SHA-3 competition. Many of the implementations contain bugs. The authors
   * propose some tests for cryptographic libraries. The test here implements a check for
   * incremental updates with the values proposed in Table 3.
   *
   * @param mac an initialized instance of MAC.
   */
  private void testUpdate(Mac mac) {
    int[] chunkSize1 = {0, 8, 16, 24, 32, 40, 48, 56, 64};
    int[] chunkSize2 = {0, 8, 16, 24, 32, 40, 48, 56, 64};
    int[] chunkSize3 = {0, 8, 16, 32, 64, 128, 256, 512, 1024, 2048};
    int[] chunkSize4 = {
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
      26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
      49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 127, 128, 129, 255, 256,
      257, 511, 512, 513
    };
    int maxSize = max(chunkSize1) + max(chunkSize2) + max(chunkSize3) + max(chunkSize4);
    byte[] data = new byte[maxSize];
    SecureRandom rand = new SecureRandom();
    rand.nextBytes(data);
    for (int size1 : chunkSize1) {
      for (int size2 : chunkSize2) {
        for (int size3 : chunkSize3) {
          for (int size4 : chunkSize4) {
            testUpdateWithChunks(mac, data, size1, size2, size3, size4);
          }
        }
      }
    }
  }

  public void testMac(String algorithm, int keySize) {
    Mac mac;
    try {
      mac = getMac(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest("Algorithm " + algorithm + " is not supported.");
      return;
    }
    byte[] key = new byte[keySize];
    SecureRandom rand = new SecureRandom();
    rand.nextBytes(key);
    try {
      mac.init(new SecretKeySpec(key, algorithm));
    } catch (InvalidKeyException ex) {
      // The test uses typical key sizes. Hence, we expect that a provider accepts them.
      fail(ex.toString());
    }
    testUpdate(mac);
  }

  @Test
  public void testHmacSha1() {
    testMac("HMACSHA1", 20);
  }

  @Test
  public void testHmacSha224() {
    testMac("HMACSHA224", 28);
  }

  @Test
  public void testHmacSha256() {
    testMac("HMACSHA256", 32);
  }

  @Test
  public void testHmacSha384() {
    testMac("HMACSHA384", 48);
  }

  @Test
  public void testHmacSha512() {
    testMac("HMACSHA512", 64);
  }

  @Test
  public void testHmacSha3_224() {
    testMac("HMACSHA3-224", 28);
  }

  @Test
  public void testHmacSha3_256() {
    testMac("HMACSHA3-256", 32);
  }

  @Test
  public void testHmacSha3_384() {
    testMac("HMACSHA3-384", 48);
  }

  @Test
  public void testHmacSha3_512() {
    testMac("HMACSHA3-512", 64);
  }

  @Test
  public void testAesCmac() {
    testMac("AES-CMAC", 16);
  }

  @Test
  public void testSipHash24() {
    testMac("SIPHASH-2-4", 16);
  }

  @Test
  public void testSipHash48() {
    testMac("SIPHASH-4-8", 16);
  }

  @Test
  public void testSipHashX24() {
    testMac("SIPHASHX-2-4", 16);
  }

  @Test
  public void testSipHashX48() {
    testMac("SIPHASHX-4-8", 16);
  }

  @Test
  public void testKmac128() {
    testMac("KMAC128", 32);
  }

  @Test
  public void testKmac256() {
    testMac("KMAC256", 64);
  }

  /**
   * Computes the mac of a message repeated multiple times.
   *
   * @param mac an initialized instance of MAC
   * @param message the bytes to mac
   * @param repetitions the number of repetitions of the message
   * @return the digest
   */
  public byte[] macRepeatedMessage(Mac mac, byte[] message, long repetitions) {
    mac.reset();
    // If the message is short then it is more efficient to collect multiple copies
    // of the message in one chunk and call update with the larger chunk.
    final int maxChunkSize = 1 << 16;
    if (message.length != 0 && 2 * message.length < maxChunkSize) {
      int repetitionsPerChunk = maxChunkSize / message.length;
      byte[] chunk = new byte[message.length * repetitionsPerChunk];
      for (int i = 0; i < repetitionsPerChunk; i++) {
        System.arraycopy(message, 0, chunk, i * message.length, message.length);
      }
      while (repetitions >= repetitionsPerChunk) {
        mac.update(chunk);
        repetitions -= repetitionsPerChunk;
      }
    }

    for (int i = 0; i < repetitions; i++) {
      mac.update(message);
    }
    return mac.doFinal();
  }

  /**
   * A test for hashing long messages.
   *
   * <p>Java does not allow strings or arrays of size 2^31 or longer. However, it is still possible
   * to compute a MAC of a long message by repeatedly calling Mac.update(). To compute correct MACs
   * the total message length must be known. This length can be bigger than 2^32 bytes.
   *
   * <p>Reference: http://www-01.ibm.com/support/docview.wss?uid=swg1PK62549 IBMJCE SHA-1
   * IMPLEMENTATION RETURNS INCORRECT HASH FOR LARGE SETS OF DATA
   */
  private void testLongMac(
      String algorithm, String keyhex, String message, long repetitions, String expected) {
    Mac mac;
    try {
      mac = getMac(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest(algorithm + " not supported");
      return;
    }
    Key key = new SecretKeySpec(TestUtil.hexToBytes(keyhex), algorithm);
    try {
      mac.init(key);
    } catch (InvalidKeyException ex) {
      // Should not happen unless the setup is wrong.
      fail(ex.toString());
    }
    byte[] bytes = message.getBytes(UTF_8);
    byte[] tag = macRepeatedMessage(mac, bytes, repetitions);
    String hextag = TestUtil.bytesToHex(tag);
    assertEquals(expected, hextag);
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongHmacSha1() {
    testLongMac(
        "HMACSHA1",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "a",
        2147483647L,
        "703925f6dceb9c602969ad39bba9b1eb49472071");
    testLongMac(
        "HMACSHA1",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "a",
        5000000000L,
        "d7f4c387f2237ea119fcc27cd7520fc5132b6230");
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongHmacSha256() {
    testLongMac(
        "HMACSHA256",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "a",
        2147483647L,
        "84f213c9bb5b329d547bc31dabed41939754b1af7482365ec74380c45f6ea0a7");
    testLongMac(
        "HMACSHA256",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "a",
        5000000000L,
        "59a75754df7093fa4339aa618b64b104f153a5b42cc85394fdb8735b13ea684a");
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongHmacSha384() {
    testLongMac(
        "HMACSHA384",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            + "202122232425262728292a2b2c2d2e2f",
        "a",
        2147483647L,
        "aea987905f64791691b3fdea06f8e4125f396ebb73f37894e961b1a7522a55da"
            + "ecd856a70c92c6646e6f8c3fcb935528");
    testLongMac(
        "HMACSHA384",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            + "202122232425262728292a2b2c2d2e2f",
        "a",
        5000000000L,
        "88485c9c5714d43a99dacbc861988c7ea39c02d82104bf93e55ec1b8a24fe15a"
            + "a477e6a84d159d8b7a3daaa89c4f2372");
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongHmacSha512() {
    testLongMac(
        "HMACSHA512",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "a",
        2147483647L,
        "fc68fbc294951c691e5bc085c3af026099f39a57230b242aaf1fc5ca691e05da"
            + "d1a5de7d4f30e1c958c6a2cee6159218dab683187e6d56bab824a3adefde9102");
    testLongMac(
        "HMACSHA512",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "a",
        5000000000L,
        "31b1d721b958203bff7d7ddf50d48b17fc760a80a99a7f23ec966ce3bbefff29"
            + "0d176eebbb6a440960024be0726c94960bbf75816548a7fd4552c7baba4585ee");
  }

}


