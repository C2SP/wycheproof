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

import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import com.google.security.wycheproof.WycheproofRunner.SlowTest;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for message digests.
 */
@RunWith(JUnit4.class)
public class MessageDigestTest {

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
   * Tests computing a MessageDigest by computing it multiple times.
   *
   * <p>The test passes if all the results are the same in all cases.
   *
   * @param md the MessageDigest
   * @param data input data for the message digest. The size of the data must be at least as long as
   *     the sum of all chunkSizes.
   * @param chunkSizes the sizes of the chunks used in the calls of update
   */
  private void testUpdateWithChunks(MessageDigest md, byte[] data, int... chunkSizes) {
    // First evaluation: compute hash in one piece.
    int totalLength = 0;
    for (int chunkSize : chunkSizes) {
      totalLength += chunkSize;
    }
    md.reset();
    md.update(data, 0, totalLength);
    byte[] digest1 = md.digest();

    // Second evaluation: using multiple chunks
    md.reset();
    int start = 0;
    for (int chunkSize : chunkSizes) {
      md.update(data, start, chunkSize);
      start += chunkSize;
    }
    byte[] digest2 = md.digest();
    if (!MessageDigest.isEqual(digest1, digest2)) {
      fail(
          "Different hashes for same input:"
              + " computed as one piece:"
              + TestUtil.bytesToHex(digest1)
              + " computed with multiple array segments:"
              + TestUtil.bytesToHex(digest2));
    }
    // Third evaluation: using ByteBuffers
    md.reset();
    start = 0;
    for (int chunkSize : chunkSizes) {
      ByteBuffer chunk = ByteBuffer.wrap(data, start, chunkSize);
      md.update(chunk);
      start += chunkSize;
    }
    byte[] digest3 = md.digest();
    if (!MessageDigest.isEqual(digest1, digest3)) {
      fail(
          "Different hashes for same input:"
              + " computed as one piece:"
              + TestUtil.bytesToHex(digest1)
              + " computed with wrapped chunks:"
              + TestUtil.bytesToHex(digest3));
    }
    // Forth evaluation: using ByteBuffer slices.
    // The effect of using slice() is that the resulting ByteBuffer has
    // position 0, but possibly an non-zero value for arrayOffset().
    md.reset();
    start = 0;
    for (int chunkSize : chunkSizes) {
      ByteBuffer chunk = ByteBuffer.wrap(data, start, chunkSize).slice();
      md.update(chunk);
      start += chunkSize;
    }
    byte[] digest4 = md.digest();
    if (!MessageDigest.isEqual(digest1, digest4)) {
      fail(
          "Different hashes for same input:"
              + " computed as one piece:"
              + TestUtil.bytesToHex(digest1)
              + " computed with ByteBuffer slices:"
              + TestUtil.bytesToHex(digest4));
    }

    // Fifth evaluation: using readonly ByteBuffer slices.
    // The effect of using slice() is that the resulting ByteBuffer has
    // position 0, but possibly an non-zero value for arrayOffset().
    md.reset();
    start = 0;
    for (int chunkSize : chunkSizes) {
      ByteBuffer chunk = ByteBuffer.wrap(data, start, chunkSize).slice().asReadOnlyBuffer();
      md.update(chunk);
      start += chunkSize;
    }
    byte[] digest5 = md.digest();
    if (!MessageDigest.isEqual(digest1, digest5)) {
      fail(
          "Different hashes for same input:"
              + " computed as one piece:"
              + TestUtil.bytesToHex(digest1)
              + " computed with ByteBuffer slices:"
              + TestUtil.bytesToHex(digest5));
    }
  }

  /**
   * The paper "Finding Bugs in Cryptographic Hash Function Implementations" by Mouha, Raunak, Kuhn,
   * and Kacker, https://eprint.iacr.org/2017/891.pdf contains an analysis of implementations
   * submitted to the SHA-3 competition. Many of the implementations contain bugs. The authors
   * propose some tests for cryptographic libraries. The test here implements a check for
   * incremental updates with the values proposed in Table 3.
   */
  private void testUpdate(MessageDigest md) {
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
            testUpdateWithChunks(md, data, size1, size2, size3, size4);
          }
        }
      }
    }
  }

  public void testMessageDigest(String algorithm) {
    MessageDigest md;
    try {
      md = MessageDigest.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest("Algorithm " + algorithm + " is not supported.");
      return;
    }
    testUpdate(md);
  }

  @Test
  public void testMd5() {
    testMessageDigest("MD5");
  }

  @Test
  public void testSha1() {
    testMessageDigest("SHA-1");
  }

  @Test
  public void testSha224() {
    testMessageDigest("SHA-224");
  }

  @Test
  public void testSha256() {
    testMessageDigest("SHA-256");
  }

  @Test
  public void testSha384() {
    testMessageDigest("SHA-384");
  }

  @Test
  public void testSha512() {
    testMessageDigest("SHA-512");
  }

  @Test
  public void testSha3_224() {
    testMessageDigest("SHA3-224");
  }

  @Test
  public void testSha3_256() {
    testMessageDigest("SHA3-256");
  }

  @Test
  public void testSha3_384() {
    testMessageDigest("SHA3-384");
  }

  @Test
  public void testSha3_512() {
    testMessageDigest("SHA3-512");
  }

  @Test
  public void testKeccak224() {
    testMessageDigest("KECCAK-224");
  }

  @Test
  public void testKeccak256() {
    testMessageDigest("KECCAK-256");
  }

  @Test
  public void testKeccak384() {
    testMessageDigest("KECCAK-384");
  }

  @Test
  public void testKeccak_512() {
    testMessageDigest("KECCAK-512");
  }

  /**
   * SHAKE128 and SHAKE256 are sometimes used as hash function. When used as hash function the
   * output size is double the security strength. Hence the output of SHAKE128 would be 256 bits and
   * the output of SHAKE256 would be 512 bits.
   *
   * <p>Two hash function based on SHAKE are implemented in BouncyCastle. BouncyCastle uses the
   * algorithm names "SHAKE128-256" and "SHAKE256-512".
   */
  @Test
  public void testShake128_256() {
    testMessageDigest("SHAKE128-256");
  }

  @Test
  public void testShake256_512() {
    testMessageDigest("SHAKE256-512");
  }

  /**
   * Some provider allow to clone instances of MessageDigests. This test checks whether cloning
   * modifies the hash result.
   */
  public void testClone(String algorithm) {
    MessageDigest md;
    try {
      md = MessageDigest.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest(ex.toString());
      return;
    }
    SecureRandom rand = new SecureRandom();
    int messageLength = 256;
    byte[] message = new byte[messageLength];
    rand.nextBytes(message);
    // Compute the hash of message in one go.
    byte[] digest1 = md.digest(message);

    // Clone md after hashing one part of message.
    for (int i = 0; i <= messageLength; i++) {
      md.reset();
      md.update(message, 0, i);
      MessageDigest md2;
      try {
        md2 = (MessageDigest) md.clone();
      } catch (CloneNotSupportedException ex) {
        TestUtil.skipTest("Cloning " + algorithm + " is not supported. Skipping test.");
        return;
      }
      md2.update(message, i, message.length - i);
      byte[] digest2 = md2.digest();
      if (!Arrays.equals(digest1, digest2)) {
        fail(
            "Different hashes for same input digest1:"
                + TestUtil.bytesToHex(digest1)
                + " digest2:"
                + TestUtil.bytesToHex(digest2)
                + " i:"
                + i);
      }
    }
  }

  @Test
  public void testCloneMd5() {
    testClone("MD5");
  }

  @Test
  public void testCloneSha1() {
    testClone("SHA-1");
  }

  @Test
  public void testCloneSha224() {
    testClone("SHA-224");
  }

  @Test
  public void testCloneSha256() {
    testClone("SHA-256");
  }

  @Test
  public void testCloneSha384() {
    testClone("SHA-384");
  }

  @Test
  public void testCloneSha512() {
    testClone("SHA-512");
  }

  @Test
  public void testCloneSha3_224() {
    testClone("SHA3-224");
  }

  @Test
  public void testCloneSha3_256() {
    testClone("SHA3-256");
  }

  @Test
  public void testCloneSha3_384() {
    testClone("SHA3-384");
  }

  @Test
  public void testCloneSha3_512() {
    testClone("SHA3-512");
  }

  @Test
  public void testCloneKeccak224() {
    testClone("KECCAK-224");
  }

  @Test
  public void testCloneKeccak256() {
    testClone("KECCAK-256");
  }

  @Test
  public void testCloneKeccak384() {
    testClone("KECCAK-384");
  }

  @Test
  public void testCloneKeccak_512() {
    testClone("KECCAK-512");
  }

  @Test
  public void testCloneShake128_256() {
    testClone("SHAKE128-256");
  }

  @Test
  public void testCloneShake256_512() {
    testClone("SHAKE256-512");
  }

  /**
   * Computes the hash of a message repeated multiple times.
   *
   * @param algorithm the message digest (e.g. "SHA-1")
   * @param message the byte to hash
   * @param repetitions the number of repetitions of the message
   * @return the digest
   * @throws GeneralSecurityException if the computation of the hash fails (e.g. because the
   *     algorithm is unknown).
   */
  public byte[] hashRepeatedMessage(MessageDigest md, byte[] message, long repetitions) {
    // If the message is short then it is more efficient to collect multiple copies
    // of the message in one chunk and call update with the larger chunk.
    final int maxChunkSize = 1 << 16;
    md.reset();
    if (message.length != 0 && 2 * message.length < maxChunkSize) {
      int repetitionsPerChunk = maxChunkSize / message.length;
      byte[] chunk = new byte[message.length * repetitionsPerChunk];
      for (int i = 0; i < repetitionsPerChunk; i++) {
        System.arraycopy(message, 0, chunk, i * message.length, message.length);
      }
      while (repetitions >= repetitionsPerChunk) {
        md.update(chunk);
        repetitions -= repetitionsPerChunk;
      }
    }

    for (int i = 0; i < repetitions; i++) {
      md.update(message);
    }
    return md.digest();
  }

  /**
   * A test for hashing long messages.
   *
   * <p>Java does not allow strings or arrays of size 2^31 or longer. However, it is still possible
   * to compute a hash of a long message by repeatedly calling MessageDigest.update(). To compute
   * correct hashes the total message length must be known. This length can be bigger than 2^32
   * bytes.
   *
   * <p>Reference: http://www-01.ibm.com/support/docview.wss?uid=swg1PK62549 IBMJCE SHA-1
   * IMPLEMENTATION RETURNS INCORRECT HASH FOR LARGE SETS OF DATA
   */
  @SuppressWarnings("InsecureCryptoUsage")
  private void testLongMessage(
      String algorithm, String message, long repetitions, String expected) {
    MessageDigest md;
    try {
      md = MessageDigest.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest("Algorithm " + algorithm + " is not supported.");
      return;
    }

    byte[] bytes;
    try {
      bytes = message.getBytes("UTF-8");
    } catch (UnsupportedEncodingException ex) {
      fail("This should not happen.");
      return;
    }
    byte[] digest = hashRepeatedMessage(md, bytes, repetitions);
    String hexdigest = TestUtil.bytesToHex(digest);
    assertEquals(expected, hexdigest);
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageMd5() {
    testLongMessage("MD5", "a", 2147483647L, "bb2ef53aae423cb9fbf8788f187601e6");
    testLongMessage("MD5", "a", 5000000000L, "cf3147924864955e385804daee42d3ef");
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageSha1() {
    testLongMessage("SHA-1", "a", 2147483647L, "1e5b490b10255e37fd96d0964f2fbfb91ed47536");
    testLongMessage("SHA-1", "a", 5000000000L, "109b426b74c3dc1bd0e15d3524c5b837557647f2");
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageSha256() {
    testLongMessage(
        "SHA-256",
        "a",
        2147483647L,
        "6cc47f3907eea90fb8de9493cf025923fff2b88fcac896cbf38036d5913b6bed");
    testLongMessage(
        "SHA-256",
        "a",
        5000000000L,
        "59fefaeb480c09b569fb8e5f277e0165e3f33bd322a2d2148cf6dd49af40779c");
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageSha224() {
    testLongMessage(
        "SHA-224", "a", 2147483647L, "bf5dbff84919d0bd40316439d102c6f856553b7a89ef9212fd200d9e");
    testLongMessage(
        "SHA-224", "a", 5000000000L, "01acee23c428420235b7cd6a4e8c7ee453242f094f1d4477de6ad61a");
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageSha384() {
    testLongMessage(
        "SHA-384",
        "a",
        2147483647L,
        "08879ffbedb441c65ecf1c66286036c853632cf73262d5d3d6ecc621ee148e89"
            + "f8acf29c0849f72e2a98756d4d4b895f");
    testLongMessage(
        "SHA-384",
        "a",
        5000000000L,
        "7f1541299d24f30155b4a849c4e8abd67cbf273a996d7a8c384476e87c143abd"
            + "35eef2e1dd576960b9e5a0cd10607c43");
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageSha512() {
    testLongMessage(
        "SHA-512",
        "a",
        2147483647L,
        "7c69df3c6a06437c6d6ea91cb10812edcdaaeabda16c6436bf3279d82c7cf40e"
            + "2a94cc4b363206c1dce79904f9ce876e434cf78745a426ceef199c4d748acea9");
    testLongMessage(
        "SHA-512",
        "a",
        5000000000L,
        "080c2d9527c960c2a4a9124d728d36cd2effcaac73de09221bfc8b4afc6d52e0"
            + "4006f962f4fb31640642aece873f7906180cc3ebf794cd319d27d30889428011");
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageSha3_224() {
    testLongMessage(
        "SHA3-224", "a", 2147483647L, "24abc6b4055cea68422fa8d73031f45f73f2afda09be9c0dae2ab88e");
    testLongMessage(
        "SHA3-224", "a", 5000000000L, "96ce1138a9f42ba22929594a636404c13a99fe3c31a05fe3a00a8fda");
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageSha3_256() {
    testLongMessage(
        "SHA3-256",
        "a",
        2147483647L,
        "8bcd31a0d849cca71991062525ffe8b5dd07b41f686880e6c30bfe4382bb2beb");
    testLongMessage(
        "SHA3-256",
        "a",
        5000000000L,
        "ecb2ba5fe2a2632ea91c59ec40b113d843409f3c91cb7ec4cced351cec1202fb");
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageSha3_384() {
    testLongMessage(
        "SHA3-384",
        "a",
        2147483647L,
        "23a834892c1bd880e6aa2070b18a73dc8abb744e08446c3cfafb4b07c23a2401"
            + "06828a950d6ececf9a2901c9afff2260");
    testLongMessage(
        "SHA3-384",
        "a",
        5000000000L,
        "70872456924c5791993f18b15cc7170be5b06e609b6925e56972a7451b2e7e2e"
            + "85c8317579057d90637da979f82e71f3");
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageSha3_512() {
    testLongMessage(
        "SHA3-512",
        "a",
        2147483647L,
        "40bd9ee7e496c2e4d086553242175b935cadb2cfc030405f67b11a1fd3dc4926"
            + "24933e6fe0d8b163a16bd3585401017847673189cffd8250d02af47e4a587745");
    testLongMessage(
        "SHA3-512",
        "a",
        5000000000L,
        "348216749aefd183244737248de016fdc113877aad833e0ad4ae5631c5af1362"
            + "e6cc5a81a5ff634f31be8f71ae8a271369abd86e6baaddfa7b9a016a6084afc2");
  }

  /**
   * KECCAK-224, KECCAK-256, KECCAK-384 and KECCAK-512 are hash functions based on KECCAK that were
   * defined before NIST finailized the SHA-3 standard. These hash functions are implemented in a
   * number of libraries such as BouncyCastle. The hash functions are almost identical to SHA3-224,
   * SHA3-256, SHA3-384 and SHA3-512. The only difference is the padding of the input. NIST appends
   * a small number of fixed bits to each message that is hashed. The purpose of these bits is
   * domain separation between different uses of KECCAK.
   *
   * <p>E.g. using NIST notation
   *
   * <pre>
   * SHA3-256(M)   = Keccak[512](M || 01, 256), whereas
   * KECCAK-256(M) = Keccak[512](M, 256)
   * </pre>
   *
   * <p>The algorithm names "KECCAK-224", "KECCAK-256", "KECCAK-384" and "KECCAK-512" are used by
   * BouncyCastle. Since they are not standard algorithm names it is likely that other providers
   * implementing the hash functions used different names.
   */
  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageKeccak224() {
    testLongMessage(
        "KECCAK-224", "a", 10000000L, "e6a07dafdde2ff8e6d67e3efc6dc871b4d0b04e4e8b87fb8d4f183ec");
    testLongMessage(
        "KECCAK-224", "a", 2147483647L, "ecbd20f13ccec2ca90e638825d815e2823193a15476bbd9c70fa1cf8");
    testLongMessage(
        "KECCAK-224", "a", 5000000000L, "eb0d1cbaf604ed955fafd528c1d945f05f97ba6bfcfc57984d662913");
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageKeccak256() {
    testLongMessage(
        "KECCAK-256",
        "a",
        10000000L,
        "c28e150b82236d82db552b84edb49ddef86e5dd3f6ba9a7ee7b82e4090d7c4ae");
    testLongMessage(
        "KECCAK-256",
        "a",
        2147483647L,
        "9932ed01cadcaffa583c7cac4586bf3aa2b82e3c28501200276d778423f471f8");
    testLongMessage(
        "KECCAK-256",
        "a",
        5000000000L,
        "875ff21c135ab9eb8a57da79f0f02c3ce0913dc9faad111e6f165dfce9715c45");
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageKeccak384() {
    testLongMessage(
        "KECCAK-384",
        "a",
        10000000L,
        "cc692ad0d7b580b431c3658367cbd798c9d0c31e36ba1dcce07a48d537d93521"
            + "fcc47abb5dd04e359570285a77d49c46");
    testLongMessage(
        "KECCAK-384",
        "a",
        2147483647L,
        "6fad5d86e01ac7cda864fb89fb5f9533516af12a2730aae663c766a910316677"
            + "cf0833f9f7d8ff2316d63737fb25e74a");
    testLongMessage(
        "KECCAK-384",
        "a",
        5000000000L,
        "529028480fc183ca7c6dc5a84270b5fe14babaf9618ce4512e27210ba1041fbd"
            + "c55f6557098335eff1982cc8b078ec4f");
  }

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageKeccak512() {
    testLongMessage(
        "KECCAK-512",
        "a",
        10000000L,
        "34272039cd0cc8344f469076a581160ee0dfbcb8ddaa9f28ff73fa3dfe8d613a"
            + "8bbcb31706d5186727bd8590bbc709ca3628c16a935a2c2e515e49b80bf26820");
    testLongMessage(
        "KECCAK-512",
        "a",
        2147483647L,
        "d0dab1cf3b6b87a38593ebf9f9dfea85513a8e2884f2c8f126f456b0e730fbcf"
            + "b423a9bd32849f077885ab9b0632402968448b872990e8255448e52883dc04ae");
    testLongMessage(
        "KECCAK-512",
        "a",
        5000000000L,
        "08e38c32234f19c7c7dfb60b9632e60f33b67eebaa9305908861657d51af9850"
            + "a82ea7a0a0733ffd83b3c6ecca437ace980048307b40df4e69ed7b290df3ea0b");
  }

  /**
   * Tests SHAKE128 when used as a hash function with 256 bit output.
   *
   * <p>BouncyCastle uses algorithm name "SHAKE128-256" for this function.
   */
  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageShake128_256() {
    testLongMessage(
        "SHAKE128-256",
        "a",
        2147483647L,
        "df99e7bfce73322df3c7b26e782f08366fc7bf17c100f52233464e4fdbefb00d");
    testLongMessage(
        "SHAKE128-256",
        "a",
        5000000000L,
        "5cb33910aeb298dbc368e3fb2add2accd5a19addf66d4e30595517b7d3285172");
  }

  /**
   * Tests SHAKE256 when used as a hash function with 512 bit output.
   *
   * <p>BouncyCastle uses algorithm name "SHAKE256-512" for this function.
   */
  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testLongMessageShake256_512() {
    testLongMessage(
        "SHAKE256-512",
        "a",
        2147483647L,
        "bbb16c288890bfbc83ff9006821f6169d92cff3a4210e30fa50ea90cb4e71eb5"
            + "5604bc55a1438a9a3f8883ec866bea932315dec6321263b31c89758272df12ac");
    testLongMessage(
        "SHAKE256-512",
        "a",
        5000000000L,
        "68649c37e983ad0ed3fb50ff242542d4236c56a30e32f77aa8d55c9616575b52"
            + "89b44845a536f0196bf06f7d248cc3ddc8378eb6c1e71d7c4e16c49f6c9e081f");
  }
}
