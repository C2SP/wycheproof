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
 *
 * <p>TODO(bleichen): The tests are quite incomplete. Some of the missing stuff: More test vectors
 * with known results are necessary. So far only simple test vectors for long messages are
 * available. The paper "Finding Bugs in Cryptographic Hash Function Implementations" by Mouha,
 * Raunak, Kuhn, and Kacker, https://eprint.iacr.org/2017/891.pdf contains an analysis of
 * implementations submitted to the SHA-3 competition. Many of the implementations contain bugs.
 */
@RunWith(JUnit4.class)
public class MessageDigestTest {

  /** Compute the same result in different ways and compare the result. */
  private void testUpdate(String algorithm, int messageLength) throws Exception {
    SecureRandom rand = new SecureRandom();
    byte[] message = new byte[messageLength];
    rand.nextBytes(message);
    MessageDigest md = MessageDigest.getInstance(algorithm);
    // Compute the hash of message in one go.
    md.update(message);
    byte[] digest1 = md.digest();

    // Compute the hash of message in multiple parts
    for (int i = 0; i <= messageLength; i++) {
      md.update(message, 0, i);
      md.update(message, i, message.length - i);
      byte[] digest2 = md.digest();
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

  /** Same test as above using ByteBuffers instead. */
  private void testByteBuffer(String algorithm, int messageLength) throws Exception {
    SecureRandom rand = new SecureRandom();
    byte[] message = new byte[messageLength];
    rand.nextBytes(message);
    MessageDigest md = MessageDigest.getInstance(algorithm);
    // Compute the hash of message without using ByteBuffer.
    md.update(message);
    byte[] digest1 = md.digest();

    // Compute the hash of message in multiple parts
    for (int i = 0; i <= messageLength; i++) {
      ByteBuffer part1 = ByteBuffer.wrap(message, 0, i);
      // Using slice() has the effect that arrayOffset() is not necessarily 0.
      ByteBuffer part2 = ByteBuffer.wrap(message, i, message.length - i).slice();
      md.update(part1);
      md.update(part2);
      byte[] digest2 = md.digest();
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

  /**
   * Same test as above using readonly ByteBuffers instead. If a ByteBuffer is readonly, then the
   * underlying array is not accessible. Some providers might have distinct code for ByteBuffers
   * where the underlying array is accessible and where the underlying array is hidden.
   */
  public void testReadOnlyByteBuffer(String algorithm, int messageLength) throws Exception {
    SecureRandom rand = new SecureRandom();
    byte[] message = new byte[messageLength];
    rand.nextBytes(message);
    MessageDigest md = MessageDigest.getInstance(algorithm);
    // Compute the hash of message without using ByteBuffer.
    md.update(message);
    byte[] digest1 = md.digest();

    // Compute the hash of message in multiple parts
    for (int i = 0; i <= messageLength; i++) {
      ByteBuffer part1 = ByteBuffer.wrap(message, 0, i).asReadOnlyBuffer();
      ByteBuffer part2 = ByteBuffer.wrap(message, i, message.length - i).asReadOnlyBuffer();
      md.update(part1);
      md.update(part2);
      byte[] digest2 = md.digest();
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

  /**
   * Some provider allow to clone instances of MessageDigests. This test checks whether cloning
   * modifies the hash result.
   */
  public void testClone(String algorithm, int messageLength) throws Exception {
    SecureRandom rand = new SecureRandom();
    byte[] message = new byte[messageLength];
    rand.nextBytes(message);
    MessageDigest md = MessageDigest.getInstance(algorithm);
    // Compute the hash of message in one go.
    byte[] digest1 = md.digest(message);

    // Clone md after hashing one part of message.
    for (int i = 0; i <= messageLength; i++) {
      md.reset();
      md.update(message, 0, i);
      try {
        MessageDigest md2 = (MessageDigest) md.clone();
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
      } catch (CloneNotSupportedException ex) {
        System.out.println("Cloning " + algorithm + " is not supported. Skipping test.");
        return;
      }
    }

    // A variant of the test above that checks whether the source message digest is still usable.
    md.reset();
    for (int i = 0; i < messageLength; i++) {
      try {
        MessageDigest md2 = (MessageDigest) md.clone();
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
      } catch (CloneNotSupportedException ex) {
        System.out.println("Cloning " + algorithm + " is not supported. Skipping test.");
        return;
      }
      md.update(message[i]);
    }
  }

  public void testMessageDigest(String algorithm) throws Exception {
    try {
      MessageDigest.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("Algorithm " + algorithm + " is not supported. Skipping test.");
      return;
    }
    testUpdate(algorithm, 48);
    testUpdate(algorithm, 64);
    testUpdate(algorithm, 256);
    testByteBuffer(algorithm, 128);
    testReadOnlyByteBuffer(algorithm, 128);
    testClone(algorithm, 256);
  }

  @Test
  public void testMd5() throws Exception {
    testMessageDigest("MD5");
  }

  @Test
  public void testSha1() throws Exception {
    testMessageDigest("SHA-1");
  }

  @Test
  public void testSha224() throws Exception {
    testMessageDigest("SHA-224");
  }

  @Test
  public void testSha256() throws Exception {
    testMessageDigest("SHA-256");
  }

  @Test
  public void testSha384() throws Exception {
    testMessageDigest("SHA-384");
  }

  @Test
  public void testSha512() throws Exception {
    testMessageDigest("SHA-512");
  }

  @Test
  public void testSha3_224() throws Exception {
    testMessageDigest("SHA3-224");
  }

  @Test
  public void testSha3_256() throws Exception {
    testMessageDigest("SHA3-256");
  }

  @Test
  public void testSha3_384() throws Exception {
    testMessageDigest("SHA3-384");
  }

  @Test
  public void testSha3_512() throws Exception {
    testMessageDigest("SHA3-512");
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
  public byte[] hashRepeatedMessage(String algorithm, byte[] message, long repetitions)
      throws Exception {
    MessageDigest md = MessageDigest.getInstance(algorithm);
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
  private void testLongMessage(String algorithm, String message, long repetitions, String expected)
      throws Exception {
    try {
      MessageDigest.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("Algorithm " + algorithm + " is not supported. Skipping test.");
      return;
    }

    byte[] bytes = message.getBytes("UTF-8");
    byte[] digest = hashRepeatedMessage(algorithm, bytes, repetitions);
    String hexdigest = TestUtil.bytesToHex(digest);
    assertEquals(expected, hexdigest);
  }

  @SlowTest(
    providers = {ProviderType.OPENJDK, ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE}
  )
  @Test
  public void testLongMessageMd5() throws Exception {
    testLongMessage("MD5", "a", 2147483647L, "bb2ef53aae423cb9fbf8788f187601e6");
    testLongMessage("MD5", "a", 5000000000L, "cf3147924864955e385804daee42d3ef");
  }

  @SlowTest(
    providers = {ProviderType.OPENJDK, ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE}
  )
  @Test
  public void testLongMessageSha1() throws Exception {
    testLongMessage("SHA-1", "a", 2147483647L, "1e5b490b10255e37fd96d0964f2fbfb91ed47536");
    testLongMessage("SHA-1", "a", 5000000000L, "109b426b74c3dc1bd0e15d3524c5b837557647f2");
  }

  @SlowTest(
    providers = {ProviderType.OPENJDK, ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE}
  )
  @Test
  public void testLongMessageSha256() throws Exception {
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

  @SlowTest(
    providers = {ProviderType.OPENJDK, ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE}
  )
  @Test
  public void testLongMessageSha224() throws Exception {
    testLongMessage(
        "SHA-224", "a", 2147483647L, "bf5dbff84919d0bd40316439d102c6f856553b7a89ef9212fd200d9e");
    testLongMessage(
        "SHA-224", "a", 5000000000L, "01acee23c428420235b7cd6a4e8c7ee453242f094f1d4477de6ad61a");
  }

  @SlowTest(
    providers = {ProviderType.OPENJDK, ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE}
  )
  @Test
  public void testLongMessageSha384() throws Exception {
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

  @SlowTest(
    providers = {ProviderType.OPENJDK, ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE}
  )
  @Test
  public void testLongMessageSha512() throws Exception {
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

  @SlowTest(
      providers = {ProviderType.OPENJDK, ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE})
  @Test
  public void testLongMessageSha3_224() throws Exception {
    testLongMessage(
        "SHA3-224", "a", 2147483647L, "24abc6b4055cea68422fa8d73031f45f73f2afda09be9c0dae2ab88e");
    testLongMessage(
        "SHA3-224", "a", 5000000000L, "96ce1138a9f42ba22929594a636404c13a99fe3c31a05fe3a00a8fda");
  }

  @SlowTest(
      providers = {ProviderType.OPENJDK, ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE})
  @Test
  public void testLongMessageSha3_256() throws Exception {
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

  @SlowTest(
      providers = {ProviderType.OPENJDK, ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE})
  @Test
  public void testLongMessageSha3_384() throws Exception {
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

  @SlowTest(
      providers = {ProviderType.OPENJDK, ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE})
  @Test
  public void testLongMessageSha3_512() throws Exception {
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
}
