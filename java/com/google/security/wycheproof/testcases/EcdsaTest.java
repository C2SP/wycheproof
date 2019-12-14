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

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import com.google.security.wycheproof.WycheproofRunner.SlowTest;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests ECDSA signatures.
 *
 * <p>Tests for signature verification with test vectors are in JsonSignatureTest.java toghether
 * with other signature schemes.
 *
 * @author bleichen@google.com (Daniel Bleichenbacher)
 */
@RunWith(JUnit4.class)
public class EcdsaTest {

  /**
   * Determines the Hash name from the ECDSA algorithm. There is a small inconsistency in the naming
   * of algorithms. The Oracle standard use no hyphen in SHA256WithECDSA but uses a hyphen in the
   * message digest, i.e., SHA-256.
   */
  private String getHashAlgorithm(String ecdsaAlgorithm) {
    ecdsaAlgorithm = ecdsaAlgorithm.toUpperCase();
    int idx = ecdsaAlgorithm.indexOf("WITH");
    if (idx > 0) {
      if (ecdsaAlgorithm.startsWith("SHA")) {
        return "SHA-" + ecdsaAlgorithm.substring(3, idx);
      } else {
        return ecdsaAlgorithm.substring(0, idx);
      }
    }
    return "";
  }

  /**
   * Extract the integer r from an ECDSA signature. This method implicitely assumes that the ECDSA
   * signature is DER encoded. and that the order of the curve is smaller than 2^1024.
   */
  BigInteger extractR(byte[] signature) throws Exception {
    int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
    int lengthR = signature[startR + 1];
    return new BigInteger(Arrays.copyOfRange(signature, startR + 2, startR + 2 + lengthR));
  }

  BigInteger extractS(byte[] signature) throws Exception {
    int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
    int lengthR = signature[startR + 1];
    int startS = startR + 2 + lengthR;
    int lengthS = signature[startS + 1];
    return new BigInteger(Arrays.copyOfRange(signature, startS + 2, startS + 2 + lengthS));
  }

  /** Extract the k that was used to sign the signature. */
  BigInteger extractK(byte[] signature, BigInteger h, ECPrivateKey priv) throws Exception {
    BigInteger x = priv.getS();
    BigInteger n = priv.getParams().getOrder();
    BigInteger r = extractR(signature);
    BigInteger s = extractS(signature);
    BigInteger k = x.multiply(r).add(h).multiply(s.modInverse(n)).mod(n);
    return k;
  }

  /**
   * Computes the bias of samples as
   *
   * abs(sum(e^(2 pi i s m / modulus) for s in samples) / sqrt(samples.length).
   *
   * If the samples are taken from a uniform distribution in the range 0 .. modulus - 1
   * and the number of samples is significantly larger than L^2
   * then the probability that the result is larger than L is approximately e^(-L^2).
   * The approximation can be derived from the assumption that samples taken from
   * a uniform distribution give a result that approximates a standard complex normal 
   * distribution Z. I.e. Z has a density f_Z(z) = exp(-abs(z)^2) / pi.
   * https://en.wikipedia.org/wiki/Complex_normal_distribution
   */
  double bias(BigInteger[] samples, BigInteger modulus, BigInteger m) {
    double sumReal = 0.0;
    double sumImag = 0.0;
    for (BigInteger s : samples) {
      BigInteger r = s.multiply(m).mod(modulus);
      // multiplier = 2 * pi / 2^52
      double multiplier = 1.3951473992034527e-15;
      // computes the quotent 2 * pi * r / modulus
      double quot = r.shiftLeft(52).divide(modulus).doubleValue() * multiplier;     
      sumReal += Math.cos(quot);
      sumImag += Math.sin(quot);
    }
    return Math.sqrt((sumReal * sumReal + sumImag * sumImag) / samples.length);
  }

  /**
   * This test checks the basic functionality of ECDSA. It simply tries to generate a key, sign and
   * verify a message for a given, algorithm and curve.
   *
   * @param algorithm the algorithm to test (e.g. "SHA256WithECDSA")
   * @param curve the curve to test (e.g. "secp256r1")
   * @return whether the algorithm and curve are supported.
   * @throws Exception if an unexpected error occurred.
   */
  boolean testParameters(String algorithm, String curve) throws Exception {
    String message = "123400";

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec ecSpec = new ECGenParameterSpec(curve);
    KeyPair keyPair;
    try {
      keyGen.initialize(ecSpec);
      keyPair = keyGen.generateKeyPair();
    } catch (InvalidAlgorithmParameterException ex) {
      // The curve is not supported.
      // The documentation does not specify whether the method initialize
      // has to reject unsupported curves or if only generateKeyPair checks
      // whether the curve is supported.
      return false;
    }
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

    // Print the parameters.
    System.out.println("Parameters for curve:" + curve);
    EcUtil.printParameters(pub.getParams());

    Signature signer;
    Signature verifier;
    try {
      signer = Signature.getInstance(algorithm);
      verifier = Signature.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      // The algorithm is not supported.
      return false;
    }
    // Both algorithm and curve are supported.
    // Hence, we expect that signing and verifying properly works.
    byte[] messageBytes = message.getBytes("UTF-8");
    signer.initSign(priv);
    signer.update(messageBytes);
    byte[] signature = signer.sign();
    verifier.initVerify(pub);
    verifier.update(messageBytes);
    assertTrue(verifier.verify(signature));
    return true;
  }

  /**
   * This test checks the basic functionality of ECDSA. This mainly checks that the provider follows
   * the JCA interface.
   */
  @Test
  public void testBasic() throws Exception {
    String algorithm = "SHA256WithECDSA";
    String curve = "secp256r1";
    assertTrue(testParameters(algorithm, curve));
  }

  /** Checks whether the one time key k in ECDSA is biased. */
  public void testBias(String algorithm, String curve, ECParameterSpec ecParams) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    try {
      keyGen.initialize(ecParams);
    } catch (InvalidAlgorithmParameterException ex) {
      System.out.println("This provider does not support curve:" + curve);
      return;
    }
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    // If we throw a fair coin tests times then the probability that
    // either heads or tails appears less than mincount is less than 2^{-32}.
    // Therefore the test below is not expected to fail unless the generation
    // of the one time keys is indeed biased.
    final int tests = 1024;
    final int mincount = 410;

    String hashAlgorithm = getHashAlgorithm(algorithm);
    String message = "Hello";
    byte[] messageBytes = message.getBytes("UTF-8");
    byte[] digest = MessageDigest.getInstance(hashAlgorithm).digest(messageBytes);

    // TODO(bleichen): Truncate the digest if the digest size is larger than the
    //   curve size.
    BigInteger h = new BigInteger(1, digest);
    BigInteger q = priv.getParams().getOrder();
    BigInteger qHalf = q.shiftRight(1);

    Signature signer = Signature.getInstance(algorithm);
    signer.initSign(priv);
    BigInteger[] kList = new BigInteger[tests];
    for (int i = 0; i < tests; i++) {
      signer.update(messageBytes);
      byte[] signature = signer.sign();
      kList[i] = extractK(signature, h, priv);
    }

    // Checks whether the most significant bits and the least significant bits
    // of the value k are unbiased.
    int countMsb = 0; // count the number of k's with lsb set
    int countLsb = 0; // count the number of k's with msb set
    for (BigInteger k : kList) {
      if (k.testBit(0)) {
        countLsb++;
      }
      if (k.compareTo(qHalf) > 0) {
        countMsb++;
      }
    }
    if (countLsb < mincount || countLsb > tests - mincount) {
      fail("Bias detected in the least significant bit of k:" + countLsb);
    }
    if (countMsb < mincount || countMsb > tests - mincount) {
      fail("Bias detected in the most significant bit of k:" + countMsb);
    }

    // One situation where the bits above are not biased even if k itself is
    // badly distributed is the case where the signer replaces s by
    // min(s, q - s). Such a replacement is sometimes done to avoid signature
    // malleability of ECDSA.
    // Breitner and Heninger describe such cases in the paper
    // "Biased Nonce Sense: Lattice Attacks against Weak ECDSA Signatures in Cryptocurrencies",
    // https://eprint.iacr.org/2019/023.pdf
    // The following tests should catch the bugs described in this paper.
    // The threshold below has been chosen to give false positives with probability < 2^{-32}.
    double threshold = 5;

    // This test detects for example the case when either k or q-k is small.
    double bias1 = bias(kList, q, BigInteger.ONE);
    if (bias1 > threshold) {
      fail("Bias for k detected. bias1 = " + bias1);
    }
    // Same as above but shifing by one bit.
    double bias2 = bias(kList, q, BigInteger.valueOf(2)); 
    if (bias2 > threshold) {
      fail("Bias for k detected. bias2 = " + bias2);
    }
    double bias3 = bias(kList, q, qHalf);
    if (bias3 > threshold) {
      fail("Bias for k detected. bias3 = " + bias3);
    }
    // Checks whether most significant bytes, words, dwords or qwords are strongly correlated.
    for (int bits : new int[] {8, 16, 32, 64}) {
      BigInteger multiplier = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE);
      double bias4 = bias(kList, q, multiplier);
      if (bias4 > threshold) {
        fail("Bias for k detected. bits = " + bits + " bias4 = " + bias4);
      }
    }
  }

  @SlowTest(
    providers = {
      ProviderType.BOUNCY_CASTLE,
      ProviderType.CONSCRYPT,
      ProviderType.OPENJDK,
      ProviderType.SPONGY_CASTLE
    }
  )
  @Test
  public void testBiasAll() throws Exception {
    testBias("SHA256WithECDSA", "secp256r1", EcUtil.getNistP256Params());
    testBias("SHA224WithECDSA", "secp224r1", EcUtil.getNistP224Params());
    testBias("SHA384WithECDSA", "secp384r1", EcUtil.getNistP384Params());
    testBias("SHA512WithECDSA", "secp521r1", EcUtil.getNistP521Params());
    testBias("SHA256WithECDSA", "brainpoolP256r1", EcUtil.getBrainpoolP256r1Params());
  }

  /**
   * Tests for a potential timing attack. This test checks if there is a correlation between the
   * timing of signature generation and the size of the one-time key k. This is for example the case
   * if a double and add method is used for the point multiplication. The test fails if such a
   * correlation can be shown with high confidence. Further analysis will be necessary to determine
   * how easy it is to exploit the bias in a timing attack.
   */
  // TODO(bleichen): Determine if there are exploitable providers.
  //
  // SunEC currently fails this test. Since ECDSA typically is used with EC groups whose order
  // is 224 bits or larger, it is unclear whether the same attacks that apply to DSA are practical.
  //
  // The ECDSA implementation in BouncyCastle leaks information about k through timing too.
  // The test has not been optimized to detect this bias. It would require about 5'000'000 samples,
  // which is too much for a simple unit test.
  //
  // BouncyCastle uses FixedPointCombMultiplier for ECDSA. This is a method using
  // precomputation. The implementation is not constant time, since the precomputation table
  // contains the point at infinity and adding this point is faster than ordinary point additions.
  // The timing leak only has a small correlation to the size of k and at the moment it is is very
  // unclear if the can be exploited. (Randomizing the precomputation table by adding the same
  // random point to each element in the table and precomputing the necessary offset to undo the
  // precomputation seems much easier than analyzing this.)
  public void testTiming(String algorithm, String curve, ECParameterSpec ecParams)
      throws Exception {
    ThreadMXBean bean = ManagementFactory.getThreadMXBean();
    if (!bean.isCurrentThreadCpuTimeSupported()) {
      System.out.println("getCurrentThreadCpuTime is not supported. Skipping");
      return;
    }
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    try {
      keyGen.initialize(ecParams);
    } catch (InvalidAlgorithmParameterException ex) {
      System.out.println("This provider does not support curve:" + curve);
      return;
    }
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

    String message = "Hello";
    String hashAlgorithm = getHashAlgorithm(algorithm);
    byte[] messageBytes = message.getBytes("UTF-8");
    byte[] digest = MessageDigest.getInstance(hashAlgorithm).digest(messageBytes);
    BigInteger h = new BigInteger(1, digest);
    Signature signer = Signature.getInstance(algorithm);
    signer.initSign(priv);
    // The number of samples used for the test. This number is a bit low.
    // I.e. it just barely detects that SunEC leaks information about the size of k.
    int samples = 50000;
    long[] timing = new long[samples];
    BigInteger[] k = new BigInteger[samples];
    for (int i = 0; i < samples; i++) {
      long start = bean.getCurrentThreadCpuTime();
      signer.update(messageBytes);
      byte[] signature = signer.sign();
      timing[i] = bean.getCurrentThreadCpuTime() - start;
      k[i] = extractK(signature, h, priv);
    }
    long[] sorted = Arrays.copyOf(timing, timing.length);
    Arrays.sort(sorted);
    double n = priv.getParams().getOrder().doubleValue();
    double expectedAverage = n / 2;
    double maxSigma = 0;
    System.out.println("testTiming algorithm:" + algorithm);
    for (int idx = samples - 1; idx > 10; idx /= 2) {
      long cutoff = sorted[idx];
      int count = 0;
      BigInteger total = BigInteger.ZERO;
      for (int i = 0; i < samples; i++) {
        if (timing[i] <= cutoff) {
          total = total.add(k[i]);
          count += 1;
        }
      }
      double expectedStdDev = n / Math.sqrt(12 * count);
      double average = total.doubleValue() / count;
      // Number of standard deviations that the average is away from
      // the expected value:
      double sigmas = Math.abs(expectedAverage - average) / expectedStdDev;
      if (sigmas > maxSigma) {
        maxSigma = sigmas;
      }
      System.out.println(
          "count:"
              + count
              + " cutoff:"
              + cutoff
              + " relative average:"
              + (average / expectedAverage)
              + " sigmas:"
              + sigmas);
    }
    // Checks if the signatures with a small timing have a biased k.
    // We use 7 standard deviations, so that the probability of a false positive is smaller
    // than 10^{-10}.
    if (maxSigma >= 7) {
      fail("Signatures with short timing have a biased k");
    }
  }

  @SlowTest(
    providers = {
      ProviderType.BOUNCY_CASTLE,
      ProviderType.CONSCRYPT,
      ProviderType.OPENJDK,
      ProviderType.SPONGY_CASTLE
    }
  )
  @Test
  public void testTimingAll() throws Exception {
    testTiming("SHA256WithECDSA", "secp256r1", EcUtil.getNistP256Params());
    // TODO(bleichen): crypto libraries sometimes use optimized code for curves that are frequently
    //   used. Hence it would make sense to test distinct curves. But at the moment testing many
    //   curves is not practical since one test alone is already quite time consuming.
    // testTiming("SHA224WithECDSA", "secp224r1", EcUtil.getNistP224Params());
    // testTiming("SHA384WithECDSA", "secp384r1", EcUtil.getNistP384Params());
    // testTiming("SHA512WithECDSA", "secp521r1", EcUtil.getNistP521Params());
    // testTiming("SHA256WithECDSA", "brainpoolP256r1", EcUtil.getBrainpoolP256r1Params());
  }
}
