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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import com.google.security.wycheproof.WycheproofRunner.SlowTest;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
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
import java.util.HashSet;
import java.util.Locale;
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
    ecdsaAlgorithm = ecdsaAlgorithm.toUpperCase(Locale.ENGLISH);
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
   * Returns true if the signature scheme is deterministic. Even though a non-deterministic
   * signature scheme can in principle return the same signature twice this should never happen in
   * practice.
   *
   * @param signer an ECDSA instance
   * @param priv an ECDSA private key
   * @return true if the signer generates deterministic signatures
   * @throws AssumptionViolatedException if the signer failed to sign a message.
   */
  private boolean isDeterministic(Signature signer, ECPrivateKey priv) {
    byte[][] signature = new byte[2][];
    byte[] message = new byte[1];
    try {
      for (int i = 0; i < 2; i++) {
        signer.initSign(priv);
        signer.update(message);
        signature[i] = signer.sign();
      }
    } catch (GeneralSecurityException ex) {
      TestUtil.skipTest(ex.toString());
      return false;
    }
    return Arrays.equals(signature[0], signature[1]);
  }

  /**
   * Returns count messages to sign. If the signature scheme is deterministic then the messages are
   * all different. If the signature scheme is randomized then the messages are all the same. If the
   * messages signed are all the same then it may be easier to detect a bias.
   */
  private byte[][] getMessagesToSign(int count, boolean isDeterministic) {
    byte[][] messages = new byte[count][];
    if (isDeterministic) {
      for (int i = 0; i < count; i++) {
        messages[i] = ByteBuffer.allocate(4).putInt(i).array();
      }
    } else {
      byte[] msg = new byte[4];
      for (int i = 0; i < count; i++) {
        messages[i] = msg;
      }
    }
    return messages;
  }

  /**
   * Extract the integer r from an ECDSA signature. This method implicitely assumes that the ECDSA
   * signature is DER encoded and that the order of the curve is smaller than 2^1024.
   */
  BigInteger extractR(byte[] signature) {
    int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
    int lengthR = signature[startR + 1];
    return new BigInteger(Arrays.copyOfRange(signature, startR + 2, startR + 2 + lengthR));
  }

  /**
   * Extract the integer s from an ECDSA signature. This method implicitely assumes that the ECDSA
   * signature is DER encoded and that the order of the curve is smaller than 2^1024.
   */
  BigInteger extractS(byte[] signature) {
    int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
    int lengthR = signature[startR + 1];
    int startS = startR + 2 + lengthR;
    int lengthS = signature[startS + 1];
    return new BigInteger(Arrays.copyOfRange(signature, startS + 2, startS + 2 + lengthS));
  }

  /** Extract the k that was used to sign the signature. */
  BigInteger extractK(byte[] signature, byte[] digest, ECPrivateKey priv) {
    BigInteger h = new BigInteger(1, digest);
    BigInteger x = priv.getS();
    BigInteger n = priv.getParams().getOrder();
    int bitLengthOrder = n.bitLength();
    if (bitLengthOrder < digest.length * 8) {
      h = h.shiftRight(digest.length * 8 - bitLengthOrder);
    }
    BigInteger r = extractR(signature);
    BigInteger s = extractS(signature);
    BigInteger k = x.multiply(r).add(h).multiply(s.modInverse(n)).mod(n);
    return k;
  }

  /**
   * Computes the bias of samples as
   *
   * <p>abs(sum(e^(2 pi i s m / modulus) for s in samples) / sqrt(samples.length).
   *
   * <p>If the samples are taken from a uniform distribution in the range 0 .. modulus - 1 and the
   * number of samples is significantly larger than L^2 then the probability that the result is
   * larger than L is approximately e^(-L^2). The approximation can be derived from the assumption
   * that samples taken from a uniform distribution give a result that approximates a standard
   * complex normal distribution Z. I.e. Z has a density f_Z(z) = exp(-abs(z)^2) / pi.
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
   */
  void testParameters(String algorithm, String curve) {
    KeyPair keyPair;
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
      keyGen.initialize(new ECGenParameterSpec(curve));
      keyPair = keyGen.generateKeyPair();
    } catch (GeneralSecurityException ex) {
      // The curve is not supported.
      // The documentation does not specify whether the method initialize
      // has to reject unsupported curves or if only generateKeyPair checks
      // whether the curve is supported.
      TestUtil.skipTest("Could not generate an EC key pair");
      return;
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
      TestUtil.skipTest("Algorithm not supported: " + algorithm);
      return;
    }
    // Both the ECDSA algorithm and key generation for the curve are supported.
    // Hence, we now expect that signing and verifyig works. Exceptions below
    // are test failures.
    String message = "123400";
    byte[] messageBytes = message.getBytes(UTF_8);
    byte[] signature;
    try {
      signer.initSign(priv);
      signer.update(messageBytes);
      signature = signer.sign();
      verifier.initVerify(pub);
      verifier.update(messageBytes);
      assertTrue(verifier.verify(signature));
    } catch (GeneralSecurityException ex) {
      throw new AssertionError("Provider can not sign and verify with its own keys: ", ex);
    }
  }

  /**
   * This test checks the basic functionality of ECDSA. This mainly checks that the provider follows
   * the JCA interface.
   */
  @Test
  public void testBasic() {
    String algorithm = "SHA256WithECDSA";
    String curve = "secp256r1";
    testParameters(algorithm, curve);
  }

  /**
   * This test check ECDSA with constructed parameters.
   *
   * <p>Typically, implementations specify the ECParameters using a curve name such as <code>
   * new ECGenParameterSpec("secp256r1")</code>. Hence the name of the the curve must be known to
   * the provider. It is also possible to specify the parameters explicitly. Using explicitly
   * constructed parameters should be regarded as a fall back for uncommon curves. Some providers
   * (e.g., BouncyCastle or Conscrypt) allow such operations.
   *
   * @param algorithm the algorithm to test (e.g. "SHA256WithECDSA")
   * @param curve the curve to test (e.g. "secp256r1")
   */
  void testEcdsaConstructed(String algorithm, String curve) {
    KeyPair keyPair;
    ECParameterSpec spec;
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
      spec = EcUtil.getCurveSpecConstructed(curve);
      keyGen.initialize(spec);
      keyPair = keyGen.generateKeyPair();
    } catch (GeneralSecurityException ex) {
      // The curve is not supported.
      // The documentation does not specify whether the method initialize
      // has to reject unsupported curves or if only generateKeyPair checks
      // whether the curve is supported.
      TestUtil.skipTest("Could not generate an EC key pair");
      return;
    }
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    Signature signer;
    Signature verifier;
    try {
      signer = Signature.getInstance(algorithm);
      verifier = Signature.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest("Algorithm not supported: " + algorithm);
      return;
    }
    try {
      signer.initSign(priv);
    } catch (GeneralSecurityException ex) {
      TestUtil.skipTest("Parameters are not supported:" + ex);
    }
    // Both the ECDSA algorithm and key generation for the curve are supported.
    // Hence, we now expect that signing and verifyig works. Exceptions below
    // are test failures.
    String message = "123400";
    byte[] messageBytes = message.getBytes(UTF_8);
    byte[] signature;
    try {
      signer.update(messageBytes);
      signature = signer.sign();
      verifier.initVerify(pub);
      verifier.update(messageBytes);
      assertTrue(verifier.verify(signature));
    } catch (GeneralSecurityException ex) {
      throw new AssertionError("Provider can not sign and verify with its own keys: ", ex);
    }
  }

  @Test
  public void testEcdsaConstructedSecp256r1() {
    testEcdsaConstructed("SHA256WithECDSA", "secp256r1");
  }

  @Test
  public void testEcdsaConstructedSecp256k1() {
    testEcdsaConstructed("SHA56WithECDSA", "secp256k1");
  }

  /**
   * secp224r1 is a rather popular curve that was removed in jdk
   * https://bugs.openjdk.org/browse/JDK-8235710
   */
  @Test
  public void testEcdsaConstructedSecp224r1() {
    testEcdsaConstructed("SHA224WithECDSA", "secp224r1");
  }

  /**
   * prime239v1 is the default curve for EC key generation in BouncyCastle (at least up to version
   * 1.71)
   */
  @Test
  public void testEcdsaConstructedPrime239v1() {
    testEcdsaConstructed("SHA256WithECDSA", "X9.62 prime239v1");
  }

  /**
   * BrainpoolP256r1 is one of the curves allowed in NIST SP 800-186 (draft) for interoperability.
   */
  @Test
  public void testEcdsaConstructedBrainpoolP256r1() {
    testEcdsaConstructed("SHA256WithECDSA", "brainpoolP256r1");
  }

  /** FRP256v1 is a curve that is rarely implemented. */
  @Test
  public void testEcdsaConstructedFRP256v1() {
    testEcdsaConstructed("SHA256WithECDSA", "FRP256v1");
  }

  /**
   * Checks whether the one time key k in ECDSA is biased.
   *
   * @param algorithm the ECDSA algorithm (e.g. "SHA256WithECDSA")
   * @param curve the curve (e.g. "secp256r1")
   * @throws AssumptionViolatedException if the test was skipped (e.g., because the curve is not
   *     supported)
   * @throws AssertionError if the test failed (i.e. there is a detectable bias)
   * @throws GeneralSecurityException if the signature generation failed. This may indicate a bug in
   *     the test or an unusual provider configuration.
   */
  public void testBias(String algorithm, String curve) {
    String hashAlgorithm = getHashAlgorithm(algorithm);
    MessageDigest md;
    Signature signer;
    try {
      md = MessageDigest.getInstance(hashAlgorithm);
      signer = Signature.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest(ex.toString());
      return;
    }
    KeyPair keyPair;
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
      keyGen.initialize(new ECGenParameterSpec(curve));
      keyPair = keyGen.generateKeyPair();
    } catch (GeneralSecurityException ex) {
      TestUtil.skipTest(curve + " is not supported.");
      return;
    }
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    boolean deterministic = isDeterministic(signer, priv);

    // If we throw a fair coin tests times then the probability that
    // either heads or tails appears less than mincount is less than 2^{-32}.
    // Therefore the test below is not expected to fail unless the generation
    // of the one time keys is indeed biased. E.g., the following values might
    // be used:
    // tests | mincount
    // ------+---------
    //  1024 |  410     catches brainpoolP256r1 using a 256 bit random number mod n
    //  2048 |  880     catches brainpoolP320r1 using a 320 bit random number mod n
    // 10000 | 4682
    // 20000 | 9551
    final int tests = 2048;
    final int mincount = 880;
    BigInteger[] kList = new BigInteger[tests];
    byte[][] message = getMessagesToSign(tests, deterministic);
    try {
      signer.initSign(priv);
      for (int i = 0; i < tests; i++) {
        signer.update(message[i]);
        byte[] digest = md.digest(message[i]);
        byte[] signature = signer.sign();
        kList[i] = extractK(signature, digest, priv);
      }
    } catch (GeneralSecurityException ex) {
      TestUtil.skipTest("Could not sign messages");
      return;
    }

    // Checks whether the most significant bits and the least significant bits
    // of the value k are unbiased.
    int countMsb = 0; // count the number of k's with lsb set
    int countLsb = 0; // count the number of k's with msb set
    BigInteger q = priv.getParams().getOrder();
    BigInteger qHalf = q.shiftRight(1);
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

    // A large number of weak random number generators can be detected by finding
    // a multiplier m, such that the values k[i]*m mod q are biased.
    // Such multipliers can be found using the LLL algorithm.
    //
    // Since we don't have an efficient implementation of LLL, only
    // some known LCGs are being tested here using precomputed constants
    // from project paranoid_crypto.
    // Multiplying k by one of these constants gives a biased result if
    // the corresponding weak random number generator was being used.
    if (curve.equals("secp256r1")) {
      for (String lcgConstant :
          new String[] {
            "300020001fff9fffd00090005fff8fffe36b469d49b2b1b86b409",
            "b0000bff4faff3f3b04f6c0cffb0a0a2d1db2882d6b85954f5ac2e9",
            "23afffffd7e00000277fffffc27000003da57311c6b4d9f1005e6d47f57",
            "4b088666fcf77998f4a6b827d661ce3f24af75fa42ec07381c0e34f360",
            "9beac7904fb495c58ca26a3af3cb3c4e0ca65224fb9a88b4073ddece0dbf",
            "1fdaf45d2f75fb5db16f94a2648fcdf6f9c93aa8785530b393470aab86f0",
            "1000000010001fffefffe0003010400ffbbe4faae22e90cb0364457"
          }) {
        BigInteger multiplier = new BigInteger(lcgConstant, 16);
        double bias5 = bias(kList, q, multiplier);
        if (bias5 > threshold) {
          fail("Bias for k detected. multiplier = " + lcgConstant + " bias5 = " + bias5);
        }
      }
    }
  }

  @Test
  public void testBiasSecp224r1() {
    testBias("SHA224WithECDSA", "secp224r1");
  }

  @Test
  public void testBiasSecp256r1() {
    testBias("SHA256WithECDSA", "secp256r1");
  }

  @Test
  public void testBiasSecp256k1() {
    testBias("SHA256WithECDSA", "secp256k1");
  }

  @Test
  public void testBiasSecp384r1() {
    testBias("SHA384WithECDSA", "secp384r1");
  }

  @Test
  public void testBiasSecp521r1() {
    testBias("SHA512WithECDSA", "secp521r1");
  }

  @Test
  public void testBiasBrainpoolP256r1() {
    testBias("SHA256WithECDSA", "brainpoolP256r1");
  }

  @Test
  public void testBiasBrainpoolP320r1() {
    testBias("SHA384WithECDSA", "brainpoolP320r1");
  }

  @Test
  public void testBiasPrime239v1() {
    testBias("SHA256WithECDSA", "X9.62 prime239v1");
  }

  /**
   * This test uses the deterministic ECDSA implementation from BouncyCastle (if BouncyCastle is
   * being tested.)
   */
  @Test
  public void testBiasSecp256r1ECDDSA() {
    testBias("SHA256WithECDDSA", "secp256r1");
  }


  /**
   * Tests initSign with a null value for SecureRandom. The expected behaviour is that a default
   * instance of SecureRandom is used and that this instance is properly seeded. I.e., the expected
   * behaviour is that Signature.initSign(ECPrivateKey, null) behaves like
   * Signature.initSign(ECPrivateKey). If the signature scheme normally is randomized then
   * Signature.initSign(ECprivateKey, null) should still be a randomized signature scheme. If the
   * implementation is deterministic then we simply want this to work.
   *
   * <p>In principle, the correct behaviour is not really defined. However, if a provider would
   * throw a null pointer exception then this can lead to unnecessary breakages.
   */
  public void testNullRandom(String algorithm, String curve) throws GeneralSecurityException {
    int samples = 8;
    Signature signer;
    try {
      signer = Signature.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest(algorithm + " is not supported.");
      return;
    }
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    KeyPair keyPair;
    try {
      keyGen.initialize(new ECGenParameterSpec(curve));
      keyPair = keyGen.generateKeyPair();
    } catch (InvalidAlgorithmParameterException ex) {
      TestUtil.skipTest(curve + " is not supported.");
      return;
    }
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    boolean deterministic = isDeterministic(signer, priv);
    byte[][] message = getMessagesToSign(samples, deterministic);
    HashSet<BigInteger> rSet = new HashSet<>();
    for (int i = 0; i < samples; i++) {
      // This is the function call that is tested by this test.
      try {
        signer.initSign(priv, null);
      } catch (NullPointerException ex) {
        throw new AssertionError("Expecting same behavior as signer.initSign(priv).", ex);
      }
      signer.update(message[i]);
      byte[] signature = signer.sign();
      BigInteger r = extractR(signature);
      assertTrue("Same r computed twice", rSet.add(r));
    }
  }

  @Test
  public void testNullRandomSecp224r1() throws GeneralSecurityException {
    testNullRandom("SHA224WithECDSA", "secp224r1");
  }

  @Test
  public void testNullRandomSecp256r1() throws GeneralSecurityException {
    testNullRandom("SHA256WithECDSA", "secp256r1");
  }

  @Test
  public void testNullRandomSecp384r1() throws GeneralSecurityException {
    testNullRandom("SHA384WithECDSA", "secp384r1");
  }

  @Test
  public void testNullRandomSecp521r1() throws GeneralSecurityException {
    testNullRandom("SHA512WithECDSA", "secp521r1");
  }

  /**
   * This test uses the deterministic ECDSA implementation from BouncyCastle (if BouncyCastle is
   * being tested.)
   */
  @Test
  public void testNullRandomSecp256r1ECDDSA() throws GeneralSecurityException {
    testNullRandom("SHA256WithECdDSA", "secp256r1");
  }

  /**
   * Tests for a potential timing attack. This test checks if there is a correlation between the
   * timing of signature generation and the size of the one-time key k. This is for example the case
   * if a double and add method is used for the point multiplication. The test fails if such a
   * correlation can be shown with high confidence. Further analysis will be necessary to determine
   * how easy it is to exploit the bias in a timing attack.
   *
   * <p>Here is a sample output of the test with 50000 samples:
   *
   * <pre>
   * count:50000 cutoff:5744550 relative average:0.9999801257112492 sigmas:0.007697278934955135
   * count:25065 cutoff:32830 relative average:1.0029020006432898 sigmas:0.7957781057129883
   * count:12519 cutoff:30720 relative average:1.0084868898996626 sigmas:1.6447277320112836
   * count:6256 cutoff:25560 relative average:1.0062130456106806 sigmas:0.8511645730122522
   * count:3152 cutoff:24000 relative average:1.0024398764372342 sigmas:0.23725838216162265
   * count:1580 cutoff:23610 relative average:0.9810427775608972 sigmas:1.305160365453478
   * count:794 cutoff:23420 relative average:0.9621892273223172 sigmas:1.8453826409748946
   * count:393 cutoff:23270 relative average:0.9648083036843184 sigmas:1.2083621237895195
   * count:206 cutoff:23140 relative average:0.924059403692487 sigmas:1.8878532876100647
   * count:102 cutoff:23010 relative average:0.8187632251385242 sigmas:3.1703487473825205
   * count:51 cutoff:22910 relative average:0.9015290921565392 sigmas:1.2180178622671547
   * count:25 cutoff:22770 relative average:0.9542895106949734 sigmas:0.3958644495756995
   * count:13 cutoff:22650 relative average:1.0086254921887976 sigmas:0.053866181454242705
   * </pre>
   *
   * count indicates the number of fastest signatures that were used for each computation cutoff is
   * the maximal time of the set of fastest signatures. relative average is the average of the
   * values k compared to the expected average n/2. sigmas: is the number of standard deviation that
   * the relative average is away from n/2. The output above has a value 3.2 for the 102 fastest
   * signatures. This is an event that happens with probability 0.2% if the k's are unbiased. Since
   * the tests are designed to be run as unit tests (i.e. frequently) this probability is not small
   * enough to fail the test. Rather the test requires a value deviating by 7 standard deviations
   * before it fails.
   *
   * @param algorithm the algorithm to test (e.g. "SHA256WithECDSA")
   * @param curve the curve to test (e.g. "secp256r1")
   * @throws AssumptionViolatedException if the algorithm or curve is not supported and the test was
   *     skipped.
   * @throws AssertionError if a significant timing different has been detected
   * @throws GeneralSecurityException if signing failed. This is either an error in the test itself
   *     or a unusual provider.
   */
  public void testTiming(String algorithm, String curve) throws GeneralSecurityException {
    ThreadMXBean bean = ManagementFactory.getThreadMXBean();
    if (!bean.isCurrentThreadCpuTimeSupported()) {
      TestUtil.skipTest("getCurrentThreadCpuTime is not supported. Skipping");
      return;
    }
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    try {
      keyGen.initialize(new ECGenParameterSpec(curve));
    } catch (InvalidAlgorithmParameterException ex) {
      TestUtil.skipTest("This provider does not support curve:" + curve);
      return;
    }
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

    MessageDigest md;
    Signature signer;
    String hashAlgorithm = getHashAlgorithm(algorithm);
    try {
      md = MessageDigest.getInstance(hashAlgorithm);
      signer = Signature.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest(ex.toString());
      return;
    }
    // The number of samples used for the test. This number is a bit low.
    // In a typical somewhat noisy test environment it usually just barely detects
    // if the timing depends on the bit length of k.
    int samples = 50000;
    long[] timing = new long[samples];
    // The test depends on whether the implementation is deterministic or not,
    // since it tries to find a correlation between the timing and k.
    // If a deterministic signature generation such as RFC 6979 is used then
    // distinct messages need to be signed, to get distinct values for k.
    // If the signature generation is randomized then the same message is
    // signed multiple times.
    boolean deterministic = isDeterministic(signer, priv);
    byte[][] message = getMessagesToSign(samples, deterministic);
    BigInteger[] k = new BigInteger[samples];
    try {
      signer.initSign(priv);
      for (int i = 0; i < samples; i++) {
        signer.update(message[i]);
        long start = bean.getCurrentThreadCpuTime();
        byte[] signature = signer.sign();
        timing[i] = bean.getCurrentThreadCpuTime() - start;
        byte[] digest = md.digest(message[i]);
        k[i] = extractK(signature, digest, priv);
      }
    } catch (GeneralSecurityException ex) {
      TestUtil.skipTest("Could not generate signatures");
      return;
    }
    long[] sorted = Arrays.copyOf(timing, timing.length);
    Arrays.sort(sorted);
    double n = priv.getParams().getOrder().doubleValue();
    double expectedAverage = n / 2;
    double maxSigma = 0;
    System.out.println("testTiming algorithm:" + algorithm);
    if (deterministic) {
      System.out.println("signer is deterministic");
    }
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

  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testTimingSecp256r1() throws GeneralSecurityException {
    testTiming("SHA256WithECDSA", "secp256r1");
  }

  /**
   * Timing test for brainpoolP256r1.
   *
   * <p>Crypto libraries sometimes use optimized code for curves that are frequently used such as
   * secp256r1. Infrequently used curves such as brainpool256r1 on the other hand might use general
   * purpose code. Hence, it is feasible that a library has no measurable timing differences for one
   * curve, but is less careful about other curves.
   */
  @SlowTest(providers = {ProviderType.ALL})
  @Test
  public void testTimingBrainpoolP256r1() throws GeneralSecurityException {
    testTiming("SHA256WithECDSA", "brainpoolP256r1");
  }
}
