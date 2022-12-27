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

// TODO(bleichen):
// - add tests for SHA1WithDSA with wrong key
// - add tests for "alternative" algorithm names
// - convert tests for deterministic DSA variants.
//   Deterministic DSA has a few new drawbacks:
//     * implementations flaws that generate k incorrectly can leak
//       the key if multiple implementations (e.g. one correct one incorrect)
//       is used.
//     * timing attacks are more serious if the attacker can ask for the same
//       signature multiple times, since this allows to get more accurate timings.
package com.google.security.wycheproof;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests DSA implementations.
 *
 * DSA was specified by NIST in the Digital Signature Standard (DSS).
 * However, the draft of FIPS 186-5 no longer approves DSA.
 *
 * The tests here mainly test key, parameter and signature generation.
 * Signature verification is mainly done with test vectors in JsonSignatureTest.java.
 *
 * @author bleichen@google.com (Daniel Bleichenbacher)
 */
@RunWith(JUnit4.class)
public class DsaTest {
  // Defines some DSA parameters to speed up the tests.
  // Some providers (e.g., BouncyCastle) generate new random DSA parameters
  // for each new key unless specified. Generating such parameters can take
  // a lot of time.
  private static final DSAParameterSpec DSA_PARAMS_1024 = new DSAParameterSpec(
        new BigInteger(
            "1106803511314772711673172950296693567629309594518393175860816428"
                + "6658764043763662129010863568011543182924292444458455864283745070"
                + "9908516713302345161980412667892373845670780253725557376379049862"
                + "4062950082444499320797079243439689601679418602390654466821968220"
                + "32212146727497041502702331623782703855119908989712161"),
        new BigInteger("974317976835659416858874959372334979171063697271"),
        new BigInteger(
            "1057342118316953575810387190942009018497979302261477972033090351"
                + "7561815639397594841480480197745063606756857212792356354588585967"
                + "3837265237205154744016475608524531648654928648461175919672511710"
                + "4878976887505840764543501512668232945506391524642105449699321960"
                + "32410302985148400531470153936516167243072120845392903"));

  private static final DSAParameterSpec DSA_PARAMS_2048 = new
      DSAParameterSpec(
          new BigInteger("3164061777193421244945967689185130966883791527930581656543940136"
             + "9851564103057893770550122576420376933644344013305735603610942719"
             + "0293352994823217443809706583073604061570104365238910634862640398"
             + "1679210161833377863606275689118136475272813790454847601448227296"
             + "1343536419929610738993809045350019003864284827404321049159705788"
             + "9549545448366098569990308459383369877789053024383489750444816799"
             + "7655021762159487052492596584201043454441595097537258007948592233"
             + "9750333178270807875426129993868319748210561432141824552116718686"
             + "0976690334031413657227645931573832903180613929329282084779414766"
             + "06239373677116746259950456018096483609849"),
         new BigInteger("1153325196737607230690138460423355902719413005219740664797410759"
             + "18190885248303"),
         new BigInteger("7143867109100500724655889012222798175962488212042071017782036283"
             + "2160817495693770539655258112318947749347515155155134204134719860"
             + "8823601342715098633684772359506724876037827905133950825065353901"
             + "6405352814524900241330050570097484028566246867839194943420499621"
             + "1140731561135100139686370478680923000451515444292933075274771723"
             + "2158242525416346441387350251926607224043098576684471584941118008"
             + "0093586361720527555676600988059377305427568792372489422765662230"
             + "0215335648878955714422647428480609353107064891801250653532699120"
             + "7943263490377529076378752274796636215661586231670013411198731440"
             + "2786085224329787545828730362102716455591"));

  // Extract the integer r from a DSA signature.
  // This method implicitely assumes that the DSA signature is DER encoded.
  BigInteger extractR(byte[] signature) {
    int lengthR = signature[3];
    return new BigInteger(Arrays.copyOfRange(signature, 4, 4 + lengthR));
  }

  BigInteger extractS(byte[] signature) {
    int lengthR = signature[3];
    int startS = 4 + lengthR;
    int lengthS = signature[startS + 1];
    return new BigInteger(Arrays.copyOfRange(signature, startS + 2, startS + 2 + lengthS));
  }

  /** Extract the k that was used to sign the signature. Validates the k if check == true. */
  BigInteger extractK(byte[] signature, BigInteger h, DSAPrivateKey priv, boolean check) {
    BigInteger x = priv.getX();
    BigInteger q = priv.getParams().getQ();
    BigInteger r = extractR(signature);
    BigInteger s = extractS(signature);
    BigInteger k = x.multiply(r).add(h).multiply(s.modInverse(q)).mod(q);
    if (check) {
      BigInteger p = priv.getParams().getP();
      BigInteger g = priv.getParams().getG();
      BigInteger r2 = g.modPow(k, p).mod(q);
      assertEquals(r.toString(), r2.toString());
    }
    return k;
  }

  /**
   * Returns a DSA key pair.
   *
   * @param the parameters p,q,g for DSA. Some provider generate new DSA parameters for each new
   *     key if these parameters are not provided. Hence, the tests are faster if they use a
   *     predefined parameter set.
   * @return a DSA key pair
   * @throws AssumptionViolatedException if no key pair could be generated. This skips the test.
   */
  KeyPair getDsaKeyPair(DSAParameterSpec params) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
      generator.initialize(params);
      return generator.generateKeyPair();
    } catch (GeneralSecurityException ex) {
      TestUtil.skipTest("Could not generate a DSA key pair");
      return null;
    }
  }

  /**
   * This is just a test for basic functionality of DSA. The test generates a public and private
   * key, generates a signature and verifies it. This test is slow with some providers, since
   * some providers generate new DSA parameters (p and q) for each new key.
   */
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testBasic() throws Exception {
    String algorithm = "SHA256WithDSA";
    String message = "Hello";
    byte[] messageBytes = message.getBytes(UTF_8);
    KeyPair keyPair = getDsaKeyPair(DSA_PARAMS_2048);
    Signature signer;
    Signature verifier;
    try {
      signer = Signature.getInstance(algorithm);
      verifier = Signature.getInstance(algorithm);
    } catch (GeneralSecurityException ex) {
      // Skips the test if DSA key generation, "SHA256WithDSA" or the key size are not supported.
      TestUtil.skipTest(ex.toString());
      return;
    }
    // If keygeneration, "SHA256WithDSA" and the key size are supported, then the test
    // expects that messages can be signed an verified.
    DSAPublicKey pub = (DSAPublicKey) keyPair.getPublic();
    DSAPrivateKey priv = (DSAPrivateKey) keyPair.getPrivate();
    signer.initSign(priv);
    signer.update(messageBytes);
    byte[] signature = signer.sign();
    verifier.initVerify(pub);
    verifier.update(messageBytes);
    assertTrue(verifier.verify(signature));
  }

  @SuppressWarnings("InsecureCryptoUsage")
  public void testKeyGeneration(int keySize) throws Exception {
    KeyPair keyPair;
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
      generator.initialize(keySize);
      keyPair = generator.generateKeyPair();
    } catch (GeneralSecurityException ex) {
      // Skips the test if DSA or the key size is not supported.
      TestUtil.skipTest(ex.toString());
      return;
    }
    DSAPrivateKey priv = (DSAPrivateKey) keyPair.getPrivate();
    DSAParams params = priv.getParams();
    assertEquals(keySize, params.getP().bitLength());
    // The NIST standard does not fully specify the size of q that
    // must be used for a given key size. Hence there are differences.
    // For example if keysize = 2048, then OpenSSL uses 256 bit q's by default,
    // but the SUN provider uses 224 bits. Both are acceptable sizes.
    // The tests below simply asserts that the size of q does not decrease the
    // overall security of the DSA.
    int qsize = params.getQ().bitLength();
    switch (keySize) {
      case 1024:
        assertTrue("Invalid qsize for 1024 bit key:" + qsize, qsize >= 160);
        break;
      case 2048:
        assertTrue("Invalid qsize for 2048 bit key:" + qsize, qsize >= 224);
        break;
      case 3072:
        assertTrue("Invalid qsize for 3072 bit key:" + qsize, qsize >= 256);
        break;
      case 4096:
        // FIPS 186-4 does not specify 4096 bit DSA keys.
        // But some libraries implement 4096 bit keys anyway. Hence the minimal
        // size for q is unclear. (Maybe 320 bits would be appropriate.)
        // Certainly a value q smaller than 256 bits should not be accepted.
        assertTrue("Invalid qsize for 4096 bit key:" + qsize, qsize >= 256);
        break;
      default:
        fail("Invalid key size:" + keySize);
    }
    // Check the length of the private key.
    // For example GPG4Browsers or the KJUR library derived from it use
    // q.bitCount() instead of q.bitLength() to determine the size of the private key
    // and hence would generate keys that are much too small.
    assertTrue(priv.getX().bitLength() >= qsize - 32);
  }

  /**
   * Tests the key generation for DSA.
   *
   * <p>Problems found:
   *
   * <ul>
   *   <li>CVE-2016-1000343 BouncyCastle before v.1.56 always generated DSA keys with a 160-bit q.
   * </ul>
   */
  @Test
  public void testKeyGeneration1024() throws Exception {
    testKeyGeneration(1024);
  }

  @Test
  public void testKeyGeneration2048() throws Exception {
    testKeyGeneration(2048);
  }

  /**
   * Checks the default key size used for DSA key generation.
   *
   * <p>This test uses NIST SP 800-57 part1 revision 4
   * http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf . Table 2 on page
   * 53 recommends a minimal key length of 2048 bits for new keys used up to the year 2030.
   *
   * <p>While smaller keys may still be used for legacy cases, we think that such a choice should
   * always be made by providing the desired key length during the initalization of the
   * KeyPairGenerator.
   *
   * <p>This test may fail with old jdk versions. Oracle has changed the default size for DSA keys
   * from 1024 bits to 2048 bits with https://bugs.java.com/bugdatabase/view_bug.do?bug_id=8184341 .
   */
  @Test
  public void testDefaultKeySize() {
    KeyPair keypair;
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
      keypair = keyGen.genKeyPair();
    } catch (GeneralSecurityException ex) {
      // Changing the default key size from 1024 bits to 2048 bits might be problematic for a
      // provider, since SHA1WithDSA is the default algorithm.
      // Hence, if a provider decides not to implement a default key size and requires that a user
      // has to initialize the KeyPairGenerator then this should be acceptable behaviour.
      System.out.println("Could not generate a key with default key size:" + ex.getMessage());
      return;
    }
    DSAPublicKey pub = (DSAPublicKey) keypair.getPublic();
    int keySizeInBits = pub.getParams().getP().bitLength();
    if (keySizeInBits < 2048) {
      fail("DSA default key size too small:" + keySizeInBits);
    }
  }

  /**
   * Checks whether the one time key k in DSA is biased. For example the SUN provider fell for this
   * test until April 2016.
   */
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testDsaBias() throws Exception {
    // q is close to 2/3 * 2^160.
    BigInteger q = DSA_PARAMS_1024.getQ();
    BigInteger p = DSA_PARAMS_1024.getP();
    BigInteger g = DSA_PARAMS_1024.getG();
    BigInteger x = new BigInteger("13706102843888006547723575730792302382646994436");

    DSAPrivateKey priv;
    Signature signer;
    try {
      KeyFactory kf = KeyFactory.getInstance("DSA");
      priv = (DSAPrivateKey) kf.generatePrivate(new DSAPrivateKeySpec(x, p, q, g));
      signer = Signature.getInstance("SHA1WithDSA");
    } catch (GeneralSecurityException ex) {
      TestUtil.skipTest(ex.toString());
      return;
    }

    // If we make TESTS tests with a fair coin then the probability that
    // either heads or tails appears less than MINCOUNT times is less than
    // 2^{-32}.
    // I.e. 2*sum(binomial(tests,i) for i in range(mincount))*2**32 < 2**tests
    // Therefore the test below is not expected to fail unless the generation
    // of the one time keys is indeed biased.
    final int tests = 1024;
    final int mincount = 410;

    String hashAlgorithm = "SHA";
    MessageDigest md;
    try {
      md = MessageDigest.getInstance(hashAlgorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest("SHA is not supported");
      return;
    }
    String message = "Hello";
    byte[] messageBytes = message.getBytes(UTF_8);
    byte[] digest = md.digest(messageBytes);
    BigInteger h = new BigInteger(1, digest);

    final BigInteger qHalf = q.shiftRight(1);
    signer.initSign(priv);
    int countLsb = 0; // count the number of k's with msb set
    int countMsb = 0; // count the number of k's with lsb set
    for (int i = 0; i < tests; i++) {
      signer.update(messageBytes);
      byte[] signature = signer.sign();
      BigInteger k = extractK(signature, h, priv, i < 10);
      if (k.testBit(0)) {
        countLsb++;
      }
      if (k.compareTo(qHalf) == 1) {
        countMsb++;
      }
    }
    if (countLsb < mincount || countLsb > tests - mincount) {
      fail("Bias detected in the least significant bit of k:" + countLsb);
    }
    if (countMsb < mincount || countMsb > tests - mincount) {
      fail("Bias detected in the most significant bit of k:" + countMsb);
    }
  }

  /**
   * Checks whether CVE-2016-0695 has been fixed. Before the April 2016 security update, the SUN
   * provider had a serious flaw that leaked the private key with about 3-5 signatures. In
   * particular, "Sha1WithDSA" always generated 160 bit k's independently of q. Unfortunately, it is
   * easily possible to use 2048 and 3072 bit DSA keys together with SHA1WithDSA. All a user has to
   * do is to use the algorithm name "DSA" instead of "SHA256WithDSA" rsp. "SHA224WithDSA".
   *
   * <p>An algorithm to extract the key from the signatures has been described for example in the
   * paper <a href="http://www.hpl.hp.com/techreports/1999/HPL-1999-90.pdf">Lattice Attacks on
   * Digital Signature Schemes</a> by N.A. Howgrave-Graham, N.P. Smart.
   *
   * <p>This bug is the same as US-CERT: VU # 940388: GnuPG generated ElGamal signatures that leaked
   * the private key.
   */
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testBiasSha1WithDSA() throws Exception {
    String hashAlgorithm = "SHA";
    String message = "Hello";
    byte[] messageBytes = message.getBytes(UTF_8);
    MessageDigest md;
    try {
      md = MessageDigest.getInstance(hashAlgorithm);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest("SHA is not supported");
      return;
    }
    byte[] digest = md.digest(messageBytes);
    BigInteger h = new BigInteger(1, digest);

    Signature signer;
    DSAPrivateKey priv;
    try {
      signer = Signature.getInstance("DSA");
      KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
      generator.initialize(DSA_PARAMS_2048);
      KeyPair keyPair = generator.generateKeyPair();
      priv = (DSAPrivateKey) keyPair.getPrivate();
      signer.initSign(priv);
    } catch (GeneralSecurityException ex) {
      // This is expected for a number of reasons:
      // (1) the algorithm name "DSA" is equivalend to "DSAWithSHA1" and hence should 
      //     not be used.
      // (2) SHA-1 has lower security than a 2048 bit key and hence should not be used.
      // (3) The provider simply no longer supports DSA.
      TestUtil.skipTest(ex.toString());
      return;
    }
    // Private key and selected algorithm by signer do not match.
    // Hence throwing an exception at this point would be the reasonable.
    signer.update(messageBytes);
    byte[] signature = signer.sign();
    BigInteger q = priv.getParams().getQ();
    BigInteger k = extractK(signature, h, priv, true);

    // Now check if k is heavily biased.
    int lengthDiff = q.bitLength() - k.bitLength();
    if (lengthDiff > 32) {
      fail(
            "Severly biased DSA signature:"
                + " len(q)="
                + q.bitLength()
                + " len(k)="
                + k.bitLength());
    }
  }

  /**
   * This test checks for potential of a timing attack. The test generates a number of signatures,
   * selects a fraction of them with a small timing and then compares the values k for the selected
   * signatures with a normal distribution. The test fails if these ks are much smaller than
   * expected. An implementation flaw that can lead to a test failure is to compute the signature
   * with a modular exponentiation with a runtime that depend on the length of the exponent.
   *
   * <p>A failing test simply means that the timing can be used to get information about k. Further
   * analysis is necessary to determine if the bias is exploitable and how many timings are
   * necessary for an attack. A passing test does not mean that the implementation is secure against
   * timing attacks. The test only catches relatively big timing differences. It requires high
   * confidence to fail. Noise on the test machine can prevent that a relation between timing and k
   * can be detected.
   *
   * <p>Claims of what is exploitable: http://www.hpl.hp.com/techreports/1999/HPL-1999-90.pdf 30
   * signatures are sufficient to find the private key if the attacker knows 8 bits of each k.
   * http://eprint.iacr.org/2004/277.pdf 27 signatures are sufficient if 8 bits of each k is known.
   * Our own old experiments (using 1GB memory on a Pentium-4? CPU): 2^11 signatures are sufficient
   * with a 3 bit leakage. 2^15 signatures are sufficient with a 2 bit leakage. 2^24 signatures are
   * sufficient with a 1 bit leakage. Estimate for biased generation in the NIST standard: e.g. 2^22
   * signatures, 2^40 memory, 2^64 time
   *
   * <p><b>Sample output for an old DSA version in OpenJDK8:</b>
   *
   * <pre>
   * count:50000 cutoff:4629300 relative average:0.9992225872624547 sigmas:0.3010906585642381
   * count:25000 cutoff:733961 relative average:0.976146066585879 sigmas:6.532668708070148
   * count:12500 cutoff:688305 relative average:0.9070352192339134 sigmas:18.00255238454385
   * count:6251 cutoff:673971 relative average:0.7747148791368986 sigmas:30.850903417893825
   * count:3125 cutoff:667045 relative average:0.5901994097874541 sigmas:39.67877152897901
   * count:1563 cutoff:662088 relative average:0.4060286694971057 sigmas:40.67294313795137
   * count:782 cutoff:657921 relative average:0.2577955312387898 sigmas:35.94906247333319
   * count:391 cutoff:653608 relative average:0.1453438859272699 sigmas:29.271192100879457
   * count:196 cutoff:649280 relative average:0.08035497211567771 sigmas:22.300206785132406
   * count:98 cutoff:645122 relative average:0.05063589092661368 sigmas:16.27820353139225
   * count:49 cutoff:641582 relative average:0.018255560447883384 sigmas:11.903018745467488
   * count:25 cutoff:638235 relative average:0.009082660721102722 sigmas:8.581595888660086
   * count:13 cutoff:633975 relative average:0.0067892346039088326 sigmas:6.20259924188633
   * </pre>
   *
   * <p><b>What this shows:</b> The first line uses all 50'000 signatures. The average k of these
   * signatures is close to the expected value q/2. Being more selective gives us signatures with a
   * more biased k. For example, the 196 signatures with the fastest timing have about a 3-bit bias.
   * From this we expect that 2^19 signatures and timings are sufficient to find the private key.
   *
   * <p>A list of problems caught by this test:
   *
   * <ul>
   *   <li>CVE-2016-5548 OpenJDK8's DSA is vulnerable to timing attacks.
   *   <li>CVE-2016-1000341 BouncyCastle before v 1.56 is vulnernerable to timing attacks.
   * </ul>
   */
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testTiming() throws Exception {
    ThreadMXBean bean = ManagementFactory.getThreadMXBean();
    if (!bean.isCurrentThreadCpuTimeSupported()) {
      TestUtil.skipTest("getCurrentThreadCpuTime is not supported. Skipping");
      return;
    }
    Signature signer;
    try {
      signer = Signature.getInstance("SHA1WITHDSA");
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest(ex.toString());
      return;
    }
    String hashAlgorithm = "SHA-1";
    String message = "Hello";
    byte[] messageBytes = message.getBytes(UTF_8);
    byte[] digest = MessageDigest.getInstance(hashAlgorithm).digest(messageBytes);
    BigInteger h = new BigInteger(1, digest);
    KeyPair keyPair;
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
      generator.initialize(DSA_PARAMS_1024);
      keyPair = generator.generateKeyPair();
    } catch (GeneralSecurityException ex) {
      TestUtil.skipTest(ex.toString());
      return;
    }
    DSAPrivateKey priv = (DSAPrivateKey) keyPair.getPrivate();
    signer.initSign(priv);
    // The timings below are quite noisy. Thus we need a large number of samples.
    int samples = 50000;
    long[] timing = new long[samples];
    BigInteger[] k = new BigInteger[samples];
    for (int i = 0; i < samples; i++) {
      long start = bean.getCurrentThreadCpuTime();
      signer.update(messageBytes);
      byte[] signature = signer.sign();
      timing[i] = bean.getCurrentThreadCpuTime() - start;
      k[i] = extractK(signature, h, priv, false);
    }
    long[] sorted = Arrays.copyOf(timing, timing.length);
    Arrays.sort(sorted);
    // Here we are only interested in roughly the 8 most significant bits of the ks.
    // Hence, using double is sufficiently precise.
    double q = priv.getParams().getQ().doubleValue();
    double expectedAverage = q / 2;
    double maxSigmas = 0;
    System.out.println("testTiming: SHA1WITHDSA");
    for (int idx = samples - 1; idx > 10; idx /= 2) {
      long cutoff = sorted[idx];
      int count = 0;
      double total = 0;
      for (int i = 0; i < samples; i++) {
        if (timing[i] <= cutoff) {
          total += k[i].doubleValue();
          count += 1;
        }
      }
      double expectedStdDev = q / Math.sqrt(12 * count);
      double average = total / count;
      // Number of standard deviations that the average is away from
      // the expected value:
      double sigmas = Math.abs(expectedAverage - average) / expectedStdDev;
      if (sigmas > maxSigmas) {
        maxSigmas = sigmas;
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
    if (maxSigmas >= 7) {
      fail("Signatures with short timing have a biased k");
    }
  }

  /**
   * DSA does not allow encryption. This test verifies that a provider does not implement an ad hoc
   * scheme that attempts to turn DSA into a public key encryption scheme.
   */
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testEncryptionWithDsa() throws Exception {
    try {
      Cipher cipher = Cipher.getInstance("DSA");
      fail("DSA must not be used as a cipher:" + cipher.getProvider().toString());
    } catch (NoSuchAlgorithmException ex) {
      // This is expected
    }
  }
}
