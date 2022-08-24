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

import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import java.lang.reflect.Constructor;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

// TODO(bleichen): Add more tests.
//   Add a test for passing null as random number generator.
//   https://github.com/bcgit/bc-java/pull/632:
//
//   Add a check for the randomization of RSAPSS./
//   Failing to properly randomize RSA-PSS signatures is not critical, but may reduce the
//   security of RSA-PSS signatures. (see e.g. RFC 8017, Section 8.1.

/**
 * Tests for RSA-PSS.
 */
@RunWith(JUnit4.class)
public class RsaPssTest {

  /**
   * Returns an AlgorithmParameterSpec for generating a RSASSA-PSS key,
   * which include the PSSParameters.
   * Requires jdk11.
   *
   * @param keySizeInBits the size of the modulus in bits.
   * @param sha the name of the hash function for hashing the input (e.g. "SHA-256")
   * @param mgf the name of the mask generating function (typically "MGF1")
   * @param mgfSha the name of the hash function for the mask generating function
   *        (typically the same as sha).
   * @param saltLength the length of the salt in bytes (typically the digest size of sha,
   *        i.e. 32 for "SHA-256")
   * @throws NoSuchMethodException if the AlgorithmParameterSpec is not
   *   supported (i.e. this happens before jdk11).
   */
  public RSAKeyGenParameterSpec getPssAlgorithmParameters(
      int keySizeInBits,
      String sha,
      String mgf,
      String mgfSha,
      int saltLength) throws Exception {
    BigInteger publicExponent = new BigInteger("65537");
    PSSParameterSpec params =
        new PSSParameterSpec(sha, mgf, new MGF1ParameterSpec(mgfSha), saltLength, 1);
    // Uses reflection to call
    // public RSAKeyGenParameterSpec(int keysize, BigInteger publicExponent,
    //        AlgorithmParameterSpec keyParams)
    // because this method is only supported in jdk11. This throws a NoSuchMethodException
    // for older jdks.
    Constructor<RSAKeyGenParameterSpec> c =
        RSAKeyGenParameterSpec.class.getConstructor(
            int.class, BigInteger.class, AlgorithmParameterSpec.class);
    return c.newInstance(keySizeInBits, publicExponent, params);
  }

  /**
   * Tries encoding and decoding of RSASSA-PSS keys generated with RSASSA-PSS.
   *
   * RSASSA-PSS keys contain the PSSParameters, hence their encodings are
   * somewhat different than plain RSA keys.
   */
  @NoPresubmitTest(
    providers = {ProviderType.OPENJDK},
    bugs = {"b/120406853"}
  )
  @Test
  public void testEncodeDecodePublic() throws Exception {
    int keySizeInBits = 2048;
    PublicKey pub;
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSASSA-PSS");
      keyGen.initialize(keySizeInBits);
      KeyPair keypair = keyGen.genKeyPair();
      pub = keypair.getPublic();
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("Key generation for RSASSA-PSS is not supported.");
      return;
    }
    byte[] encoded = pub.getEncoded();
    assertEquals(
        "The test assumes that the public key is in X.509 format", "X.509", pub.getFormat());
    System.out.println("Generated RSA-PSS key");
    System.out.println(TestUtil.bytesToHex(encoded));
    KeyFactory kf = KeyFactory.getInstance("RSASSA-PSS");
    X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
    kf.generatePublic(spec);

    // Tries to generate another pair or keys. This time the generator is given an
    // RSAKeyGenParameterSpec containing the key size an the PSS parameters.
    String sha = "SHA-256";
    String mgf = "MGF1";
    int saltLength = 20;
    try {
      RSAKeyGenParameterSpec params =
          getPssAlgorithmParameters(keySizeInBits, sha, mgf, sha, saltLength);
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSASSA-PSS");
      keyGen.initialize(params);
      KeyPair keypair = keyGen.genKeyPair();
      pub = keypair.getPublic();
    } catch (NoSuchAlgorithmException | NoSuchMethodException ex) {
      System.out.println("Key generation for RSASSA-PSS is not supported.");
      return;
    }
    byte[] encoded2 = pub.getEncoded();
    System.out.println("Generated RSA-PSS key with PSS parameters");
    System.out.println(TestUtil.bytesToHex(encoded2));
    X509EncodedKeySpec spec2 = new X509EncodedKeySpec(encoded2);
    kf.generatePublic(spec2);
  }

  /**
   * Tests the default parameters used for a given algorithm name.
   *
   * @param algorithm the algorithm name for an RSA-PSS instance. (e.g. "SHA256WithRSAandMGF1")
   * @param expectedHash the hash algorithm expected for the given algorithm
   * @param expectedMgf the mask generation function expected for the given algorithm (e.g. "MGF1")
   * @param expectedMgfHash the hash algorithm exptected for the mask generation function
   * @param expectedSaltLength the expected salt length in bytes for the given algorithm
   * @param expectedTrailerField the expected value for the tailer field (e.g. 1 for 0xbc).
   */
  protected void testDefaultForAlgorithm(
      String algorithm,
      String expectedHash,
      String expectedMgf,
      String expectedMgfHash,
      int expectedSaltLength,
      int expectedTrailerField) throws Exception {
    // An X509 encoded 2048-bit RSA public key.
    String pubKey =
        "30820122300d06092a864886f70d01010105000382010f003082010a02820101"
            + "00bdf90898577911c71c4d9520c5f75108548e8dfd389afdbf9c997769b8594e"
            + "7dc51c6a1b88d1670ec4bb03fa550ba6a13d02c430bfe88ae4e2075163017f4d"
            + "8926ce2e46e068e88962f38112fc2dbd033e84e648d4a816c0f5bd89cadba0b4"
            + "d6cac01832103061cbb704ebacd895def6cff9d988c5395f2169a6807207333d"
            + "569150d7f569f7ebf4718ddbfa2cdbde4d82a9d5d8caeb467f71bfc0099b0625"
            + "a59d2bad12e3ff48f2fd50867b89f5f876ce6c126ced25f28b1996ee21142235"
            + "fb3aef9fe58d9e4ef6e4922711a3bbcd8adcfe868481fd1aa9c13e5c658f5172"
            + "617204314665092b4d8dca1b05dc7f4ecd7578b61edeb949275be8751a5a1fab"
            + "c30203010001";
    KeyFactory kf;
    kf = KeyFactory.getInstance("RSA");
    X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(TestUtil.hexToBytes(pubKey));
    PublicKey key = kf.generatePublic(x509keySpec);
    Signature verifier;
    try {
      verifier = Signature.getInstance(algorithm);
      verifier.initVerify(key);
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("Unsupported algorithm:" + algorithm);
      return;
    }
    AlgorithmParameters params = verifier.getParameters();
    if (params == null) {
      // No defaults are specified. This is a good choice since this avoid
      // incompatible implementations.
      return;
    }
    PSSParameterSpec pssParams = params.getParameterSpec(PSSParameterSpec.class);
    assertEquals("digestAlgorithm", expectedHash, pssParams.getDigestAlgorithm());
    assertEquals("mgfAlgorithm", expectedMgf, pssParams.getMGFAlgorithm());
    assertEquals("saltLength", expectedSaltLength, pssParams.getSaltLength());
    assertEquals("trailerField", expectedTrailerField, pssParams.getTrailerField());
    if (expectedMgf.equals("MGF1")) {
      MGF1ParameterSpec mgf1Params = (MGF1ParameterSpec) pssParams.getMGFParameters();
      assertEquals("mgf1 digestAlgorithm", expectedMgfHash, mgf1Params.getDigestAlgorithm());
    }
  }

  /**
   * Tests the default values for PSS parameters.
   *
   * <p>RSA-PSS has a number of parameters. RFC 8017 specifies the parameters as follows:
   *
   * <pre>
   * RSASSA-PSS-params :: = SEQUENCE {
   *   hashAlgorithm            [0] HashAlgorithm     DEFAULT sha1,
   *   maskGenerationAlgorithm  [1] MaskGenAlgorithm  DEFAULT mgf1SHA1,
   *   saltLength               [2] INTEGER           DEFAULT 20,
   *   trailerField             [3] TrailerField      DEFAULT trailerFieldBC
   * }
   * </pre>
   *
   * <p>The algorithm name for RSA-PSS used in jdk11 is "RSASSA-PSS". Previously, the algorithm
   * names for RSA-PSS were defined in the section "Signature Algorithms" of
   * https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
   * I.e. the proposed standard names had the format <digest>with<encryption>and<mgf>, e.g.,
   * SHA256withRSAandMGF1. This name only specifies the hashAlgorithm and the mask generation
   * algorithm, but not the hash used for the mask generation algorithm, the salt length and
   * the trailerField. The missing parameters can be explicitly specified with and instance
   * of PSSParameterSpec. The test below checks that distinct providers use the same default values
   * when no PSSParameterSpec is given.
   *
   * <p>In particular, the test expects that the two hash algorithm (for message hashing and mgf)
   * are the same. It expects that the saltLength is the same as the size of the message digest.
   * It expects that the default for the trailerField is 1. These expectations are based on
   * existing implementations. They differ from the ASN defaults in RFC 8017.
   *
   * <p>There is no test for defaults for the algorithm name "RSASSA-PSS".
   * "RSASSA-PSS" does not specify any parameters. Using the default values from RFC 8017
   * (i.e. SHA-1 for both hashes) leads to potential weaknesses and hence is of course a bad
   * choice. Other defaults lead to incompatibilities and hence isn't a reasonable choice either.
   * jdk11 requires that the parameters are always specified. BouncyCastle however uses the SHA-1
   * default. The behaviour in jdk11 is preferable, since it requires that an implementor chooses
   * PSSParameters explicitly, and does not default to weak behaviour.
   */
  @Test
  public void testDefaults() throws Exception {
    testDefaultForAlgorithm("SHA1withRSAandMGF1", "SHA-1", "MGF1", "SHA-1", 20, 1);
    testDefaultForAlgorithm("SHA224withRSAandMGF1", "SHA-224", "MGF1", "SHA-224", 28, 1);
    testDefaultForAlgorithm("SHA256withRSAandMGF1", "SHA-256", "MGF1", "SHA-256", 32, 1);
    testDefaultForAlgorithm("SHA384withRSAandMGF1", "SHA-384", "MGF1", "SHA-384", 48, 1);
    testDefaultForAlgorithm("SHA512withRSAandMGF1", "SHA-512", "MGF1", "SHA-512", 64, 1);
    testDefaultForAlgorithm(
        "SHA512/224withRSAandMGF1", "SHA-512/224", "MGF1", "SHA-512/224", 28, 1);
    testDefaultForAlgorithm(
        "SHA512/256withRSAandMGF1", "SHA-512/256", "MGF1", "SHA-512/256", 32, 1);
    testDefaultForAlgorithm("SHA3-224withRSAandMGF1", "SHA3-224", "MGF1", "SHA3-224", 28, 1);
    testDefaultForAlgorithm("SHA3-256withRSAandMGF1", "SHA3-256", "MGF1", "SHA3-256", 32, 1);
    testDefaultForAlgorithm("SHA3-384withRSAandMGF1", "SHA3-384", "MGF1", "SHA3-384", 48, 1);
    testDefaultForAlgorithm("SHA3-512withRSAandMGF1", "SHA3-512", "MGF1", "SHA3-512", 64, 1);
  }
}

