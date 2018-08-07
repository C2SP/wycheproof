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
import static org.junit.Assert.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for RSA-PSS.
 */
@RunWith(JUnit4.class)
public class RsaPssTest {

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
   * <p>The standard algorithm names for RSA-PSS are defined in the section "Signature Algorithms"
   * of https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
   * I.e. the standard names have the format <digest>with<encryption>and<mgf>, e.g.,
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
   */
  @Test
  public void testDefaults() throws Exception {
    testDefaultForAlgorithm("SHA1withRSAandMGF1", "SHA-1", "MGF1", "SHA-1", 20, 1);
    testDefaultForAlgorithm("SHA224withRSAandMGF1", "SHA-224", "MGF1", "SHA-224", 28, 1);
    testDefaultForAlgorithm("SHA256withRSAandMGF1", "SHA-256", "MGF1", "SHA-256", 32, 1);
    testDefaultForAlgorithm("SHA384withRSAandMGF1", "SHA-384", "MGF1", "SHA-384", 48, 1);
    testDefaultForAlgorithm("SHA512withRSAandMGF1", "SHA-512", "MGF1", "SHA-512", 64, 1);
    testDefaultForAlgorithm("SHA512/224withRSAandMGF1", "SHA-512", "MGF1", "SHA-512", 28, 1);
    testDefaultForAlgorithm("SHA512/256withRSAandMGF1", "SHA-512", "MGF1", "SHA-512", 32, 1);
    testDefaultForAlgorithm("SHA3-224withRSAandMGF1", "SHA3-224", "MGF1", "SHA3-224", 28, 1);
    testDefaultForAlgorithm("SHA3-256withRSAandMGF1", "SHA3-256", "MGF1", "SHA3-256", 32, 1);
    testDefaultForAlgorithm("SHA3-384withRSAandMGF1", "SHA3-384", "MGF1", "SHA3-384", 48, 1);
    testDefaultForAlgorithm("SHA3-512withRSAandMGF1", "SHA3-512", "MGF1", "SHA3-512", 64, 1);
  }
    
  /** Convenience mehtod to get a String from a JsonObject */
  protected static String getString(JsonObject object, String name) throws Exception {
    return object.get(name).getAsString();
  }

  /** Convenience method to get a byte array from a JsonObject */
  protected static byte[] getBytes(JsonObject object, String name) throws Exception {
    return JsonUtil.asByteArray(object.get(name));
  }

  /**
   * Returns the algorithm name for the RSA-PSS signature scheme.
   * algorithm names used in JCA are a bit inconsequential. E.g. a dash is necessary for message
   * digests (e.g. "SHA-256") but are not used in the corresponding names for digital signatures
   * (e.g. "SHA256WITHRSAandMGF1").
   *
   * <p>See http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
   *
   * @param group A json dictionary containing a field "sha" with message digest (e.g. "SHA-256")
   *              and the a field "mgf" for the mask generation function (e.g. "MGF1").
   * @return the algorithm name for the signature scheme with the given hash.
   */
  protected static String getAlgorithmName(JsonObject group) throws Exception {
    String md = getString(group, "sha");
    String mgf = getString(group, "mgf");
    if (md.equals("SHA-1")) {
      md = "SHA1";
    } else if (md.equals("SHA-224")) {
      md = "SHA224";
    } else if (md.equals("SHA-256")) {
      md = "SHA256";
    } else if (md.equals("SHA-384")) {
      md = "SHA384";
    } else if (md.equals("SHA-512")) {
      md = "SHA512";
    }
    return md + "WITHRSAand" + mgf;
  }

  /**
   * Get a PublicKey from a JsonObject.
   *
   * <p>object contains the key in multiple formats: "key" : elements of the public key "keyDer":
   * the key in ASN encoding encoded hexadecimal "keyPem": the key in Pem format encoded hexadecimal
   * The test can use the format that is most convenient.
   */
  protected static PublicKey getPublicKey(JsonObject object) throws Exception {
    KeyFactory kf;
    kf = KeyFactory.getInstance("RSA");
    byte[] encoded = TestUtil.hexToBytes(getString(object, "keyDer"));
    X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(encoded);
    return kf.generatePublic(x509keySpec);
  }

  protected static PSSParameterSpec getPSSParams(JsonObject group) throws Exception {
    String mgf = getString(group, "mgf");
    String mgfSha = getString(group, "mgfSha");
    int saltLen = group.get("sLen").getAsInt();
    return new PSSParameterSpec(mgfSha, mgf, new MGF1ParameterSpec(mgfSha), saltLen, 1);
  }

  /** 
   * Tests the signature verification with test vectors in a given JSON file.
   *
   * <p> Example format for test vectors
   * {
   *   "algorithm" : "RSASSA-PSS",
   *   "generatorVersion" : "0.4.12",
   *   "numberOfTests" : 37,
   *   "header" : [],
   *   "testGroups" : [
   *     {
   *       "e" : "10001",
   *       "keyAsn" : "3082010a02820101...",
   *       "keyDer" : "30820122300d0609...",
   *       "keyPem" : "-----BEGIN PUBLIC KEY-----\n...",
   *       "keysize" : 2048,
   *       "mgf" : "MGF1",
   *       "mgfSha" : "SHA-256",
   *       "n" : "0a2b451a07d0aa5f...",
   *       "saltLen" : 20,
   *       "sha" : "SHA-256",
   *       "type" : "RSASigVer",
   *       "tests" : [
   *         {
   *           "tcId" : 1,
   *           "comment" : "",
   *           "msg" : "313133343030",
   *           "sig" : "577dfef111ae9a39..."
   *           "result" : "valid",
   *           "flags" : []
   *         },
   *        ...
   *
   * @param filename the filename of the test vectors
   * @param allowSkippingKeys if true then keys that cannot be constructed will not fail the test.
   *     This is for example used for files with test vectors that use elliptic curves that are not
   *     commonly supported.
   **/
  public void testRsaPss(String filename, boolean allowSkippingKeys)
      throws Exception {
    // Testing with old test vectors may be a reason for a test failure.
    // Generally mismatched version numbers are of little or no concern, since
    // the test vector version change much more frequently than the format.
    //
    // Version numbers have the format major.minor[status].
    // Versions before 1.0 are experimental and  use formats that are expected to change.
    // Versions after 1.0 change the major number if the format changes and change
    // the minor number if only the test vectors (but not the format) changes.
    // Versions meant for distribution have no status.
    final String expectedVersion = "0.5";
    JsonObject test = JsonUtil.getTestVectors(filename); 
    String generatorVersion = getString(test, "generatorVersion");
    if (!generatorVersion.equals(expectedVersion)) {
      System.out.println(
          "Expecting test vectors with version "
              + expectedVersion
              + " found vectors with version "
              + generatorVersion);
    }
    int numTests = test.get("numberOfTests").getAsInt();
    int cntTests = 0;
    int errors = 0;
    int skippedKeys = 0;
    Set<String> skippedAlgorithms = new HashSet<String>();
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      String algorithm = getAlgorithmName(group);
      PublicKey key = null;
      Signature verifier = null;
      try {
        key = getPublicKey(group);
        PSSParameterSpec pssParams = getPSSParams(group);
        verifier = Signature.getInstance(algorithm);
        verifier.setParameter(pssParams);
      } catch (GeneralSecurityException ex) {
        if (allowSkippingKeys) {
          skippedKeys++;
          skippedAlgorithms.add(algorithm);
        } else {
          System.out.println("Failed to generate verifier for " + algorithm);
          errors++;
        }
        continue;
      }
      for (JsonElement t : group.getAsJsonArray("tests")) {
        cntTests++;
        JsonObject testcase = t.getAsJsonObject();
        byte[] message = getBytes(testcase, "msg");
        byte[] signature = getBytes(testcase, "sig");
        int tcid = testcase.get("tcId").getAsInt();
        String sig = TestUtil.bytesToHex(signature);
        String result = getString(testcase, "result");
        verifier.initVerify(key);
        verifier.update(message);
        boolean verified = false;
        try {
          verified = verifier.verify(signature);
        } catch (SignatureException ex) {
          // verify can throw SignatureExceptions if the signature is malformed.
          // We don't flag these cases and simply consider the signature as invalid.
          verified = false;
        } catch (Exception ex) {
          // Other exceptions (i.e. unchecked exceptions) are considered as error
          // since a third party should never be able to cause such exceptions.
          System.out.println(
              "Signature verification throws "
                  + ex.toString()
                  + " "
                  + filename
                  + " tcId:"
                  + tcid
                  + " sig:"
                  + sig);
          verified = false;
          errors++;
        }
        if (!verified && result.equals("valid")) {
          System.out.println(
              "Valid signature not verified. "
                  + filename
                  + " tcId:"
                  + tcid
                  + " sig:"
                  + sig);
          errors++;
        } else if (verified && result.equals("invalid")) {
          System.out.println(
              "Invalid signature verified. "
                  + filename
                  + " tcId:"
                  + tcid
                  + " sig:"
                  + sig);
          errors++;
        }
      }
    }
    System.out.println("Number of skipped keys:" + skippedKeys);
    for (String s : skippedAlgorithms) {
      System.out.println("Skipped algorithms " + s);
    }
    assertEquals(0, errors);
    if (skippedKeys == 0) {
      assertEquals(numTests, cntTests);
    } else {
      assertTrue(allowSkippingKeys);
    }
  }

  @Test
  public void testRsaPss2048Sha256() throws Exception {
    testRsaPss("rsa_pss_2048_sha256_mgf1_32_test.json", false);
  }

  @NoPresubmitTest(
    providers = {ProviderType.BOUNCY_CASTLE},
    bugs = {"b/111634359"}
  )
  @Test
  public void testRsaPss3072Sha256() throws Exception {
    testRsaPss("rsa_pss_3072_sha256_mgf1_32_test.json", false);
  }

  @Test
  public void testRsaPss4096Sha256() throws Exception {
    testRsaPss("rsa_pss_4096_sha256_mgf1_32_test.json", false);
  }

  @Test
  public void testRsaPss4096Sha512() throws Exception {
    testRsaPss("rsa_pss_4096_sha512_mgf1_32_test.json", false);
  }

  @Test
  public void testRsaPss2048Sha256NoSalt() throws Exception {
    testRsaPss("rsa_pss_2048_sha256_mgf1_0_test.json", false);
  }

  /**
   * Checks RSA-PSS with various combinations of hashes and salt lengths.
   * Some providers restrict the range of supported parameters.
   * E.g. BouncyCastle requires that the signature hash and the mgf hash
   * are the same. The test expects that unsupported combinations are
   * rejected during the initialization of the Signature instance.
   */
  @Test
  public void testRsaPssMisc() throws Exception {
    testRsaPss("rsa_pss_misc_test.json", true);
  }
}

