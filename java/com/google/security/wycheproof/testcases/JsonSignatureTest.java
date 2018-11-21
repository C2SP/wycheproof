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
import com.google.security.wycheproof.WycheproofRunner.ExcludedTest;
import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * This test uses test vectors in JSON format to check digital signature schemes. There are still a
 * lot of open questions, e.g. the format for the test vectors is not yet finalized. Therefore, we
 * are not integrating the tests here into other tests
 */
@RunWith(JUnit4.class)
public class JsonSignatureTest {


  /** Convenience mehtod to get a String from a JsonObject */
  protected static String getString(JsonObject object, String name) throws Exception {
    return object.get(name).getAsString();
  }

  /** Convenience method to get a byte array from a JsonObject */
  protected static byte[] getBytes(JsonObject object, String name) throws Exception {
    return JsonUtil.asByteArray(object.get(name));
  }

  /**
   * Returns an instance of java.security.Signature for an algorithm name, a digest name and
   * a signature format. The algorithm names used in JCA are a bit inconsequential. E.g. a dash 
   * is necessary for message digests (e.g. "SHA-256") but are not used in the corresponding
   * names for digital signatures (e.g. "SHA256WITHECDSA"). Providers sometimes use distinct
   * algorithm names for the same cryptographic primitive.
   *
   * <p>See http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
   *
   * @param md the name of the message digest (e.g. "SHA-256")
   * @param signatureAlgorithm the name of the signature algorithm (e.g. "ECDSA")
   * @param signatureFormat the format of the signatures. This should be "P1363Format" for 
   *        P1363 encoded ECDSA signatures or "" otherwise.  
   * @return an instance of java.security.Signature if the algorithm is known
   * @throws NoSuchAlgorithmException if the algorithm is not known
   */
  protected static Signature getSignatureInstance(
      String md, String signatureAlgorithm, String signatureFormat)
      throws NoSuchAlgorithmException {
    if (md.equalsIgnoreCase("SHA-1")) {
      md = "SHA1";
    } else if (md.equalsIgnoreCase("SHA-224")) {
      md = "SHA224";
    } else if (md.equalsIgnoreCase("SHA-256")) {
      md = "SHA256";
    } else if (md.equalsIgnoreCase("SHA-384")) {
      md = "SHA384";
    } else if (md.equalsIgnoreCase("SHA-512")) {
      md = "SHA512";
    }
    if (signatureFormat.equalsIgnoreCase("P1363Format")
        && signatureAlgorithm.equalsIgnoreCase("ECDSA")) {
      // The algorithm names for signature schemes with P1363 format have distinct names
      // in distinct providers. This is mainly the case since the P1363 format has only
      // been added in jdk11, while providers such as BouncyCastle added the format earlier
      // than that. Hence the code below just tries known algorithm names.
      try {
        String jdkName = md + "WITH" + signatureAlgorithm + "inP1363Format";
        return Signature.getInstance(jdkName);
      } catch (NoSuchAlgorithmException ex) {
        // jdkName is not known.
      }
      try {
        String bcName = md + "WITHPLAIN-" + signatureAlgorithm;
        return Signature.getInstance(bcName);
      } catch (NoSuchAlgorithmException ex) {
        // bcName is not known.
      }
    } 
    if (!signatureFormat.isEmpty()) {
      throw new NoSuchAlgorithmException("Invalid signatureFormat:" + signatureFormat);
    }
    return Signature.getInstance(md + "WITH" + signatureAlgorithm);
  }

  /**
   * Get a PublicKey from a JsonObject.
   *
   * <p>object contains the key in multiple formats: "key" : elements of the public key "keyDer":
   * the key in ASN encoding encoded hexadecimal "keyPem": the key in Pem format encoded hexadecimal
   * The test can use the format that is most convenient.
   */
  // This is a false positive, since errorprone cannot track values passed into a method.
  @SuppressWarnings("InsecureCryptoUsage")
  protected static PublicKey getPublicKey(JsonObject object, String algorithm) throws Exception {
    KeyFactory kf;
    if (algorithm.equals("ECDSA")) {
      kf = KeyFactory.getInstance("EC");
    } else {
      kf = KeyFactory.getInstance(algorithm);
    }
    byte[] encoded = TestUtil.hexToBytes(getString(object, "keyDer"));
    X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(encoded);
    return kf.generatePublic(x509keySpec);
  }

  /**
   * Get a PrivateKey from a JsonObject.
   */
  // This is a false positive, since errorprone cannot track values passed into a method.
  @SuppressWarnings("InsecureCryptoUsage")
  protected static PrivateKey getPrivateKey(JsonObject object, String algorithm) throws Exception {
    KeyFactory kf = KeyFactory.getInstance(algorithm);
    byte[] encoded = TestUtil.hexToBytes(getString(object, "privateKeyPkcs8"));
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
    return kf.generatePrivate(keySpec);
  }

  /** 
   * Tests the signature verification with test vectors in a given JSON file.
   *
   * <p> Example format for test vectors
   * {
   *   "algorithm": "ECDSA",
   *   "generatorVersion": "0.0a13",
   *   "numberOfTests": 217,
   *   "testGroups": [
   *     {
   *       "key": {
   *         "curve": "secp256r1",
   *         "type": "ECPublicKey",
   *         "wx": "0c9c4bc2617c81eb2dcbfda2db2a370a955be86a0d2e95fcb86a99f90cf046573",
   *         "wy": "0c400363b1b6bcc3595a7d6d3575ccebcbb03f90ba8e58da2bc4824272f4fecff"
   *       },
   *       "keyDer": <X509encoded key>
   *       "keyPem": "-----BEGIN PUBLIC KEY-----\ ... \n-----END PUBLIC KEY-----",
   *       "sha": "SHA-256",
   *       "tests": [
   *         {
   *           "comment": "random signature",
   *           "msg": "48656c6c6f",
   *           "result": "valid",
   *           "sig": "...",
   *           "tcId": 1
   *         },
   *        ...
   * }
   *
   * @param filename the filename of the test vectors
   * @param signatureAlgorithm the algorithm name of the test vectors
   * @param signatureFormat the format of the signatures. This should be "P1363Format" for 
   *        P1363 encoded ECDSA signatures or "" otherwise.  
   * @param allowSkippingKeys if true then keys that cannot be constructed will not fail the test.
   *     This is for example used for files with test vectors that use elliptic curves that are not
   *     commonly supported.
   **/
  public void testVerification(
      String filename, String signatureAlgorithm, String signatureFormat, boolean allowSkippingKeys)
      throws Exception {
    // Testing with old test vectors may be a reason for a test failure.
    // Generally mismatched version numbers are of little or no concern, since
    // the test vector version change much more frequently than the format.
    //
    // Version numbers have the format major.minor[.subversion].
    // Versions before 1.0 are experimental and  use formats that are expected to change.
    // Versions after 1.0 change the major number if the format changes and change
    // the minor number if only the test vectors (but not the format) changes.
    // Subversions are release canddiate for the next version.
    final String expectedVersion = "0.6";
    JsonObject test = JsonUtil.getTestVectors(filename); 
    String generatorVersion = getString(test, "generatorVersion");
    if (!generatorVersion.equals(expectedVersion)) {
      System.out.println(
          signatureAlgorithm
              + ": expecting test vectors with version "
              + expectedVersion
              + " found vectors with version "
              + generatorVersion);
    }
    int numTests = test.get("numberOfTests").getAsInt();
    int cntTests = 0;
    int errors = 0;
    int skippedKeys = 0;
    Set<String> skippedGroups = new HashSet<String>();
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      PublicKey key;
      try {
        key = getPublicKey(group, signatureAlgorithm);
      } catch (GeneralSecurityException ex) {
        if (group.has("key")) {
          JsonObject keyStruct = group.getAsJsonObject("key");
          if (keyStruct.has("curve")) {
            skippedGroups.add("curve = " + getString(keyStruct, "curve"));
          }
        }
        skippedKeys++;
        continue;
      }
      String md = getString(group, "sha");
      Signature verifier;
      try {
        verifier = getSignatureInstance(md, signatureAlgorithm, signatureFormat);
      } catch (NoSuchAlgorithmException ex) {
        skippedKeys++;
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
        Exception failure = null;
        try {
          verified = verifier.verify(signature);
        } catch (SignatureException ex) {
          // verify can throw SignatureExceptions if the signature is malformed.
          // We don't flag these cases and simply consider the signature as invalid.
          verified = false;
          failure = ex;
        } catch (java.lang.ArithmeticException ex) {
          // b/33446454 The Sun provider may throw an ArithmeticException instead of
          // the expected SignatureException for DSA signatures.
          // We should eventually remove this.
          verified = false;
          failure = ex;
        } catch (Exception ex) {
          // Other exceptions (i.e. unchecked exceptions) are considered as error
          // since a third party should never be able to cause such exceptions.
          System.out.println(
              signatureAlgorithm
                  + " signature throws "
                  + ex.toString()
                  + " "
                  + filename
                  + " tcId:"
                  + tcid
                  + " sig:"
                  + sig);
          verified = false;
          failure = ex;
          errors++;
        }
        if (!verified && result.equals("valid")) {
          String reason = "";
          if (failure != null) {
            reason = " reason:" + failure;
          }
          System.out.println(
              "Valid "
                  + signatureAlgorithm
                  + " signature not verified."
                  + " "
                  + filename
                  + " tcId:"
                  + tcid
                  + " sig:"
                  + sig
                  + reason);
          errors++;
        } else if (verified && result.equals("invalid")) {
          System.out.println(
              "Invalid"
                  + signatureAlgorithm
                  + " signature verified."
                  + " "
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
    for (String s : skippedGroups) {
      System.out.println("Skipped groups where " + s);
    }
    assertEquals(0, errors);
    if (skippedKeys == 0) {
      assertEquals(numTests, cntTests);
    } else {
      assertTrue(allowSkippingKeys);
    }
  }

  /**
   * Tests signature generation of deterministic signature schemes such as RSA-PKCS#1 v1.5.
   *
   * <p>The test expects that signatures are fully complying with the standards.
   * E.g. it is acceptable when RSA-PKCS#1 verification considers ASN encodings of the
   * digest name with a missing NULL value for legacy reasons. However, it is considered not
   * acceptable when the signature generation does not include the NULL value.
   * 
   * @param filename the filename of the test vectors
   * @param signatureAlgorithm the algorithm name of the test vectors (e.g. "RSA")
   * @param signatureFormat the format of the signatures. This should be "P1363Format" for 
   *        P1363 encoded ECDSA signatures or "" otherwise.  
   * @param allowSkippingKeys if true then keys that cannot be constructed will not fail the test.
   */
  public void testSigning(
      String filename, String signatureAlgorithm, String signatureFormat,
      boolean allowSkippingKeys) throws Exception {
    final String expectedVersion = "0.6";
    JsonObject test = JsonUtil.getTestVectors(filename); 
    String generatorVersion = getString(test, "generatorVersion");
    if (!generatorVersion.equals(expectedVersion)) {
      System.out.println(
          signatureAlgorithm
              + ": expecting test vectors with version "
              + expectedVersion
              + " found vectors with version "
              + generatorVersion);
    }
    int cntTests = 0;
    int errors = 0;
    int skippedKeys = 0;
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      PrivateKey key;
      try {
        key = getPrivateKey(group, signatureAlgorithm);
      } catch (GeneralSecurityException ex) {
        skippedKeys++;
        continue;
      }
      String md = getString(group, "sha");
      Signature signer;
      try {
        signer = getSignatureInstance(md, signatureAlgorithm, signatureFormat);
      } catch (NoSuchAlgorithmException ex) {
        skippedKeys++;
        continue;
      }
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        String result = getString(testcase, "result");
        byte[] message = getBytes(testcase, "msg");
        byte[] signature = getBytes(testcase, "sig");
        int tcid = testcase.get("tcId").getAsInt();
        String expectedSig = TestUtil.bytesToHex(signature);
        try {
          signer.initSign(key);
          signer.update(message);
          String sig = TestUtil.bytesToHex(signer.sign());
          if (!sig.equals(expectedSig)) {
            System.out.println(
                "Incorrect signature generated "
                    + filename
                    + " tcId:"
                    + tcid
                    + " expected:"
                    + expectedSig
                    + " sig:"
                    + sig);
            errors++;
          } else {
            cntTests++;
          }
        } catch (InvalidKeyException | SignatureException ex) {
          if (result.equals("valid")) {
            System.out.println(
                "Failed to sign "
                    + filename
                    + " tcId:"
                    + tcid
                    + " with exception:"
                    + ex);
            
            errors++;
          }
        }
      }
    }
    System.out.println("Number of skipped keys:" + skippedKeys);
    System.out.println("Number of signatures verified:" + cntTests);
    assertEquals(0, errors);
    if (!allowSkippingKeys) {
      assertEquals(0, skippedKeys);
    }
  }

  @Test
  public void testEcdsa() throws Exception {
    testVerification("ecdsa_test.json", "ECDSA", "", true);
  }

  @Test
  public void testSecp224r1Sha224() throws Exception {
    testVerification("ecdsa_secp224r1_sha224_test.json", "ECDSA", "", false);
  }

  @Test
  public void testSecp224r1Sha256() throws Exception {
    testVerification("ecdsa_secp224r1_sha256_test.json", "ECDSA", "", false);
  }

  @Test
  public void testSecp224r1Sha512() throws Exception {
    testVerification("ecdsa_secp224r1_sha512_test.json", "ECDSA", "", false);
  }

  @Test
  public void testSecp256r1Sha256() throws Exception {
    testVerification("ecdsa_secp256r1_sha256_test.json", "ECDSA", "", false);
  }

  @Test
  public void testSecp256r1Sha512() throws Exception {
    testVerification("ecdsa_secp256r1_sha512_test.json", "ECDSA", "", false);
  }

  @Test
  public void testSecp384r1Sha384() throws Exception {
    testVerification("ecdsa_secp384r1_sha384_test.json", "ECDSA", "", false);
  }

  @Test
  public void testSecp384r1Sha512() throws Exception {
    testVerification("ecdsa_secp384r1_sha512_test.json", "ECDSA", "", false);
  }

  @Test
  public void testSecp521r1Sha512() throws Exception {
    testVerification("ecdsa_secp521r1_sha512_test.json", "ECDSA", "", false);
  }

  // Testing curves that may not be supported by a provider.
  @Test
  public void testSecp256k1Sha256() throws Exception {
    testVerification("ecdsa_secp256k1_sha256_test.json", "ECDSA", "", true);
  }

  @Test
  public void testSecp256k1Sha512() throws Exception {
    testVerification("ecdsa_secp256k1_sha512_test.json", "ECDSA", "", true);
  }

  @NoPresubmitTest(
    providers = {ProviderType.OPENJDK},
    bugs = {"b/117643131"}
  )
  @Test
  public void testBrainpoolP224r1Sha224() throws Exception {
    testVerification("ecdsa_brainpoolP224r1_sha224_test.json", "ECDSA", "", true);
  }

  @Test
  public void testBrainpoolP256r1Sha256() throws Exception {
    testVerification("ecdsa_brainpoolP256r1_sha256_test.json", "ECDSA", "", true);
  }

  @Test
  public void testBrainpoolP320r1Sha384() throws Exception {
    testVerification("ecdsa_brainpoolP320r1_sha384_test.json", "ECDSA", "", true);
  }

  @Test
  public void testBrainpoolP384r1Sha384() throws Exception {
    testVerification("ecdsa_brainpoolP384r1_sha384_test.json", "ECDSA", "", true);
  }

  @Test
  public void testBrainpoolP512r1Sha512() throws Exception {
    testVerification("ecdsa_brainpoolP512r1_sha512_test.json", "ECDSA", "", true);
  }

  // jdk11 adds P1363 encoded signatures.
  @Test
  public void testSecp224r1Sha224inP1363Format() throws Exception {
    testVerification("ecdsa_secp224r1_sha224_p1363_test.json", "ECDSA", "P1363Format", true);
  }

  @Test
  public void testSecp224r1Sha256inP1363Format() throws Exception {
    testVerification("ecdsa_secp224r1_sha256_p1363_test.json", "ECDSA", "P1363Format", true);
  }

  @Test
  public void testSecp224r1Sha512inP1363Format() throws Exception {
    testVerification("ecdsa_secp224r1_sha512_p1363_test.json", "ECDSA", "P1363Format", true);
  }

  @Test
  public void testSecp256r1Sha256inP1363Format() throws Exception {
    testVerification("ecdsa_secp256r1_sha256_p1363_test.json", "ECDSA", "P1363Format", true);
  }

  @Test
  public void testSecp256r1Sha512inP1363Format() throws Exception {
    testVerification("ecdsa_secp256r1_sha512_p1363_test.json", "ECDSA", "P1363Format", true);
  }

  @Test
  public void testSecp384r1Sha384inP1363Format() throws Exception {
    testVerification("ecdsa_secp384r1_sha384_p1363_test.json", "ECDSA", "P1363Format", true);
  }

  @Test
  public void testSecp384r1Sha512inP1363Format() throws Exception {
    testVerification("ecdsa_secp384r1_sha512_p1363_test.json", "ECDSA", "P1363Format", true);
  }

  @Test
  public void testSecp521r1Sha512inP1363Format() throws Exception {
    testVerification("ecdsa_secp521r1_sha512_p1363_test.json", "ECDSA", "P1363Format", true);
  }

  @Test
  public void testSecp256k1Sha256inP1363Format() throws Exception {
    testVerification("ecdsa_secp256k1_sha256_p1363_test.json", "ECDSA", "P1363Format", true);
  }

  @Test
  public void testSecp256k1Sha512inP1363Format() throws Exception {
    testVerification("ecdsa_secp256k1_sha512_p1363_test.json", "ECDSA", "P1363Format", true);
  }

  @NoPresubmitTest(
    providers = {ProviderType.OPENJDK},
    bugs = {"b/117643131"}
  )
  @Test
  public void testBrainpoolP224r1Sha224inP1363Format() throws Exception {
    testVerification("ecdsa_brainpoolP224r1_sha224_p1363_test.json", "ECDSA", "P1363Format", true);
  }

  @Test
  public void testBrainpoolP256r1Sha256inP1363Format() throws Exception {
    testVerification("ecdsa_brainpoolP256r1_sha256_p1363_test.json", "ECDSA", "P1363Format", true);
  }

  @Test
  public void testBrainpoolP320r1Sha384inP1363Format() throws Exception {
    testVerification("ecdsa_brainpoolP320r1_sha384_p1363_test.json", "ECDSA", "P1363Format", true);
  }

  @Test
  public void testBrainpoolP384r1Sha384inP1363Format() throws Exception {
    testVerification("ecdsa_brainpoolP384r1_sha384_p1363_test.json", "ECDSA", "P1363Format", true);
  }

  @Test
  public void testBrainpoolP512r1Sha512inP1363Format() throws Exception {
    testVerification("ecdsa_brainpoolP512r1_sha512_p1363_test.json", "ECDSA", "P1363Format", true);
  }

  // Testing RSA PKCS#1 v1.5 signatures.
  @Test
  public void testRsaSigning() throws Exception { 
    testSigning("rsa_sig_gen_misc_test.json", "RSA", "", false);
  }

  @Test
  public void testRsaSignatures() throws Exception {
    testVerification("rsa_signature_test.json", "RSA", "", false);
  }

  @Test
  public void testRsaSignature2048sha224() throws Exception {
    testVerification("rsa_signature_2048_sha224_test.json", "RSA", "", false);
  }

  @Test
  public void testRsaSignatures2048sha256() throws Exception {
    testVerification("rsa_signature_2048_sha256_test.json", "RSA", "", false);
  }

  @Test
  public void testRsaSignatures2048sha512() throws Exception {
    testVerification("rsa_signature_2048_sha512_test.json", "RSA", "", false);
  }

  @Test
  public void testRsaSignatures3072sha256() throws Exception {
    testVerification("rsa_signature_3072_sha256_test.json", "RSA", "", false);
  }

  @Test
  public void testRsaSignatures3072sha384() throws Exception {
    testVerification("rsa_signature_3072_sha384_test.json", "RSA", "", false);
  }

  @Test
  public void testRsaSignatures3072sha512() throws Exception {
    testVerification("rsa_signature_3072_sha512_test.json", "RSA", "", false);
  }

  @Test
  public void testRsaSignatures4096sha384() throws Exception {
    testVerification("rsa_signature_4096_sha384_test.json", "RSA", "", false);
  }

  @Test
  public void testRsaSignatures4096sha512() throws Exception {
    testVerification("rsa_signature_4096_sha512_test.json", "RSA", "", false);
  }

  // Testing DSA signatures.
  @NoPresubmitTest(
    providers = {ProviderType.OPENJDK},
    bugs = {"b/33446454"}
  )
  @ExcludedTest(
    providers = {ProviderType.CONSCRYPT},
    comment = "Conscrypt does not support DSA.")
  @Test
  public void testDsa() throws Exception {
    testVerification("dsa_test.json", "DSA", "", false);
  }
}

