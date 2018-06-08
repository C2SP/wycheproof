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
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
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
   * Returns the algorithm name for a digital signature algorithm with a given message digest. The
   * algorithm names used in JCA are a bit inconsequential. E.g. a dash is necessary for message
   * digests (e.g. "SHA-256") but are not used in the corresponding names for digital signatures
   * (e.g. "SHA256WITHECDSA").
   *
   * <p>See http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
   *
   * @param md the name of the message digest (e.g. "SHA-256")
   * @param signatureAlgorithm the name of the signature algorithm (e.g. "ECDSA")
   * @return the algorithm name for the signature scheme with the given hash.
   */
  protected static String getAlgorithmName(String md, String signatureAlgorithm) {
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
    return md + "WITH" + signatureAlgorithm;
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
   * @param allowSkippingKeys if true then keys that cannot be constructed will not fail the test.
   *     This is for example used for files with test vectors that use elliptic curves that are not
   *     commonly supported.
   **/
  public void testSignatureScheme(
      String filename, String signatureAlgorithm, boolean allowSkippingKeys)
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
    final String expectedVersion = "0.4";
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
      String algorithm = getAlgorithmName(md, signatureAlgorithm);
      Signature verifier = Signature.getInstance(algorithm);
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
        } catch (java.lang.ArithmeticException ex) {
          // b/33446454 The Sun provider may throw an ArithmeticException instead of
          // the expected SignatureException for DSA signatures.
          // We should eventually remove this.
          verified = false;
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
          errors++;
        }
        if (!verified && result.equals("valid")) {
          System.out.println(
              "Valid "
                  + signatureAlgorithm
                  + " signature not verified."
                  + " "
                  + filename
                  + " tcId:"
                  + tcid
                  + " sig:"
                  + sig);
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

  @Test
  public void testEcdsa() throws Exception {
    testSignatureScheme("ecdsa_test.json", "ECDSA", true);
  }

  @Test
  public void testSecp224r1Sha224() throws Exception {
    testSignatureScheme("ecdsa_secp224r1_sha224_test.json", "ECDSA", false);
  }

  @Test
  public void testSecp224r1Sha256() throws Exception {
    testSignatureScheme("ecdsa_secp224r1_sha256_test.json", "ECDSA", false);
  }

  @Test
  public void testSecp256r1Sha256() throws Exception {
    testSignatureScheme("ecdsa_secp256r1_sha256_test.json", "ECDSA", false);
  }

  @Test
  public void testSecp384r1Sha384() throws Exception {
    testSignatureScheme("ecdsa_secp384r1_sha384_test.json", "ECDSA", false);
  }

  @Test
  public void testSecp384r1Sha512() throws Exception {
    testSignatureScheme("ecdsa_secp384r1_sha512_test.json", "ECDSA", false);
  }

  @Test
  public void testSecp521r1Sha512() throws Exception {
    testSignatureScheme("ecdsa_secp521r1_sha512_test.json", "ECDSA", false);
  }

  // Testing curves that may not be supported by a provider.
  @Test
  public void testSecp256k1Sha256() throws Exception {
    testSignatureScheme("ecdsa_secp256k1_sha256_test.json", "ECDSA", true);
  }

  @Test
  public void testBrainpoolP224r1Sha224() throws Exception {
    testSignatureScheme("ecdsa_brainpoolP224r1_sha224_test.json", "ECDSA", true);
  }

  @Test
  public void testBrainpoolP256r1Sha256() throws Exception {
    testSignatureScheme("ecdsa_brainpoolP256r1_sha256_test.json", "ECDSA", true);
  }

  @Test
  public void testBrainpoolP320r1Sha384() throws Exception {
    testSignatureScheme("ecdsa_brainpoolP320r1_sha384_test.json", "ECDSA", true);
  }

  @Test
  public void testBrainpoolP384r1Sha384() throws Exception {
    testSignatureScheme("ecdsa_brainpoolP384r1_sha384_test.json", "ECDSA", true);
  }

  @Test
  public void testBrainpoolP512r1Sha512() throws Exception {
    testSignatureScheme("ecdsa_brainpoolP512r1_sha512_test.json", "ECDSA", true);
  }

  // Testing RSA signatures.
  @Test
  public void testRsaSignatures() throws Exception {
    testSignatureScheme("rsa_signature_test.json", "RSA", false);
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
    testSignatureScheme("dsa_test.json", "DSA", false);
  }
}

