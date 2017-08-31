/**
 * @license
 * Copyright 2017 Google Inc. All rights reserved.
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

import static org.junit.Assert.*;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import org.junit.Test;

/**
 * This test uses test vectors in JSON format to check digital signature schemes.
 * There are still a lot of open questions, e.g. the format for the test vectors is not
 * yet finalized. Therefore, we are not integrating the tests here into other tests
 */
public class JsonSignatureTest {

  static protected String getString(JsonObject object, String name) throws Exception {
    return object.get(name).getAsString();
  }

  /**
   * Wycheproof represents BigIntegers as hexadecimal strings, using bigendian order and
   * twos complement representation.
   */
  static protected BigInteger getBigInteger(JsonObject object, String name) throws Exception {
    String hex = getString(object, name);
    byte[] bytes = TestUtil.hexToBytes(hex);
    return new BigInteger(bytes);
  }

  /**
   * Wycheproof represents byte arrays as hexadeciamal strings.
   */
  static protected byte[] getBytes(JsonObject object, String name) throws Exception {
    String hex = getString(object, name);
    return TestUtil.hexToBytes(hex);
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
   * object should contain the key in multiple formats:
   * "key" : elements of the public key
   * "keyDer": the key in ASN encoding encoded hexadecimal
   * "keyPem": the key in Pem format encoded hexadecimal
   * The test can use the format that is most convenient.
   */
  // This is a false positive, since errorprone cannot track values passed into a method.
  @SuppressWarnings("InsecureCryptoUsage")
  static protected PublicKey getPublicKey(JsonObject object, String algorithm) throws Exception {
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

  /** Example format for test vectors
   * {
   *   "algorithm": "ECDSA",
   *   "generatorVersion": "0.0a10",
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
   *           "message": "48656c6c6f",
   *           "result": "valid",
   *           "sig": "...",
   *           "tcId": 1
   *         },
   *        ...
   **/
  public void testVectors(JsonObject test, String signatureAlgorithm) throws Exception {
    // This test expects that the version in the test vectors and the version here match
    // exactly, since the formats have not yet been fixed.
    final String expectedVersion = "0.0a10";
    String generatorVersion = getString(test, "generatorVersion");
    assertEquals(expectedVersion, generatorVersion);
    int numTests = test.get("numberOfTests").getAsInt();
    int cntTests = 0;
    int errors = 0;
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      PublicKey key = getPublicKey(group, signatureAlgorithm);
      String md = getString(group, "sha");
      String algorithm = getAlgorithmName(md, signatureAlgorithm);
      Signature verifier = Signature.getInstance(algorithm);
      for (JsonElement t : group.getAsJsonArray("tests")) {
        cntTests++;
        JsonObject testcase = t.getAsJsonObject();
        byte[] message = getBytes(testcase, "message");
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
          System.out.println(signatureAlgorithm + " signature throws " + ex.toString()
                             + " tcId:" + tcid + " sig:" + sig);
          verified = false;
          errors++;
        }
        if (!verified && result.equals("valid")) {
          System.out.println("Valid " + signatureAlgorithm + " signature not verified."
                             + " tcId:" + tcid + " sig:" + sig);
          errors++;
        } else if (verified && result.equals("invalid")) {
          System.out.println("Invalid" + signatureAlgorithm + " signature verified."
                             + " tcId:" + tcid + " sig:" + sig);
          errors++;
        }
      }
    }
    assertEquals(0, errors);
    assertEquals(numTests, cntTests);
  }

  public JsonObject getJsonObjectFromFile(String filename) throws Exception {
    FileInputStream is = new FileInputStream(filename);
    JsonReader reader = new JsonReader(new InputStreamReader(is, UTF_8));
    JsonParser parser = new JsonParser();
    JsonElement elem = parser.parse(reader);
    return elem.getAsJsonObject();
  }

  public void testSignatureScheme(String filename, String algorithm) throws Exception {
    // TODO(bleichen): This (likely) will not work when published.
    String TEST_VECTORS = "third_party/wycheproof/testvectors/";
    JsonObject tests = getJsonObjectFromFile(TEST_VECTORS + filename);
    testVectors(tests, algorithm);
  }

  @Test
  public void testEcdsa() throws Exception {
    testSignatureScheme("ecdsa_test.json", "ECDSA");
  }

  @Test
  public void testRsaSignatures() throws Exception {
    testSignatureScheme("rsa_signature_test.json", "RSA");
  }
}
