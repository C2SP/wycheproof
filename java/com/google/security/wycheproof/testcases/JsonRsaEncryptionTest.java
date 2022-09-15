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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Checks implementations of RSA-OAEP and RSA-PKCS #1 v1.5 using test vectors. */
@RunWith(JUnit4.class)
public class JsonRsaEncryptionTest {

  /** Convenience mehtod to get a String from a JsonObject */
  private static String getString(JsonObject object, String name) {
    return object.get(name).getAsString();
  }

  /** Convenience method to get a byte array from a JsonObject */
  private static byte[] getBytes(JsonObject object, String name) {
    return JsonUtil.asByteArray(object.get(name));
  }

  /**
   * Get a PrivateKey from a JsonObject.
   *
   * <p>object contains the private key in multiple formats:
   *
   * <ul>
   *   <li>"privateKey" : the private key as a dictionary.
   *   <li>"privateKeyPkcs8" : the private key encoded in the PKCS #8 format.
   *   <li>"privateKeyPem" : the PEM encoded private key.
   * </ul>
   *
   * The code below assumes that the object identifier of the key is equal to rsaEncryption. An
   * alternative would be to use OID id-RSASSA-PSS, but we are not aware of a provider that support
   * such keys.
   */
  private static PrivateKey getPrivateKey(JsonObject object) throws Exception {
    KeyFactory kf;
    kf = KeyFactory.getInstance("RSA");
    byte[] encoded = TestUtil.hexToBytes(getString(object, "privateKeyPkcs8"));
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
    return kf.generatePrivate(keySpec);
  }

  private static OAEPParameterSpec getOaepParameters(JsonObject group, JsonObject test)
      throws Exception {
    String sha = getString(group, "sha");
    String mgf = getString(group, "mgf");
    String mgfSha = getString(group, "mgfSha");
    PSource p = PSource.PSpecified.DEFAULT;
    if (test.has("label")) {
      p = new PSource.PSpecified(getBytes(test, "label"));
    }
    return new OAEPParameterSpec(sha, mgf, new MGF1ParameterSpec(mgfSha), p);
  }

  /**
   * Checks a single test vector.
   *
   * @param testcase the test vector to verify
   * @param decrypter a Cipher instance. This instance is not initialized.
   * @param key the public key
   * @param testResult the result of the test are added to testResult
   */
  private static void singleTest(
      JsonObject testcase,
      Cipher decrypter,
      PrivateKey key,
      OAEPParameterSpec params,
      TestResult testResult) {
    int tcid = testcase.get("tcId").getAsInt();
    byte[] ciphertext = getBytes(testcase, "ct");
    byte[] message = getBytes(testcase, "msg");
    String messageHex = TestUtil.bytesToHex(message);
    String result = getString(testcase, "result");
    try {
      decrypter.init(Cipher.DECRYPT_MODE, key, params);
    } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
      testResult.addResult(tcid, TestResult.Type.REJECTED_ALGORITHM, "init throws " + ex);
      return;
    } catch (RuntimeException ex) {
      testResult.addResult(tcid, TestResult.Type.WRONG_EXCEPTION, "init throws " + ex);
      return;
    }

    byte[] decrypted = null;
    try {
      decrypted = decrypter.doFinal(ciphertext);
    // Some provider throw RuntimeExceptions instead of GeneralSecurityException.
    // For example BouncyCastle throws org.bouncycastle.crypto.DataLengthException
    // when the ciphertext has the wrong length.
    // While throwing a RuntimeException is a mistake, we catch it here so that the
    // test can check for an even bigger issue: Manger's attack.
    } catch (GeneralSecurityException | RuntimeException ex) {
      if (!result.equals("valid")) {
        testResult.addResult(tcid, TestResult.Type.REJECTED_INVALID, "doFinal throws " + ex);
      } else {
        testResult.addResult(tcid, TestResult.Type.REJECTED_VALID, "doFinal throws " + ex);
      }
      return;
    }
    String decryptedHex = TestUtil.bytesToHex(decrypted);
    if (result.equals("invalid")) {
      testResult.addResult(
          tcid, TestResult.Type.PASSED_MALFORMED, "Invalid ciphertext returned " + decryptedHex);
    } else if (decryptedHex.equals(messageHex)) {
      testResult.addResult(tcid, TestResult.Type.PASSED_VALID, "");
    } else {
      testResult.addResult(tcid, TestResult.Type.WRONG_RESULT, "got: " + decryptedHex);
    }
  }

  /**
   * Checks each test vector in a file of test vectors.
   *
   * <p>This method is the part of testVerification that does not log any result. The main idea
   * behind splitting off this part from testVerification is that it may be easier to call from a
   * third party.
   *
   * @param testVectors the test vectors
   * @return a test result
   */
  public static TestResult allTests(TestVectors testVectors) throws Exception {
    var testResult = new TestResult(testVectors);
    JsonObject test = testVectors.getTest();
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      PrivateKey key;
      Cipher decrypter;
      try {
        key = getPrivateKey(group);
        // There are two ways to specify the algorithm for RSA-OAEP. The first way is to use
        // <code>
        //   cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        //   OAEPParameterSpec params = ...;
        //   cipher.init(mode, key, params);
        // </code>
        // The second method is to specify parameters in the algorithm name:
        // <code>
        //   cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        //   cipher.init(mode, key, params);
        // </code>
        // The second method does not specify all algorithm parameters. In particular it does
        // not specify the hash algorithm used for MGF1 or any label.
        decrypter = Cipher.getInstance("RSA/ECB/OAEPPadding");
      } catch (GeneralSecurityException ex) {
        testResult.addFailure(TestResult.Type.REJECTED_ALGORITHM, ex.toString());
        continue;
      }
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        OAEPParameterSpec params = getOaepParameters(group, testcase);
        singleTest(testcase, decrypter, key, params, testResult);
      }
    }
    // Test vectors with invalid OAEP padding must show indistinguishable
    // behavior. Otherwise Manger's attack may be possible.
    testResult.checkIndistinguishableResult("InvalidOaepPadding");
    return testResult;
  }

  /**
   * Tests OAEP decryption with test vectors from a JSON file.
   *
   * <p>Example format for test vectors
   *
   * <pre>
   * { "algorithm" : "RSAES-OAEP",
   * "schema" : "rsaes_oaep_decrypt_schema.json",
   * "generatorVersion" : "0.9",
   * ...
   * "testGroups" : [
   * {
   * "type" : "RsaesOaepDecrypt",
   *  "keySize" : 2048,
   *  "sha" : "SHA-256",
   *  "mgf" : "MGF1",
   *  "mgfSha" : "SHA-1",
   *  "privateKey" : {
   *    "modulus" : "...",
   *    "privateExponent" : "...",
   *    "publicExponent" : "010001",
   *    "prime1" : "...",
   *    "prime2" : "...",
   *    "exponent1" : "...",
   *    "exponent2" : "...",
   *    "coefficient" : "...",
   *  },
   *  "privateKeyPkcs8" : "...",
   *  "privateKeyPem" : "-----BEGIN PRIVATE KEY-----\n...",
   *  "tests" : [
   *    {
   *      "tcId" : 1,
   *      "comment" : "",
   *      "flags" : [
   *        "Normal"
   *      ],
   *      "msg" : "",
   *      "ct" : "...",
   *      "label" : "",
   *      "result" : "valid"
   *    },
   *    ...
   * </pre>
   *
   * @param filename the filename of the test vectors
   * @param allowSkippingKeys if true then keys that cannot be constructed will not fail the test.
   *     This is for example used for files with test vectors that use elliptic curves that are not
   *     commonly supported.
   */
  public void testOaep(String filename, boolean allowSkippingKeys) throws Exception {
    JsonObject test = JsonUtil.getTestVectorsV1(filename);
    TestVectors testVectors = new TestVectors(test, filename);
    TestResult testResult = allTests(testVectors);

    if (testResult.skipTest()) {
      System.out.println("Skipping " + filename + " no ciphertext decrypted.");
      TestUtil.skipTest("No ciphertext decrypted");
      return;
    }
    System.out.print(testResult.asString());
    assertEquals(0, testResult.errors());
    if (!allowSkippingKeys) {
      int skippedKeys = testResult.getCount(TestResult.Type.REJECTED_ALGORITHM);
      assertEquals(0, skippedKeys);
    }
  }

  @Test
  public void testRsaOaep2048Sha1Mgf1Sha1() throws Exception {
   testOaep("rsa_oaep_2048_sha1_mgf1sha1_test.json", false);
  }

  @Test
  public void testRsaOaep2048Sha224Mgf1Sha1() throws Exception {
   testOaep("rsa_oaep_2048_sha224_mgf1sha1_test.json", false);
  }

  @Test
  public void testRsaOaep2048Sha224Mgf1Sha224() throws Exception {
   testOaep("rsa_oaep_2048_sha224_mgf1sha224_test.json", false);
  }

  @Test
  public void testRsaOaep2048Sha256Mgf1Sha1() throws Exception {
   testOaep("rsa_oaep_2048_sha256_mgf1sha1_test.json", false);
  }

  @Test
  public void testRsaOaep2048Sha256Mgf1Sha256() throws Exception {
   testOaep("rsa_oaep_2048_sha256_mgf1sha256_test.json", false);
  }

  @Test
  public void testRsaOaep2048Sha384Mgf1Sha1() throws Exception {
   testOaep("rsa_oaep_2048_sha384_mgf1sha1_test.json", false);
  }

  @Test
  public void testRsaOaep2048Sha384Mgf1Sha384() throws Exception {
   testOaep("rsa_oaep_2048_sha384_mgf1sha384_test.json", false);
  }

  @Test
  public void testRsaOaep2048Sha512Mgf1Sha1() throws Exception {
   testOaep("rsa_oaep_2048_sha512_mgf1sha1_test.json", false);
  }

  @Test
  public void testRsaOaep2048Sha512Mgf1Sha512() throws Exception {
   testOaep("rsa_oaep_2048_sha512_mgf1sha512_test.json", false);
  }

  @Test
  public void testRsaOaep3072Sha256Mgf1Sha1() throws Exception {
   testOaep("rsa_oaep_3072_sha256_mgf1sha1_test.json", false);
  }

  @Test
  public void testRsaOaep3072Sha256Mgf1Sha256() throws Exception {
   testOaep("rsa_oaep_3072_sha256_mgf1sha256_test.json", false);
  }

  @Test
  public void testRsaOaep3072Sha512Mgf1Sha1() throws Exception {
   testOaep("rsa_oaep_3072_sha512_mgf1sha1_test.json", false);
  }

  @Test
  public void testRsaOaep3072Sha512Mgf1Sha512() throws Exception {
   testOaep("rsa_oaep_3072_sha512_mgf1sha512_test.json", false);
  }

  @Test
  public void testRsaOaep4096Sha256Mgf1Sha1() throws Exception {
   testOaep("rsa_oaep_4096_sha256_mgf1sha1_test.json", false);
  }

  @Test
  public void testRsaOaep4096Sha256Mgf1Sha256() throws Exception {
   testOaep("rsa_oaep_4096_sha256_mgf1sha256_test.json", false);
  }

  @Test
  public void testRsaOaep4096Sha512Mgf1Sha1() throws Exception {
   testOaep("rsa_oaep_4096_sha512_mgf1sha1_test.json", false);
  }

  @Test
  public void testRsaOaep4096Sha512Mgf1Sha512() throws Exception {
   testOaep("rsa_oaep_4096_sha512_mgf1sha512_test.json", false);
  }

  @Test
  public void testRsaOaepMisc() throws Exception {
   testOaep("rsa_oaep_misc_test.json", false);
  }
}
