/**
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.security.wycheproof;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for PBKDF.
 *
 * @author bleichen@google.com (Daniel Bleichenbacher)
 */
@RunWith(JUnit4.class)
public class JsonPbkdfTest {

  /** Convenience method to get a byte array from an JsonObject */
  private static byte[] getBytes(JsonObject obj, String name) {
    return JsonUtil.asByteArray(obj.get(name));
  }

  /**
   * Returns a SecretKeyFactory for a given algorithm name.
   *
   * <p>This method expects that the provider registers PBKDF2 implementations using
   * https://docs.oracle.com/en/java/javase/19/docs/specs/security/standard-names.html .
   *
   * <p>Some providers also also allow alternative algorithm names such as PBKDF2With<hash> with
   * hash = SHA1, SHA224, etc. These are aliases.
   *
   * <p>BouncyCastle implements variants such as PBKDF2WITHHMACSHA1AND8BIT and
   * PBKDF2WITHHMACSHA1ANDUTF8. The purpose of these variants is to implement different conversions
   * of the password in PBEKeySpec to a byte array.
   *
   * <p>RFC 8018 also defines PBKDF2 with SHA512-224 and SHA512-256. No provider appears to support
   * these hash functions. Hence it is unclear what algorithm name should be used. Additional hash
   * functions are sometimes supported: e.g. BouncyCastle also implements PBKDF2 with SHA-3, Ghost
   * and SM3. These hash functions are not supported here, since they are currently not
   * standardized.
   *
   * @param algorithmName the algorithm name from a test vector file.
   * @return an instance of a SecretKeyFactory
   * @throws NoSuchAlgorithmException if the algorithm is not supported
   */
  private static SecretKeyFactory getSecretKeyFactory(String algorithmName)
      throws NoSuchAlgorithmException {
    switch (algorithmName) {
      case "PBKDF2-HMACSHA1":
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      case "PBKDF2-HMACSHA224":
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA224");
      case "PBKDF2-HMACSHA256":
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      case "PBKDF2-HMACSHA384":
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA384");
      case "PBKDF2-HMACSHA512":
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
      default:
        throw new NoSuchAlgorithmException(algorithmName);
    }
  }

  /**
   * Computes PBKDF2.
   *
   * <p>The JCE interface restricts the passwords that are acceptable. RFC 8018 defines PBKDF2 for
   * any byte array. Unfortunately, PBEKeySpec defined in javax.crypto.spec.PBEKeySpec.java requires
   * that the password is specified with an array of chars. This means that during the PBKDF2
   * computation the char array has to be converted to a byte array. The documentation of PBEKeySpec
   * mentions several possibilities: (1) ignoring the hight bits of the characters or (2) using a
   * conversion that depends on all the bits.
   *
   * <p>The code below computes PBKDF2 by using an instance of a SecretKeyFactory. This computation
   * converts the char array in the PBEKeySpec into a byte array, by encoding it with UTF-8. This
   * means that inputs for PBKDF2 that are not valid UTF-8 encodings cannot be used here.
   *
   * @param algorithm the algorithm (e.g. "PBKDF2-HMACSHA256")
   * @param password the password.
   * @param salt the salt
   * @param iterationCount the number of iterations
   * @param keyLength the length of the derived key in bytes
   * @return the derived key.
   * @throws NoSuchAlgorithmException if the algorithm or algorithm name is not supported.
   * @throws InvalidKeyException if password is not valid (e.g. if it is not a valid UTF-8 encoding.
   * @throws InvalidKeySpecException may be thrown if the password is empty.
   */
  private static byte[] computePbkdf(
      String algorithm, byte[] password, byte[] salt, int iterationCount, int keyLength)
      throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
    SecretKeyFactory factory = getSecretKeyFactory(algorithm);
    // Tries to convert password into a char[]. This needs to be done in a rather cumbersome way.
    // Using for example new String(password, "UTF-8") has unspecified behavior and could simply
    // ignore bytes that are not valid UTF-8.
    CharsetDecoder decoder = UTF_8.newDecoder();
    CharBuffer buffer;
    try {
      buffer = decoder.decode(ByteBuffer.wrap(password));
    } catch (CharacterCodingException ex) {
      throw new InvalidKeyException("Only UTF-8 encoded passwords are supported");
    }
    char[] pwd = new char[buffer.limit()];
    buffer.get(pwd);
    KeySpec keySpec = new PBEKeySpec(pwd, salt, iterationCount, 8 * keyLength);
    SecretKey tmp = factory.generateSecret(keySpec);
    return tmp.getEncoded();
  }

  /**
   * Tests a single test case:
   *
   * <p>An example for a test case is
   *
   * <pre>
   *     {
   *       "tcId" : 1,
   *       "comment" : "RFC 7914",
   *       "flags" : [
   *         "Rfc7914",
   *         "Printable",
   *       ],
   *       "password" : "706173737764",
   *       "salt" : "73616c74",
   *       "iterationCount" : 1,
   *       "dkLen" : 64,
   *       "dk" : "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
   *       "result" : "valid"
   *     }
   * </pre>
   *
   * The fields password, salt and dk are hexadecimal encoded byte arrays. Some of the passwords in
   * the test vector files are byte arrays that are not correct UTF-8 encoded string. PBKDF2 is well
   * defined for these cases, since the function expects an octet string as parameter.
   */
  private static void singleTest(String algorithm, JsonObject testcase, TestResult testResult) {
    int tcId = testcase.get("tcId").getAsInt();
    byte[] passwordBytes = getBytes(testcase, "password");
    byte[] salt = getBytes(testcase, "salt");
    int iterationCount = testcase.get("iterationCount").getAsInt();
    int dkLen = testcase.get("dkLen").getAsInt();
    byte[] expectedDk = getBytes(testcase, "dk");
    String result = testcase.get("result").getAsString();
    byte[] computedDk;
    try {
      computedDk = computePbkdf(algorithm, passwordBytes, salt, iterationCount, dkLen);
    } catch (GeneralSecurityException ex) {
      testResult.addResult(tcId, TestResult.Type.REJECTED_ALGORITHM, ex.toString());
      return;
    } catch (RuntimeException ex) {
      testResult.addResult(tcId, TestResult.Type.WRONG_EXCEPTION, ex.toString());
      return;
    }
    boolean eq = MessageDigest.isEqual(expectedDk, computedDk);
    TestResult.Type resultType;
    String comment = "";
    if (eq) {
      if (result.equals("invalid")) {
        resultType = TestResult.Type.NOT_REJECTED_INVALID;
      } else {
        resultType = TestResult.Type.PASSED_VALID;
      }
    } else {
      if (result.equals("valid")) {
        resultType = TestResult.Type.WRONG_RESULT;
        comment = TestUtil.bytesToHex(computedDk);
      } else {
        resultType = TestResult.Type.REJECTED_INVALID;
      }
    }
    testResult.addResult(tcId, resultType, comment);
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
  public static TestResult allTests(TestVectors testVectors) {
    var testResult = new TestResult(testVectors);
    JsonObject test = testVectors.getTest();
    String algorithm = test.get("algorithm").getAsString();
    String schema = test.get("schema").getAsString();
    if (!schema.equals("pbkdf_test_schema.json")) {
      testResult.addFailure(TestResult.Type.WRONG_SETUP, "Unknown schema: " + schema);
      return testResult;
    }
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        singleTest(algorithm, testcase, testResult);
      }
    }
    return testResult;
  }

  /**
   * Tests PBKDFs against test vectors.
   *
   * @param filename the JSON file with the test vectors.
   * @throws AssumptionViolatedException when the test was skipped. This happens for example when
   *     the underlying primitive is not supported.
   * @throws AssertionError when the test failed.
   * @throws IOException when the test vectors could not be read.
   */
  public void testPbkdf(String filename) throws IOException {
    JsonObject test = JsonUtil.getTestVectorsV1(filename);
    TestVectors testVectors = new TestVectors(test, filename);
    TestResult testResult = allTests(testVectors);

    if (testResult.skipTest()) {
      TestUtil.skipTest("No PBKDFs computed");
      return;
    }
    System.out.print(testResult.asString());
    assertEquals(0, testResult.errors());
  }

  @Test
  public void testPbkdf2Sha1() throws Exception {
    testPbkdf("pbkdf2_hmacsha1_test.json");
  }

  @Test
  public void testPbkdf2Sha224() throws Exception {
    testPbkdf("pbkdf2_hmacsha224_test.json");
  }

  @Test
  public void testPbkdf2Sha256() throws Exception {
    testPbkdf("pbkdf2_hmacsha256_test.json");
  }

  @Test
  public void testPbkdf2Sha384() throws Exception {
    testPbkdf("pbkdf2_hmacsha384_test.json");
  }

  @Test
  public void testPbkdf2Sha512() throws Exception {
    testPbkdf("pbkdf2_hmacsha512_test.json");
  }
}
