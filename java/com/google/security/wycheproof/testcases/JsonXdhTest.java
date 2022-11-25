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
import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import javax.crypto.KeyAgreement;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for XDH.
 *
 * <p>XDH is a Diffie-Hellman key agreement scheme over curve25519 or curve448. It has been added to
 * jdk11 (http://openjdk.java.net/jeps/324) jdk11 also adds new interfaces for XDH. Using the XDH
 * interfaces has some disadvantages: (1) the XDH interfaces are low level, they require that the
 * caller performs some bit fiddling specified in RFC 7748. (2) Third party providers do not support
 * these interfaces well. (3) Code becomes algorithm dependent. Because of these disadvantages it is
 * preferable to work with ASN encoded keys.
 */
@RunWith(JUnit4.class)
public class JsonXdhTest {

  @Test
  public void testKeyGeneration() throws Exception {
    KeyPairGenerator kpg;
    try {
      kpg = KeyPairGenerator.getInstance("XDH");
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest("XDH not supported");
      return;
    }
    // An alternative is
    //   NamedParameterSpec paramSpec = new NamedParameterSpec("X25519");
    //   kpg.initialize(paramSpec);
    // But this only compiles with jdk11.
    kpg.initialize(255);
    KeyPair kp = kpg.generateKeyPair();
    PrivateKey priv = kp.getPrivate();
    PublicKey pub = kp.getPublic();

    // Encodings are a bit of a problem.
    byte[] privEncoded = priv.getEncoded();
    System.out.println(
        "X25519 privat key format:"
            + priv.getFormat()
            + " encoded:"
            + TestUtil.bytesToHex(privEncoded));

    byte[] pubEncoded = pub.getEncoded();
    System.out.println(
        "X25519 public key format:"
            + pub.getFormat()
            + " encoded:"
            + TestUtil.bytesToHex(pubEncoded));
  }

  /**
   * An alternative way to generate an XDH key is to use specific names for the algorithm (i.e.
   * "X25519" or "X448"). These names fully specify key size and algorithm.
   *
   * <p>This test generates a key pair with such an algorithm name, serializes the keys, prints them
   * and the imports the keys back again. This allows to debug issues such as
   * https://bugs.openjdk.java.net/browse/JDK-8213493
   */
  public void testKeyGenerationWithName(String algorithmName) throws Exception {
    KeyPairGenerator kpg;
    try {
      kpg = KeyPairGenerator.getInstance(algorithmName);
    } catch (NoSuchAlgorithmException ex) {
      TestUtil.skipTest(algorithmName + " is not supported");
      return;
    }
    KeyPair kp = kpg.generateKeyPair();

    PrivateKey priv = kp.getPrivate();
    PublicKey pub = kp.getPublic();

    // Encodings are a bit of a problem.
    byte[] privEncoded = priv.getEncoded();
    System.out.println(
        algorithmName
            + " privat key format:"
            + priv.getFormat()
            + " encoded:"
            + TestUtil.bytesToHex(privEncoded));

    byte[] pubEncoded = pub.getEncoded();
    System.out.println(
        algorithmName
            + " public key format:"
            + pub.getFormat()
            + " encoded:"
            + TestUtil.bytesToHex(pubEncoded));

    KeyFactory kf = KeyFactory.getInstance("XDH");
    PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privEncoded);
    PrivateKey unusedPrivKey2 = kf.generatePrivate(privKeySpec);
    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubEncoded);
    PublicKey unusedPubKey2 = kf.generatePublic(pubKeySpec);
  }

  @Test
  public void testKeyGenerationX25519() throws Exception {
    testKeyGenerationWithName("X25519");
  }

  @Test
  public void testKeyGenerationX448() throws Exception {
    testKeyGenerationWithName("X448");
  }

  /** Convenience method to get a byte array from a JsonObject */
  private static byte[] getBytes(JsonObject object, String name) {
    return JsonUtil.asByteArray(object.get(name));
  }

  /**
   * Returns the bit size of the underlying curve.
   *
   * @param paramSpec the XDH parameters
   * @return the size of the underlying curve in bits.
   */
  public static int getBits(NamedParameterSpec paramSpec) throws NoSuchAlgorithmException {
    switch (paramSpec.getName()) {
      case "X25519":
        return 255;
      case "X448":
        return 448;
      default:
        throw new NoSuchAlgorithmException("Unsupported algorithm: " + paramSpec.getName());
    }
  }

  /**
   * Decodes a raw public key.
   *
   * <p>This function is defined in Section 5 of RFC 7748. Support for this representation is a bit
   * weak. While raw key can be converted into an XECPublickeySpec it is necessary that the user is
   * aware of a number of subtleties to ensure a correct conversion. I.e., there are a number of
   * ways an encoding can be malformed or non-canonical:
   *
   * <ul>
   *   <li>The size of the encoded coordinate is wrong. RFC 7748 implicitely assumes a fixed size.
   *       Hence such encoding should be rejected. The size of the encoded coordinate is lost after
   *       converting to an integer. Hence this method checks the size and throws an exception when
   *       the size is incorrect.
   *   <li>The most significant bit of an X25519 coordinate is set. RFC 7748 states that this bit
   *       must be ignored. XECPublicKeySpec allows to specify public keys where this bit has not
   *       been cleared. Computing XDH with such keys has non-conforming behavior. Hence it is left
   *       to the caller to clear the most significant bit.
   *   <li>The coordinate is larger than the size of the XDH field but has the same bit length. In
   *       this case the value should be reduced modulo the order of the XDH field. This functions
   *       does not do this reduction and expects the provider to perform this function.
   * </ul>
   *
   * @param encoded the encoded public key
   * @param paramSpec the parameter defining the algorithm
   * @return the decoded public key
   * @throws InvalidKeySpecException if the encoded coordinate has an incorrect size.
   * @throws NoSuchAlgorithmException if paramSpec is not supported.
   */
  public static KeySpec decodeRawPublic(byte[] encoded, NamedParameterSpec paramSpec)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    int bits = getBits(paramSpec);
    int size = (bits + 7) / 8;
    if (encoded.length != size) {
      throw new InvalidKeySpecException("Invalid size of the encoded coordinate.");
    }
    BigInteger u = BigInteger.ZERO;
    for (int i = 0; i < size; i++) {
      u = u.add(BigInteger.valueOf(encoded[i] & 0xff).shiftLeft(8 * i));
    }
    // Discard additional bits as specified in Section 5 of RFC 7748.
    if (u.bitLength() >= bits) {
      u = u.mod(BigInteger.ONE.shiftLeft(bits));
    }
    return new XECPublicKeySpec(paramSpec, u);
  }

  /* Returns a KeySpec for the public key in an XDH exchange.
   *
   * @param paramSpec The parameterSpec that defines the XDH parameters.
   * @param schema The JSON schema of the test vectors. The schema defines the
   *      format of the public key.
   * @param testcase The testcase containing the public key.
   * @return the public key
   */
  private static KeySpec getPublicKeySpec(
      NamedParameterSpec paramSpec, String schema, JsonObject testcase)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    byte[] pub = getBytes(testcase, "public");
    switch (schema) {
      case "xdh_asn_comp_schema.json":
        return new X509EncodedKeySpec(pub);
      case "xdh_comp_schema.json":
        return decodeRawPublic(pub, paramSpec);
      default:
        throw new NoSuchAlgorithmException("Unsupported schema: " + schema);
    }
  }

  /**
   * Returns a KeySpec for the private key in an XDH exchange.
   *
   * @param paramSpec The parameterSpec that defines the XDH parameters.
   * @param schema The JSON schema of the test vectors. The schema defines the format of the private
   *     key.
   * @param testcase The testcase containing the private key.
   * @return the private key
   */
  private static KeySpec getPrivateKeySpec(
      NamedParameterSpec paramSpec, String schema, JsonObject testcase)
      throws NoSuchAlgorithmException {
    byte[] priv = getBytes(testcase, "private");
    switch (schema) {
      case "xdh_asn_comp_schema.json":
        return new PKCS8EncodedKeySpec(priv);
      case "xdh_comp_schema.json":
        return new XECPrivateKeySpec(paramSpec, priv);
      default:
        throw new NoSuchAlgorithmException("Unsupported schema: " + schema);
    }
  }

  private static NamedParameterSpec getParameterSpec(String curve) throws NoSuchAlgorithmException {
    switch (curve) {
      case "curve25519":
        return NamedParameterSpec.X25519;
      case "curve448":
        return NamedParameterSpec.X448;
      default:
        throw new NoSuchAlgorithmException("Unsupported curve: " + curve);
    }
  }

  private static void singleTest(
      TestVectors testvectors,
      NamedParameterSpec paramSpec,
      String schema,
      JsonObject testcase,
      TestResult testResult) {
    int tcId = testcase.get("tcId").getAsInt();
    String result = testcase.get("result").getAsString();
    String expectedHex = testcase.get("shared").getAsString();
    try {
      KeyFactory kf = KeyFactory.getInstance("XDH");
      KeySpec privKeySpec = getPrivateKeySpec(paramSpec, schema, testcase);
      PrivateKey privKey = kf.generatePrivate(privKeySpec);
      KeySpec pubKeySpec = getPublicKeySpec(paramSpec, schema, testcase);
      PublicKey pubKey = kf.generatePublic(pubKeySpec);
      KeyAgreement ka = KeyAgreement.getInstance("XDH");
      ka.init(privKey);
      ka.doPhase(pubKey, true);
      String sharedHex = TestUtil.bytesToHex(ka.generateSecret());
      TestResult.Type res;
      String comment = "";
      if (expectedHex.equals(sharedHex)) {
        if (result.equals("valid") || testvectors.isLegacy(tcId)) {
          res = TestResult.Type.PASSED_VALID;
        } else {
          // A shared secret was computed with an invalid input.
          // This indicates an incomplete input validation.
          res = TestResult.Type.PASSED_MALFORMED;
        }
      } else {
        if (result.equals("valid") || testvectors.isLegacy(tcId)) {
          res = TestResult.Type.WRONG_RESULT;
        } else {
          // An invalid shared secret was computed with an invalid input.
          // Bugs like this can indicate that an invalid curve attack
          // might be possible. Hence this error is typically much more critical
          // than PASSED_MALFORMED.
          res = TestResult.Type.NOT_REJECTED_INVALID;
        }
        comment = "Incorrect result: " + sharedHex;
      }
      testResult.addResult(tcId, res, comment);
    } catch (NoSuchAlgorithmException ex) {
      testResult.addResult(tcId, TestResult.Type.REJECTED_ALGORITHM, ex.toString());
    } catch (InvalidKeySpecException | InvalidKeyException | IllegalStateException ex) {
      // IllegalStateException is a RuntimeException. Normally a provider should not throw
      // any RuntimeException, when the input is malformed. Unfortunately, the interface
      // KeyAgreement.generateSecret only allows ShortBufferException and IllegalStateException.
      // Hence some provider throw, IllegalStateExceptions when the shared secret is invalid.
      if (result.equals("valid")) {
        testResult.addResult(tcId, TestResult.Type.REJECTED_VALID, ex.toString());
      } else {
        testResult.addResult(tcId, TestResult.Type.REJECTED_INVALID, ex.toString());
      }
    } catch (RuntimeException ex) {
      testResult.addResult(tcId, TestResult.Type.WRONG_EXCEPTION, ex.toString());
    }
  }

  /**
   * This test requires test vectors where the public key is X.509 encoded and the private key is
   * PKCS #8 encoded. I.e. test vectors that use the JSON schema "xdh_asn_comp_schema.json".
   *
   * <p>The main reason for using this encoding is that the tests below can be implemented without
   * using new interfaces such as XECPublicKey, XECPrivateKey, so that the code still compiles on
   * older jdk versions and tests are simply skipped.
   *
   * <p>Example for test vector
   *
   * <pre>
   * {
   *   "algorithm" : "XDH",
   *   "generatorVersion" : "0.8",
   *   "numberOfTests" : 32,
   *   "header" : [],
   *   "schema" : "xdh_asn_comp_schema.json",
   *   "testGroups" : [
   *     {
   *       "curve" : "curve25519",
   *       "type" : "XDHComp",
   *       "tests" : [
   *         {
   *           "tcId" : 1,
   *           "comment" : "normal case",
   *           "public" : "302c300706032b...",
   *           "private" : "302e0201003007...",
   *           "shared" : "87b7f212b627f7...",
   *           "result" : "valid",
   *           "flags" : []
   *         },
   *         ...
   * </pre>
   */
  public static TestResult allTests(TestVectors testVectors) {
    var testResult = new TestResult(testVectors);
    try {
      KeyAgreement unused = KeyAgreement.getInstance("XDH");
    } catch (NoSuchAlgorithmException ex) {
      testResult.addFailure(TestResult.Type.REJECTED_ALGORITHM, "XDH is not known");
      return testResult;
    }
    JsonObject test = testVectors.getTest();
    String schema = test.get("schema").getAsString();
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      String curve = group.get("curve").getAsString();
      NamedParameterSpec paramSpec;
      try {
        paramSpec = getParameterSpec(curve);
      } catch (NoSuchAlgorithmException ex) {
        testResult.addFailure(TestResult.Type.REJECTED_ALGORITHM, ex.toString());
        continue;
      }
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        singleTest(testVectors, paramSpec, schema, testcase, testResult);
      }
    }
    return testResult;
  }

  public void testXdhComp(String filename) throws Exception {
    JsonObject test = JsonUtil.getTestVectorsV1(filename);
    TestResult testResult = allTests(new TestVectors(test, filename));
    if (testResult.skipTest()) {
      TestUtil.skipTest("No valid test vectors passed");
      return;
    }
    System.out.print(testResult.asString());
    assertEquals(0, testResult.errors());
  }

  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE, ProviderType.OPENJDK},
      bugs = {"b/138722408"})
  @Test
  public void testX25519Asn() throws Exception {
    testXdhComp("x25519_asn_test.json");
  }

  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE, ProviderType.OPENJDK},
      bugs = {"b/138722408"})
  @Test
  public void testX448Asn() throws Exception {
    testXdhComp("x448_asn_test.json");
  }

  @Test
  public void testX25519() throws Exception {
    testXdhComp("x25519_test.json");
  }

  @Test
  public void testX448() throws Exception {
    testXdhComp("x448_test.json");
  }
}
