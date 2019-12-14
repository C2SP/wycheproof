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
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for XDH.
 *
 * <p>XDH is a Diffie-Hellman key agreement scheme over curve25519 or curve448. It has been added to
 * jdk11 (http://openjdk.java.net/jeps/324) jdk11 also adds new interfaces for XDH. The tests in
 * this class avoid the new interfaces, so that compiling with older versions is still possible.
 */
@RunWith(JUnit4.class)
public class JsonXdhTest {

  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/138722408"})
  @Test
  public void testKeyGeneration() throws Exception {
    KeyPairGenerator kpg;
    try {
      kpg = KeyPairGenerator.getInstance("XDH");
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("XDH not supported");
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
      System.out.println(algorithmName + " is not supported");
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

  /** Convenience mehtod to get a String from a JsonObject */
  protected static String getString(JsonObject object, String name) throws Exception {
    return object.get(name).getAsString();
  }

  /** Convenience method to get a byte array from a JsonObject */
  protected static byte[] getBytes(JsonObject object, String name) throws Exception {
    return JsonUtil.asByteArray(object.get(name));
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
  public void testXdhComp(String filename) throws Exception {
    // Checks the precondition for this test.
    // XDH has been added in jdk11.
    try {
      KeyAgreement.getInstance("XDH");
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("XDH is not supported: skipping test");
      return;
    }

    final String expectedSchema = "xdh_asn_comp_schema.json";
    JsonObject test = JsonUtil.getTestVectors(filename);
    String generatorVersion = test.get("generatorVersion").getAsString();
    String schema = test.get("schema").getAsString();
    if (!schema.equals(expectedSchema)) {
      System.out.println(
          "XDH: expecting JSON schema "
              + expectedSchema
              + " found "
              + schema
              + " generatorVersion:"
              + generatorVersion);
    }
    int numTests = test.get("numberOfTests").getAsInt();
    int passedTests = 0;
    int rejectedTests = 0;  // invalid test vectors leading to exceptions
    int skippedTests = 0;  // valid test vectors leading to exceptions
    int errors = 0;
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        int tcid = testcase.get("tcId").getAsInt();
        String comment = getString(testcase, "comment");
        byte[] priv = getBytes(testcase, "private");
        byte[] publicEncoded = getBytes(testcase, "public");
        String result = getString(testcase, "result");
        String expectedHex = getString(testcase, "shared");
        KeyFactory kf = KeyFactory.getInstance("XDH");
        try {
          PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(priv);
          PrivateKey privKey = kf.generatePrivate(privKeySpec);
          X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicEncoded);
          PublicKey pubKey = kf.generatePublic(pubKeySpec);
          KeyAgreement ka = KeyAgreement.getInstance("XDH");
          ka.init(privKey);
          ka.doPhase(pubKey, true);
          String sharedHex = TestUtil.bytesToHex(ka.generateSecret());
          if (result.equals("invalid")) {
            System.out.println(
                "Computed XDH with invalid parameters"
                    + " tcId:"
                    + tcid
                    + " comment:"
                    + comment
                    + " shared:"
                    + sharedHex);
            errors++;
          } else if (!expectedHex.equals(sharedHex)) {
            System.out.println(
                "Incorrect XDH computation"
                    + " tcId:"
                    + tcid
                    + " comment:"
                    + comment
                    + "\nshared:"
                    + sharedHex
                    + "\nexpected:"
                    + expectedHex
                    + "\npublic:"
                    + TestUtil.bytesToHex(publicEncoded)
                    + "\nprivate:"
                    + TestUtil.bytesToHex(priv));
            errors++;
          } else {
            passedTests++;
          }
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException ex) {
          // These are the exception that we expect to see when a curve is not implemented
          // or when a key is not valid.
          if (result.equals("valid")) {
            skippedTests++;
          } else {
            rejectedTests++;
          }
        } catch (IllegalStateException | ClassCastException ex) {
          // TODO(bleichen): Eventually the cases here should be counted as errors.
          // BouncyCastle throws IllegalStateException when the shared secret is all 0.
          // The library throws a ClassCastException in some case where the public key uses
          // a different curve. Instead of these exception I'd rather expect checked exception.
          // However, testing for incorrect results is more important at this point.
          System.out.println(
              "Test vector with tcId:" + tcid + " comment:" + comment + " throws:" + ex);
          if (result.equals("valid")) {
            skippedTests++;
          } else {
            rejectedTests++;
          }
        } catch (Exception ex) {
          // Other exceptions typically indicate that something is wrong with the implementation.
          System.out.println(
              "Test vector with tcId:" + tcid + " comment:" + comment + " throws:" + ex.toString());
          errors++;
        }
      }
    }
    System.out.println(
        filename
            + " passed:"
            + passedTests
            + " skipped:"
            + skippedTests
            + " errors:"
            + errors
            + " rejected:"
            + rejectedTests);
    assertEquals(0, errors);
    assertEquals(numTests, passedTests + rejectedTests + skippedTests);
  }

  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE, ProviderType.OPENJDK},
      bugs = {"b/138722408"})
  @Test
  public void testX25519() throws Exception {
    testXdhComp("x25519_asn_test.json");
  }

  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE, ProviderType.OPENJDK},
      bugs = {"b/138722408"})
  @Test
  public void testX448() throws Exception {
    testXdhComp("x448_asn_test.json");
  }
}
