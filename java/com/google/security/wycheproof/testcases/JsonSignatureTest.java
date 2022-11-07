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
import static org.junit.Assert.assertFalse;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;
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
  /**
   * Defines the format of the signatures. RAW is used when the signature scheme already defines an
   * encoding (e.g. this is used for RSA signatures).
   */
  public enum Format {
    UNKNOWN,
    RAW,
    ASN,
    P1363
  };

  /**
   * Defines the algorithm of the signature scheme.
   *
   * <p>Some signatures schemes (i.e., RSASSA-PSS) have multiple different formats for their keys
   * and require slightly different use of JCA. Such schemes are split into multiple algorithms.
   *
   * <p>Files with test vectors in Wycheproof contain test vectors for a single signature algorithm.
   * This signature algorithm can be derived from the JSON schema.
   */
  public enum SignatureAlgorithm {
    UNKNOWN,
    // RSA PKCS #1 signatures
    RSA_PKCS1,
    // RSASSA-PSS signatures with keys that do not include algorithm parameters.
    // JCA requires to treat RSASSA-PSS key without algorithm parameters differently from
    // key that include them.
    // I.e., if the parameters are not included in the key then one has to use
    // KeyFactory.getInstance("RSA"), and set the algorithm parameters separately.
    RSA_PSS_WITHOUT_PARAMS,
    // RSASSA-PSS signatures with keys that include the algorithm parameters.
    // The encoding of the parameters is defined in Section A.2.3 of RFC 8017.
    // Keys that include these parameters should use
    // KeyFactory.getInstance("RSASSA-PSS").
    RSA_PSS_WITH_PARAMS,
    ECDSA,
    EDDSA,
    DSA,
  }

  /** Returns the signature format corresponding to a JSON schema. */
  protected static Format getSignatureFormat(String schema) {
    if (schema.equals("ecdsa_verify_schema.json") || schema.equals("dsa_verify_schema.json")) {
      return Format.ASN;
    }
    if (schema.equals("ecdsa_p1363_verify_schema.json")
        || schema.equals("dsa_p1363_verify_schema.json")) {
      return Format.P1363;
    }
    if (schema.equals("rsassa_pkcs1_verify_schema.json")
        || schema.equals("rsassa_pss_verify_schema.json")
        || schema.equals("rsassa_pss_with_parameters_verify_schema.json")
        || schema.equals("eddsa_verify_schema.json")) {
      return Format.RAW;
    }
    return Format.UNKNOWN;
  }

  /** Returns the signature algorithm corresponding to a JSON schema. */
  protected static SignatureAlgorithm getSignatureAlgorithm(String schema) {
    if (schema.equals("ecdsa_verify_schema.json")
        || schema.equals("ecdsa_p1363_verify_schema.json")) {
      return SignatureAlgorithm.ECDSA;
    }
    if (schema.equals("dsa_verify_schema.json") || schema.equals("dsa_p1363_verify_schema.json")) {
      return SignatureAlgorithm.DSA;
    }
    if (schema.equals("rsassa_pkcs1_verify_schema.json")) {
      return SignatureAlgorithm.RSA_PKCS1;
    }
    if (schema.equals("rsassa_pss_verify_schema.json")) {
      // Used for RSASSA-PSS without parameters in the key.
      return SignatureAlgorithm.RSA_PSS_WITHOUT_PARAMS;
    }
    if (schema.equals("rsassa_pss_with_parameters_verify_schema.json")) {
      // Used for RSASSA-PSS with parameters in the key.
      return SignatureAlgorithm.RSA_PSS_WITH_PARAMS;
    }
    if (schema.equals("eddsa_verify_schema.json")) {
      return SignatureAlgorithm.EDDSA;
    }
    return SignatureAlgorithm.UNKNOWN;
  }

  /** Convenience method to get a String from a JsonObject */
  protected static String getString(JsonObject object, String name) {
    return object.get(name).getAsString();
  }

  /** Convenience method to get a byte array from a JsonObject */
  protected static byte[] getBytes(JsonObject object, String name) {
    return JsonUtil.asByteArray(object.get(name));
  }

  /**
   * Convert hash names, so that they can be used in an algorithm name for a signature. The
   * algorithm names used in JCA are a bit inconsequential. E.g. a dash is necessary for message
   * digests (e.g. "SHA-256") but are not used in the corresponding names for digital signatures
   * (e.g. "SHA256WITHECDSA"). Providers sometimes use distinct algorithm names for the same
   * cryptographic primitive. On the other hand, the dash remains for SHA-3. Hence, the correct
   * name for ECDSA with SHA3-256 is "SHA3-256WithECDSA".
   *
   * <p>See https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html
   *
   * @param md the name of a message digest
   * @return the name of the message digest when used in a signature algorithm.
   */
  protected static String convertMdName(String md) {
    switch (md.toUpperCase(Locale.ENGLISH)) {
      case "SHA-1":
        return "SHA1";
      case "SHA-224":
        return "SHA224";
      case "SHA-256":
        return "SHA256";
      case "SHA-384":
        return "SHA384";
      case "SHA-512":
        return "SHA512";
      case "SHA-512/224":
        return "SHA512/224";
      case "SHA-512/256":
        return "SHA512/256";
      default:
        return md;
    }
  }

  protected static Signature getPssInstance(JsonObject group) throws NoSuchAlgorithmException {
    String md = convertMdName(getString(group, "sha"));
    String mgfSha = convertMdName(getString(group, "mgfSha"));
    try {
      return Signature.getInstance("RSASSA-PSS");
    } catch (NoSuchAlgorithmException ex) {
      // RSASSA-PSS is not known. Try the other options.
    }
    try {
      String name = md + "WITHRSAand" + mgfSha;
      return Signature.getInstance(name);
    } catch (NoSuchAlgorithmException ex) {
      // RSASSA-PSS using legacy JCE naming is not known.
    }
    try {
      String name = md + "withRSA/PSS";
      return Signature.getInstance(name);
    } catch (NoSuchAlgorithmException ex) {
      // Conscrypt naming is not known.
    }
    throw new NoSuchAlgorithmException("RSASSA-PSS is not supported");
  }

  /**
   * Returns the algorithm parameters for RSASSA-PSS.
   *
   * <p>The Algorithm parameters are necessary when the keys do not include the algorithm
   * parameters.
   */
  protected static AlgorithmParameterSpec getPssParameterSpec(JsonObject group)
      throws NoSuchAlgorithmException {
    String sha = getString(group, "sha");
    String mgf = getString(group, "mgf");
    String mgfSha = getString(group, "mgfSha");
    int saltLen = group.get("sLen").getAsInt();
    int trailerField = 1;
    if (mgf.equals("MGF1")) {
      return new PSSParameterSpec(sha, mgf, new MGF1ParameterSpec(mgfSha), saltLen, trailerField);
    } else {
      throw new NoSuchAlgorithmException("Unknown MGF:" + mgfSha);
    }
  }

  /**
   * Returns an instance of java.security.Signature for an algorithm name, a digest name and a
   * signature format.
   *
   * @param md the name of the message digest (e.g. "SHA-256")
   * @param signatureAlgorithm the name of the signature algorithm (e.g. "ECDSA")
   * @param signatureFormat the format of the signatures.
   * @return an instance of java.security.Signature if the algorithm is known
   * @throws NoSuchAlgorithmException if the algorithm is not known
   * @throws InvalidAlgorithmParameterException if the parameters are wrong
   */
  protected static Signature getSignatureInstance(
      JsonObject group,
      SignatureAlgorithm signatureAlgorithm,
      Format signatureFormat,
      PublicKey key)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    String md = "";
    if (group.has("sha")) {
      md = convertMdName(getString(group, "sha"));
    }
    switch (signatureAlgorithm) {
      case ECDSA:
      if (signatureFormat == Format.ASN) {
          return Signature.getInstance(md + "WITHECDSA");
      } else if (signatureFormat == Format.P1363) {
        // The algorithm names for signature schemes with P1363 format have distinct names
        // in distinct providers. This is mainly the case since the P1363 format has only
        // been added in jdk11, while providers such as BouncyCastle added the format earlier
        // than that. Hence the code below just tries known algorithm names.
        try {
            String jdkName = md + "WITHECDSAinP1363Format";
          return Signature.getInstance(jdkName);
        } catch (NoSuchAlgorithmException ex) {
          // jdkName is not known.
        }
        try {
            String bcName = md + "WITHPLAIN-ECDSA";
          return Signature.getInstance(bcName);
        } catch (NoSuchAlgorithmException ex) {
          // bcName is not known.
        }
      }
        break;
      case DSA:
        if (signatureFormat == Format.ASN) {
          return Signature.getInstance(md + "WITHDSA");
        } else if (signatureFormat == Format.P1363) {
          // The algorithm names for signature schemes with P1363 format have distinct names
          // in distinct providers. This is mainly the case since the P1363 format has only
          // been added in jdk11, while providers such as BouncyCastle added the format earlier
          // than that. Hence the code below just tries known algorithm names.
          try {
            String jdkName = md + "WITHDSAinP1363Format";
            return Signature.getInstance(jdkName);
        } catch (NoSuchAlgorithmException ex) {
            // jdkName is not known.
          }
        try {
            String bcName = md + "WITHPLAIN-DSA";
            return Signature.getInstance(bcName);
        } catch (NoSuchAlgorithmException ex) {
            // bcName is not known.
          }
      }
        break;
      case RSA_PKCS1:
        if (signatureFormat == Format.RAW) {
          return Signature.getInstance(md + "WITHRSA");
        }
        break;
      case RSA_PSS_WITHOUT_PARAMS:
        if (signatureFormat == Format.RAW) {
          Signature signature = getPssInstance(group);
          AlgorithmParameterSpec params = getPssParameterSpec(group);
          signature.setParameter(params);
          return signature;
        }
        break;
      case RSA_PSS_WITH_PARAMS:
        if (signatureFormat == Format.RAW) {
          Signature signature = Signature.getInstance("RSASSA-PSS");
          // Copies the RSASSA-PSS parameters from key into signature.
          // It is somewhat unexpected that this step is necessary.
          // At least one jdk version tested does not copy algorithm parameters
          // from key into signature during signature.init(key).
          RSAPublicKey pub = (RSAPublicKey) key;
          signature.setParameter(pub.getParams());
          return signature;
        }
        break;
      case EDDSA:
        if (signatureFormat == Format.RAW) {
          try {
            return Signature.getInstance("EdDSA");
          } catch (NoSuchAlgorithmException ex) {
            // The name EdDSA is unknown.
          }
          // Try curve specific names
          JsonObject publicKey = group.get("publicKey").getAsJsonObject();
          String curve = getString(publicKey, "curve");
          // http://openjdk.java.net/jeps/339
          switch (curve) {
            case "edwards25519":
              return Signature.getInstance("ED25519");
            case "edwards448":
              return Signature.getInstance("ED448");
            default:
              break;
          }
        }
        break;
      default:
        break;
    }
    throw new NoSuchAlgorithmException(
        "Algorithm "
            + signatureAlgorithm.name()
            + " with format "
            + signatureFormat
            + " is not supported");
  }

  /**
   * Get a PublicKey from a JsonObject.
   *
   * <p>object contains the key in multiple formats: "publicKey" : elements of the public key
   * "publicLKeyDer": the key in ASN encoding encoded hexadecimal "publicKeyPem": the key in Pem
   * format encoded hexadecimal The test can use the format that is most convenient.
   */
  protected static PublicKey getPublicKey(JsonObject group, SignatureAlgorithm algorithm)
      throws Exception {
    KeyFactory kf;
    switch (algorithm) {
      case ECDSA:
      kf = KeyFactory.getInstance("EC");
        break;
      case EDDSA:
      // http://openjdk.java.net/jeps/339
      kf = KeyFactory.getInstance("EdDSA");
        break;
      case RSA_PKCS1:
      case RSA_PSS_WITHOUT_PARAMS:
        kf = KeyFactory.getInstance("RSA");
        break;
      case RSA_PSS_WITH_PARAMS:
        kf = KeyFactory.getInstance("RSASSA-PSS");
        break;
      case DSA:
        kf = KeyFactory.getInstance("DSA");
        break;
      default:
        throw new NoSuchAlgorithmException("Algorithm " + algorithm + " is not supported");
    }
    byte[] encoded = TestUtil.hexToBytes(getString(group, "publicKeyDer"));
    X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(encoded);
    return kf.generatePublic(x509keySpec);
  }

  /** Get a PrivateKey from a JsonObject. */
  protected static PrivateKey getPrivateKey(JsonObject object, SignatureAlgorithm algorithm)
      throws Exception {
    switch (algorithm) {
      case RSA_PKCS1:
        KeyFactory kf = KeyFactory.getInstance("RSA");
      byte[] encoded = TestUtil.hexToBytes(getString(object, "privateKeyPkcs8"));
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
      return kf.generatePrivate(keySpec);
      default:
      throw new NoSuchAlgorithmException("Algorithm " + algorithm + " is not supported");
    }
  }

  /**
   * Checks a single test vector.
   *
   * @param testVectors the test vectors containing the test vector to check.
   * @param testcase the test vector to verify
   * @param verifier a signature instance. This instance is not initialized. However, if the
   *     signature scheme uses additional parameters (such RSASSA-PSS) then these parameters must be
   *     set.
   * @param key the public key
   * @param testResult the result of the test are added to testResult
   */
  private static void singleTest(
      TestVectors testVectors,
      JsonObject testcase,
      Signature verifier,
      PublicKey key,
      TestResult testResult) {
    byte[] message = getBytes(testcase, "msg");
    byte[] signature = getBytes(testcase, "sig");
    int tcid = testcase.get("tcId").getAsInt();
    // Version 1.0 test vectors only contain test vectors with
    // result = "valid" or result = "invalid".
    String result = getString(testcase, "result");
    try {
      verifier.initVerify(key);
    } catch (InvalidKeyException ex) {
      testResult.addResult(tcid, TestResult.Type.REJECTED_ALGORITHM, "initVerify throws " + ex);
      return;
    } catch (RuntimeException ex) {
      testResult.addResult(tcid, TestResult.Type.WRONG_EXCEPTION, "initVerify throws " + ex);
      return;
    }

    try {
      verifier.update(message);
    } catch (SignatureException ex) {
      // verifier has been correctly initialized, hence we do not expect an exception.
      // Some implementations may check curves late. If this happens then it might be
      // possible to change the type to REJECTED.
      testResult.addResult(tcid, TestResult.Type.WRONG_EXCEPTION, "update throws " + ex);
      return;
    } catch (RuntimeException ex) {
      // However any exception other than SignatureException is unexpected.
      testResult.addResult(tcid, TestResult.Type.WRONG_EXCEPTION, "update throws " + ex);
      return;
    }

    boolean verified = false;
    try {
      verified = verifier.verify(signature);
    } catch (SignatureException ex) {
      // verify can throw SignatureExceptions if the signature is malformed.
      // We don't flag these cases and simply consider the signature as invalid.
      verified = false;
    } catch (RuntimeException ex) {
      testResult.addResult(tcid, TestResult.Type.WRONG_EXCEPTION, "verify throws " + ex);
      return;
    }

    TestResult.Type res;
    if (result.equals("valid")) {
      if (verified) {
        res = TestResult.Type.PASSED_VALID;
      } else {
        res = TestResult.Type.REJECTED_VALID;
      }
    } else {
      if (verified) {
        if (testVectors.isLegacy(tcid)) {
          res = TestResult.Type.PASSED_LEGACY;
        } else {
          res = TestResult.Type.NOT_REJECTED_INVALID;
        }
      } else {
        res = TestResult.Type.REJECTED_INVALID;
      }
    }
    testResult.addResult(tcid, res, "");
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
    String schema = getString(test, "schema");
    Format signatureFormat = getSignatureFormat(schema);
    assertFalse("Unsupported schema:" + schema, signatureFormat == Format.UNKNOWN);
    SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm(schema);
    assertFalse("Unsupported schema:" + schema, signatureAlgorithm == SignatureAlgorithm.UNKNOWN);
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      PublicKey key;
      Signature verifier;
      try {
        key = getPublicKey(group, signatureAlgorithm);
        verifier = getSignatureInstance(group, signatureAlgorithm, signatureFormat, key);
      } catch (GeneralSecurityException ex) {
        testResult.addFailure(TestResult.Type.REJECTED_ALGORITHM, ex.toString());
        continue;
      }
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        singleTest(testVectors, testcase, verifier, key, testResult);
      }
    }
    return testResult;
  }

  /**
   * Tests the signature verification with test vectors in a given JSON file.
   *
   * <p>Example format for test vectors
   *
   * <pre>
   * { "algorithm": "ECDSA",
   *   "generatorVersion": "0.9rc5",
   *   "numberOfTests": 217,
   *   "testGroups": [
   *     {
   *       "sha": "SHA-256",
   *       "publicKey": {
   *         "curve": "secp256r1",
   *         "type": "ECPublicKey",
   *         "wx": "0c9c4bc2617c81eb2dcbfda2db2a370a955be86a0d2e95fcb86a99f90cf046573",
   *         "wy": "0c400363b1b6bcc3595a7d6d3575ccebcbb03f90ba8e58da2bc4824272f4fecff" },
   *       "publicKeyDer": <X509encoded key>
   *       "publicKeyPem": "-----BEGIN PUBLIC KEY-----\ ... \n-----END PUBLIC KEY-----",
   *       "tests": [
   *         { "comment": "random signature",
   *           "msg": "48656c6c6f",
   *           "result": "valid",
   *           "sig": "...",
   *           "tcId": 1 },
   *    ... }
   * </pre>
   *
   * @param filename the filename of the test vectors
   * @param allowSkippingKeys if true then keys that cannot be constructed will not fail the test.
   *     This is for example used for files with test vectors that use elliptic curves that are not
   *     commonly supported.
   */
  public void testVerification(String filename, boolean allowSkippingKeys) throws Exception {
    JsonObject test = JsonUtil.getTestVectorsV1(filename);
    TestVectors testVectors = new TestVectors(test, filename);
    TestResult testResult = allTests(testVectors);

    if (testResult.skipTest()) {
      System.out.println("Skipping " + filename + " no signatures verified.");
      TestUtil.skipTest("No signatures were verified");
      return;
    }
    System.out.print(testResult.asString());
    assertEquals(0, testResult.errors());
    if (!allowSkippingKeys) {
      int skippedKeys = testResult.getCount(TestResult.Type.REJECTED_ALGORITHM);
      assertEquals(0, skippedKeys);
    }
  }

  /**
   * secp160k1, sepc160r1 and secp160r2 are curves with an order slightly larger than 2^160. This
   * means that the bitlength of n is 161, and hence that hash digests have to be truncated to 161
   * bits.
   */
  @Test
  public void testSecp160k1Sha256() throws Exception {
    testVerification("ecdsa_secp160k1_sha256_test.json", true);
  }

  @Test
  public void testSecp160r1Sha256() throws Exception {
    testVerification("ecdsa_secp160r1_sha256_test.json", true);
  }

  @Test
  public void testSecp160r2Sha256() throws Exception {
    testVerification("ecdsa_secp160r2_sha256_test.json", true);
  }

  @Test
  public void testSecp192k1Sha256() throws Exception {
    testVerification("ecdsa_secp192k1_sha256_test.json", true);
  }

  @Test
  public void testSecp192r1Sha256() throws Exception {
    testVerification("ecdsa_secp192r1_sha256_test.json", true);
  }

  @Test
  public void testSecp224r1Sha224() throws Exception {
    testVerification("ecdsa_secp224r1_sha224_test.json", false);
  }

  @Test
  public void testSecp224r1Sha256() throws Exception {
    testVerification("ecdsa_secp224r1_sha256_test.json", false);
  }

  @Test
  public void testSecp224r1Sha512() throws Exception {
    testVerification("ecdsa_secp224r1_sha512_test.json", false);
  }

  @Test
  public void testSecp256r1Sha256() throws Exception {
    testVerification("ecdsa_secp256r1_sha256_test.json", false);
  }

  @Test
  public void testSecp256r1Sha512() throws Exception {
    testVerification("ecdsa_secp256r1_sha512_test.json", false);
  }

  @Test
  public void testSecp384r1Sha384() throws Exception {
    testVerification("ecdsa_secp384r1_sha384_test.json", false);
  }

  @Test
  public void testSecp384r1Sha512() throws Exception {
    testVerification("ecdsa_secp384r1_sha512_test.json", false);
  }

  @Test
  public void testSecp521r1Sha512() throws Exception {
    testVerification("ecdsa_secp521r1_sha512_test.json", false);
  }

  // Testing curves that may not be supported by a provider.
  @Test
  public void testSecp256k1Sha256() throws Exception {
    testVerification("ecdsa_secp256k1_sha256_test.json", true);
  }

  @Test
  public void testSecp256k1Sha512() throws Exception {
    testVerification("ecdsa_secp256k1_sha512_test.json", true);
  }

  @Test
  public void testBrainpoolP224r1Sha224() throws Exception {
    testVerification("ecdsa_brainpoolP224r1_sha224_test.json", true);
  }

  @Test
  public void testBrainpoolP256r1Sha256() throws Exception {
    testVerification("ecdsa_brainpoolP256r1_sha256_test.json", true);
  }

  @Test
  public void testBrainpoolP320r1Sha384() throws Exception {
    testVerification("ecdsa_brainpoolP320r1_sha384_test.json", true);
  }

  @Test
  public void testBrainpoolP384r1Sha384() throws Exception {
    testVerification("ecdsa_brainpoolP384r1_sha384_test.json", true);
  }

  @Test
  public void testBrainpoolP512r1Sha512() throws Exception {
    testVerification("ecdsa_brainpoolP512r1_sha512_test.json", true);
  }

  // SHA-3 signatures
  @Test
  public void testSecp224r1Sha3_224 () throws Exception {
    testVerification("ecdsa_secp224r1_sha3_224_test.json", true);
  }

  @Test
  public void testSecp224r1Sha3_256 () throws Exception {
    testVerification("ecdsa_secp224r1_sha3_256_test.json", true);
  }

  @Test
  public void testSecp224r1Sha3_512 () throws Exception {
    testVerification("ecdsa_secp224r1_sha3_512_test.json", true);
  }

  @Test
  public void testSecp256r1Sha3_256 () throws Exception {
    testVerification("ecdsa_secp256r1_sha3_256_test.json", true);
  }

  @Test
  public void testSecp256r1Sha3_512 () throws Exception {
    testVerification("ecdsa_secp256r1_sha3_512_test.json", true);
  }

  @Test
  public void testSecp256k1Sha3_256 () throws Exception {
    testVerification("ecdsa_secp256k1_sha3_256_test.json", true);
  }

  @Test
  public void testSecp256k1Sha3_512 () throws Exception {
    testVerification("ecdsa_secp256k1_sha3_512_test.json", true);
  }

  @Test
  public void testSecp384r1Sha3_384 () throws Exception {
    testVerification("ecdsa_secp384r1_sha3_384_test.json", true);
  }

  @Test
  public void testSecp384r1Sha3_512 () throws Exception {
    testVerification("ecdsa_secp384r1_sha3_512_test.json", true);
  }

  @Test
  public void testSecp521r1Sha3_512 () throws Exception {
    testVerification("ecdsa_secp521r1_sha3_512_test.json", true);
  }

  @Test
  public void testSecp224r1Shake128() throws Exception {
    testVerification("ecdsa_secp224r1_shake128_test.json", true);
  }

  @Test
  public void testSecp256r1Shake128() throws Exception {
    testVerification("ecdsa_secp256r1_shake128_test.json", true);
  }

  @Test
  public void testSecp256k1Shake128() throws Exception {
    testVerification("ecdsa_secp256k1_shake128_test.json", true);
  }

  @Test
  public void testSecp256k1Shake256() throws Exception {
    testVerification("ecdsa_secp256k1_shake256_test.json", true);
  }

  @Test
  public void testSecp384r1Shake256() throws Exception {
    testVerification("ecdsa_secp384r1_shake256_test.json", true);
  }

  @Test
  public void testSecp521Shake256() throws Exception {
    testVerification("ecdsa_secp521r1_shake256_test.json", true);
  }

  // jdk11 adds P1363 encoded signatures.
  @Test
  public void testSecp160k1Sha256inP1363Format() throws Exception {
    testVerification("ecdsa_secp160k1_sha256_p1363_test.json", true);
  }

  @Test
  public void testSecp160r1Sha256inP1363Format() throws Exception {
    testVerification("ecdsa_secp160r1_sha256_p1363_test.json", true);
  }

  @Test
  public void testSecp160r2Sha256inP1363Format() throws Exception {
    testVerification("ecdsa_secp160r2_sha256_p1363_test.json", true);
  }

  @Test
  public void testSecp192k1Sha256inP1363Format() throws Exception {
    testVerification("ecdsa_secp192k1_sha256_p1363_test.json", true);
  }

  @Test
  public void testSecp192r1Sha256inP1363Format() throws Exception {
    testVerification("ecdsa_secp192r1_sha256_p1363_test.json", true);
  }

  @Test
  public void testSecp224r1Sha224inP1363Format() throws Exception {
    testVerification("ecdsa_secp224r1_sha224_p1363_test.json", true);
  }

  @Test
  public void testSecp224r1Sha256inP1363Format() throws Exception {
    testVerification("ecdsa_secp224r1_sha256_p1363_test.json", true);
  }

  @Test
  public void testSecp224r1Sha512inP1363Format() throws Exception {
    testVerification("ecdsa_secp224r1_sha512_p1363_test.json", true);
  }

  @Test
  public void testSecp256r1Sha256inP1363Format() throws Exception {
    testVerification("ecdsa_secp256r1_sha256_p1363_test.json", true);
  }

  @Test
  public void testSecp256r1Sha512inP1363Format() throws Exception {
    testVerification("ecdsa_secp256r1_sha512_p1363_test.json", true);
  }

  @Test
  public void testSecp384r1Sha384inP1363Format() throws Exception {
    testVerification("ecdsa_secp384r1_sha384_p1363_test.json", true);
  }

  @Test
  public void testSecp384r1Sha512inP1363Format() throws Exception {
    testVerification("ecdsa_secp384r1_sha512_p1363_test.json", true);
  }

  @Test
  public void testSecp521r1Sha512inP1363Format() throws Exception {
    testVerification("ecdsa_secp521r1_sha512_p1363_test.json", true);
  }

  @Test
  public void testSecp256k1Sha256inP1363Format() throws Exception {
    testVerification("ecdsa_secp256k1_sha256_p1363_test.json", true);
  }

  @Test
  public void testSecp256k1Sha512inP1363Format() throws Exception {
    testVerification("ecdsa_secp256k1_sha512_p1363_test.json", true);
  }

  @Test
  public void testBrainpoolP224r1Sha224inP1363Format() throws Exception {
    testVerification("ecdsa_brainpoolP224r1_sha224_p1363_test.json", true);
  }

  @Test
  public void testBrainpoolP256r1Sha256inP1363Format() throws Exception {
    testVerification("ecdsa_brainpoolP256r1_sha256_p1363_test.json", true);
  }

  @Test
  public void testBrainpoolP320r1Sha384inP1363Format() throws Exception {
    testVerification("ecdsa_brainpoolP320r1_sha384_p1363_test.json", true);
  }

  @Test
  public void testBrainpoolP384r1Sha384inP1363Format() throws Exception {
    testVerification("ecdsa_brainpoolP384r1_sha384_p1363_test.json", true);
  }

  @Test
  public void testBrainpoolP512r1Sha512inP1363Format() throws Exception {
    testVerification("ecdsa_brainpoolP512r1_sha512_p1363_test.json", true);
  }

  @Test
  public void testSecp224r1Shake128inP1363Format() throws Exception {
    testVerification("ecdsa_secp224r1_shake128_p1363_test.json", true);
  }

  @Test
  public void testSecp256r1Shake128inP1363Format() throws Exception {
    testVerification("ecdsa_secp256r1_shake128_p1363_test.json", true);
  }

  @Test
  public void testSecp256k1Shake128inP1363Format() throws Exception {
    testVerification("ecdsa_secp256k1_shake128_p1363_test.json", true);
  }

  @Test
  public void testSecp256k1Shake256inP1363Format() throws Exception {
    testVerification("ecdsa_secp256k1_shake256_p1363_test.json", true);
  }

  @Test
  public void testSecp384r1Shake256inP1363Format() throws Exception {
    testVerification("ecdsa_secp384r1_shake256_p1363_test.json", true);
  }

  @Test
  public void testSecp521Shake256inP1363Format() throws Exception {
    testVerification("ecdsa_secp521r1_shake256_p1363_test.json", true);
  }

  @Test
  public void testRsaSignature2048sha224() throws Exception {
    testVerification("rsa_signature_2048_sha224_test.json", false);
  }

  @Test
  public void testRsaSignatures2048sha256() throws Exception {
    testVerification("rsa_signature_2048_sha256_test.json", false);
  }

  @Test
  public void testRsaSignatures2048sha384() throws Exception {
    testVerification("rsa_signature_2048_sha384_test.json", false);
  }

  @Test
  public void testRsaSignatures2048sha512() throws Exception {
    testVerification("rsa_signature_2048_sha512_test.json", false);
  }

  @Test
  public void testRsaSignatures3072sha256() throws Exception {
    testVerification("rsa_signature_3072_sha256_test.json", false);
  }

  @Test
  public void testRsaSignatures3072sha384() throws Exception {
    testVerification("rsa_signature_3072_sha384_test.json", false);
  }

  @Test
  public void testRsaSignatures3072sha512() throws Exception {
    testVerification("rsa_signature_3072_sha512_test.json", false);
  }

  @Test
  public void testRsaSignatures4096sha384() throws Exception {
    testVerification("rsa_signature_4096_sha384_test.json", false);
  }

  @Test
  public void testRsaSignatures4096sha512() throws Exception {
    testVerification("rsa_signature_4096_sha512_test.json", false);
  }

  // RSA signatures with truncated hashes. Tests may be skipped if the provider
  // does not support the hash.
  @Test
  public void testRsaSignatures2048sha512_224() throws Exception {
    testVerification("rsa_signature_2048_sha512_224_test.json", true);
  }

  @Test
  public void testRsaSignatures2048sha512_256() throws Exception {
    testVerification("rsa_signature_2048_sha512_256_test.json", true);
  }

  @Test
  public void testRsaSignatures3072sha512_256() throws Exception {
    testVerification("rsa_signature_3072_sha512_256_test.json", true);
  }

  @Test
  public void testRsaSignatures4096sha512_256() throws Exception {
    testVerification("rsa_signature_4096_sha512_256_test.json", true);
  }

  // RSA signatures with SHA-3. Not every provider supports SHA-3. Hence the tests
  // may be skipped.
  @Test
  public void testRsaSignature2048sha3_224() throws Exception {
    testVerification("rsa_signature_2048_sha3_224_test.json", true);
  }

  @Test
  public void testRsaSignatures2048sha3_256() throws Exception {
    testVerification("rsa_signature_2048_sha3_256_test.json", true);
  }

  @Test
  public void testRsaSignatures2048sha3_512() throws Exception {
    testVerification("rsa_signature_2048_sha3_512_test.json", true);
  }

  @Test
  public void testRsaSignatures3072sha3_256() throws Exception {
    testVerification("rsa_signature_3072_sha3_256_test.json", true);
  }

  @Test
  public void testRsaSignatures3072sha3_384() throws Exception {
    testVerification("rsa_signature_3072_sha3_384_test.json", true);
  }

  @Test
  public void testRsaSignatures3072sha3_512() throws Exception {
    testVerification("rsa_signature_3072_sha3_512_test.json", true);
  }

  // EdDSA
  @Test
  public void testEd25519Verify() throws Exception {
    testVerification("ed25519_test.json", true);
  }

  @Test
  public void testEd448Verify() throws Exception {
    testVerification("ed448_test.json", true);
  }

  // DSA
  // Two signature encodings for DSA are tested below: ASN encoded signatures
  // and P1363 encoded signatures.
  @Test
  public void testDsa2048Sha224() throws Exception {
    testVerification("dsa_2048_224_sha224_test.json", true);
  }

  // NIST allows 2048-bit DSA keys with either a 224-bit q or a 256-bit q.
  // In both cases the security level is 112-bit.
  // Jdk generates DSA keys with a 224-bit q (unless specified).
  @Test
  public void testDsa2048JdkSha256() throws Exception {
    testVerification("dsa_2048_224_sha256_test.json", true);
  }

  // OpenSSL generates DSA keys with a 256-bit q (unless specified).
  @Test
  public void testDsa2048Sha256() throws Exception {
    testVerification("dsa_2048_256_sha256_test.json", true);
  }

  @Test
  public void testDsa3072Sha256() throws Exception {
    testVerification("dsa_3072_256_sha256_test.json", true);
  }

  // DSA tests using P1363 formated signatures.
  @Test
  public void testDsa2048Sha224inP1363Format() throws Exception {
    testVerification("dsa_2048_224_sha224_p1363_test.json", true);
  }

  @Test
  public void testDsa2048JdkSha256inP1363Format() throws Exception {
    testVerification("dsa_2048_224_sha256_p1363_test.json", true);
  }

  @Test
  public void testDsa2048Sha256inP1363Format() throws Exception {
    testVerification("dsa_2048_256_sha256_p1363_test.json", true);
  }

  @Test
  public void testDsa3072Sha256inP1363Format() throws Exception {
    testVerification("dsa_3072_256_sha256_p1363_test.json", true);
  }

  @Test
  public void testRsaPss2048Sha256() throws Exception {
    testVerification("rsa_pss_2048_sha256_mgf1_32_test.json", true);
  }

  @Test
  public void testRsaPss3072Sha256() throws Exception {
    testVerification("rsa_pss_3072_sha256_mgf1_32_test.json", true);
  }

  @Test
  public void testRsaPss4096Sha256() throws Exception {
    testVerification("rsa_pss_4096_sha256_mgf1_32_test.json", true);
  }

  @Test
  public void testRsaPss4096Sha512() throws Exception {
    testVerification("rsa_pss_4096_sha512_mgf1_32_test.json", true);
  }

  // Testing RSA-PSS implementation where the salt is 0.
  // This makes the signature scheme deterministic.
  @Test
  public void testRsaPss2048Sha256NoSalt() throws Exception {
    testVerification("rsa_pss_2048_sha256_mgf1_0_test.json", true);
  }

  // Testing RSA-PSS implementation where the hash is SHA-512/224.
  // Such hashes are frequently not supported.
  @Test
  public void testRsaPss2048Sha512_224() throws Exception {
    testVerification("rsa_pss_2048_sha512_224_mgf1_28_test.json", true);
  }

  // Testing RSA-PSS implementation where the hash is SHA-512/256.
  // Such hashes are frequently not supported.
  @Test
  public void testRsaPss2048Sha512_256() throws Exception {
    testVerification("rsa_pss_2048_sha512_256_mgf1_32_test.json", true);
  }

  // Testing RSA-PSS implementation using SHA-1
  @Test
  public void testRsaPss2048Sha256Mgf1Sha1() throws Exception {
    testVerification("rsa_pss_2048_sha1_mgf1_20_test.json", true);
  }

  // RSASSA-PSS with algorithm parameters
  @Test
  public void testRsaPss2048Sha1Mgf1Params() throws Exception {
    testVerification("rsa_pss_2048_sha1_mgf1_20_params_test.json", true);
  }

  @Test
  public void testRsaPss2048Sha256Mgf1Params() throws Exception {
    testVerification("rsa_pss_2048_sha256_mgf1_32_params_test.json", true);
  }

  @Test
  public void testRsaPss2048Sha256Mgf1NoSaltParams() throws Exception {
    testVerification("rsa_pss_2048_sha256_mgf1_0_params_test.json", true);
  }

  @Test
  public void testRsaPss2048Sha512Mgf1Sha1Params() throws Exception {
    testVerification("rsa_pss_2048_sha512_mgf1sha256_32_params_test.json", true);
  }

  @Test
  public void testRsaPss3072Sha256Mgf1Params() throws Exception {
    testVerification("rsa_pss_3072_sha256_mgf1_32_params_test.json", true);
  }

  @Test
  public void testRsaPss4096Sha512Mgf1Params() throws Exception {
    testVerification("rsa_pss_4096_sha512_mgf1_64_params_test.json", true);
  }

  @Test
  public void testRsaPss4096Sha512Mgf1Sha512_32Params() throws Exception {
    testVerification("rsa_pss_4096_sha512_mgf1_32_params_test.json", true);
  }

  @Test
  public void testRsaPss2048Shake128Params() throws Exception {
    testVerification("rsa_pss_2048_shake128_params_test.json", true);
  }

  @Test
  public void testRsaPss2072Shake256Params() throws Exception {
    testVerification("rsa_pss_3072_shake256_params_test.json", true);
  }

  @Test
  public void testRsaPss4096Shake256Params() throws Exception {
    testVerification("rsa_pss_4096_shake256_params_test.json", true);
  }
}

