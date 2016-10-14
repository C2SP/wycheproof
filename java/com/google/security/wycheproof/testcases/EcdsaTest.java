/**
 * @license
 * Copyright 2016 Google Inc. All rights reserved.
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

import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import com.google.security.wycheproof.WycheproofRunner.SlowTest;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import junit.framework.TestCase;

/**
 * Tests ECDSA against invalid signatures.
 *
 * @author bleichen@google.com (Daniel Bleichenbacher)
 */
// Tested providers:
//   SunEC: accepts a few alternative encodings and throws run time exceptions.
//     The implementation does not protect against timing attacks.
//   BC: accepts alternative encoding, and additional arguments
//   AndroidOpenSSL: OK
// TODO(bleichen):
//   - CVE-2015-2730: Firefox failed to handle some signatures correctly because of incorrect
//     point multiplication. (I don't have enough information here.)
public class EcdsaTest extends TestCase {
  // ECDSA-Key1
  static final String MESSAGE = "Hello";
  static final String CURVE = "secp256r1";
  static final BigInteger PubX =
      new BigInteger(
          "3390396496586153202365024500890309020181905168626402195853036609" + "0984128098564");
  static final BigInteger PubY =
      new BigInteger(
          "1135421298983937257390683162600855221890652900790509030911087400" + "65052129055287");

  // Valid signatures for MESSAGE
  static final String[] VALID_SIGNATURES = {
    "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
  };

  /**
   * Test vectors with invalid signatures. The motivation for these test vectors are previously
   * broken implementations. - The implementation of DSA in gpg4browsers accepted signatures with
   * r=1 and s=q as valid. Similar bugs in ECDSA are thinkable, hence the test vectors contain a
   * number of tests with edge case integers. - CVE-2013-2944: strongSwan 5.0.4 accepts invalid
   * ECDSA signatures when openssl is used. (Not sure if the following interpretation is correct,
   * because of missing details). OpenSSLs error codes are easy to misinterpret. For many functions
   * the result can be 0 (verification failed), 1 (verification succeded) or -1 (invalid format). A
   * simple if (result) { ... } will be incorrect in such situations. The test vectors below contain
   * incorrectly encoded signatures. - careless ASN parsing. For example SunEC throws various run
   * time exceptions when the ASN encoding is broken. NOTE(bleichen): The following test vectors
   * were generated with some python code. New test vectors should best be done by extending this
   * code.
   */
  static final String[] INVALID_SIGNATURES = {
    // missing argument
    "30220220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f4" + "3260ecce",
    "3023022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49" + "1b39fd2c3f",
    "",
    // empty
    "302402000220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd" + "59f43260ecce",
    "3025022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49" + "1b39fd2c3f0200",
    "3000",
    // integer overflows
    "304a0285010000002100b7babae9332b54b8a3a05b7004579821a887a1b21465"
        + "f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c1"
        + "06a6e76285cd59f43260ecce",
    "304e028901000000000000002100b7babae9332b54b8a3a05b7004579821a887"
        + "a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f"
        + "94e418c106a6e76285cd59f43260ecce",
    "304a022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f02850100000020747291dd2f3f44af7ace68ea33431d6f94e418c1"
        + "06a6e76285cd59f43260ecce",
    "304e022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0289010000000000000020747291dd2f3f44af7ace68ea33431d6f"
        + "94e418c106a6e76285cd59f43260ecce",
    "30850100000045022100b7babae9332b54b8a3a05b7004579821a887a1b21465"
        + "f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c1"
        + "06a6e76285cd59f43260ecce",
    "3089010000000000000045022100b7babae9332b54b8a3a05b7004579821a887"
        + "a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f"
        + "94e418c106a6e76285cd59f43260ecce",
    // infinity
    "30250901800220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285" + "cd59f43260ecce",
    "3026022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49" + "1b39fd2c3f090180",
    // Signatures with special case values for r and s (such as 0 and 1).
    // Such values often uncover implementation errors.
    "300402000200",
    "30050200020101",
    "300502000201ff",
    "30250200022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3" + "b9cac2fc632551",
    "30250200022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3" + "b9cac2fc632550",
    "30250200022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3" + "b9cac2fc632552",
    "30250200022100ffffffff00000001000000000000000000000000ffffffffff" + "ffffffffffffff",
    "30250200022100ffffffff000000010000000000000000000000010000000000" + "00000000000000",
    "30070200090380fe01",
    "30050201010200",
    "3006020101020101",
    "30060201010201ff",
    "3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84" + "f3b9cac2fc632551",
    "3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84" + "f3b9cac2fc632550",
    "3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84" + "f3b9cac2fc632552",
    "3026020101022100ffffffff00000001000000000000000000000000ffffffff" + "ffffffffffffffff",
    "3026020101022100ffffffff0000000100000000000000000000000100000000" + "0000000000000000",
    "3008020101090380fe01",
    "30050201ff0200",
    "30060201ff020101",
    "30060201ff0201ff",
    "30260201ff022100ffffffff00000000ffffffffffffffffbce6faada7179e84" + "f3b9cac2fc632551",
    "30260201ff022100ffffffff00000000ffffffffffffffffbce6faada7179e84" + "f3b9cac2fc632550",
    "30260201ff022100ffffffff00000000ffffffffffffffffbce6faada7179e84" + "f3b9cac2fc632552",
    "30260201ff022100ffffffff00000001000000000000000000000000ffffffff" + "ffffffffffffffff",
    "30260201ff022100ffffffff0000000100000000000000000000000100000000" + "0000000000000000",
    "30080201ff090380fe01",
    "3025022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca" + "c2fc6325510200",
    "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca" + "c2fc632551020101",
    "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca" + "c2fc6325510201ff",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632551022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632551",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632551022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632550",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632551022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632552",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632551022100ffffffff00000001000000000000000000000000ffffffff"
        + "ffffffffffffffff",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632551022100ffffffff0000000100000000000000000000000100000000"
        + "0000000000000000",
    "3028022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca" + "c2fc632551090380fe01",
    "3025022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca" + "c2fc6325500200",
    "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca" + "c2fc632550020101",
    "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca" + "c2fc6325500201ff",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632550022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632551",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632550022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632550",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632550022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632552",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632550022100ffffffff00000001000000000000000000000000ffffffff"
        + "ffffffffffffffff",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632550022100ffffffff0000000100000000000000000000000100000000"
        + "0000000000000000",
    "3028022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca" + "c2fc632550090380fe01",
    "3025022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca" + "c2fc6325520200",
    "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca" + "c2fc632552020101",
    "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca" + "c2fc6325520201ff",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632552022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632551",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632552022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632550",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632552022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632552",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632552022100ffffffff00000001000000000000000000000000ffffffff"
        + "ffffffffffffffff",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632552022100ffffffff0000000100000000000000000000000100000000"
        + "0000000000000000",
    "3028022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca" + "c2fc632552090380fe01",
    "3025022100ffffffff00000001000000000000000000000000ffffffffffffff" + "ffffffffff0200",
    "3026022100ffffffff00000001000000000000000000000000ffffffffffffff" + "ffffffffff020101",
    "3026022100ffffffff00000001000000000000000000000000ffffffffffffff" + "ffffffffff0201ff",
    "3046022100ffffffff00000001000000000000000000000000ffffffffffffff"
        + "ffffffffff022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632551",
    "3046022100ffffffff00000001000000000000000000000000ffffffffffffff"
        + "ffffffffff022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632550",
    "3046022100ffffffff00000001000000000000000000000000ffffffffffffff"
        + "ffffffffff022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632552",
    "3046022100ffffffff00000001000000000000000000000000ffffffffffffff"
        + "ffffffffff022100ffffffff00000001000000000000000000000000ffffffff"
        + "ffffffffffffffff",
    "3046022100ffffffff00000001000000000000000000000000ffffffffffffff"
        + "ffffffffff022100ffffffff0000000100000000000000000000000100000000"
        + "0000000000000000",
    "3028022100ffffffff00000001000000000000000000000000ffffffffffffff" + "ffffffffff090380fe01",
    "3025022100ffffffff0000000100000000000000000000000100000000000000" + "00000000000200",
    "3026022100ffffffff0000000100000000000000000000000100000000000000" + "0000000000020101",
    "3026022100ffffffff0000000100000000000000000000000100000000000000" + "00000000000201ff",
    "3046022100ffffffff0000000100000000000000000000000100000000000000"
        + "0000000000022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632551",
    "3046022100ffffffff0000000100000000000000000000000100000000000000"
        + "0000000000022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632550",
    "3046022100ffffffff0000000100000000000000000000000100000000000000"
        + "0000000000022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632552",
    "3046022100ffffffff0000000100000000000000000000000100000000000000"
        + "0000000000022100ffffffff00000001000000000000000000000000ffffffff"
        + "ffffffffffffffff",
    "3046022100ffffffff0000000100000000000000000000000100000000000000"
        + "0000000000022100ffffffff0000000100000000000000000000000100000000"
        + "0000000000000000",
    "3028022100ffffffff0000000100000000000000000000000100000000000000" + "0000000000090380fe01",
  };

  /**
   * Determines the Hash name from the ECDSA algorithm. There is a small inconsistency in the naming
   * of algorithms. The Oracle standard use no hyphen in SHA256WithECDSA but uses a hyphen in the
   * message digest, i.e., SHA-256.
   */
  public String getHashAlgorithm(String ecdsaAlgorithm) {
    ecdsaAlgorithm = ecdsaAlgorithm.toUpperCase();
    int idx = ecdsaAlgorithm.indexOf("WITH");
    if (idx > 0) {
      if (ecdsaAlgorithm.startsWith("SHA")) {
        return "SHA-" + ecdsaAlgorithm.substring(3, idx);
      } else {
        return ecdsaAlgorithm.substring(0, idx);
      }
    }
    return "";
  }

  /**
   * Extract the integer r from an ECDSA signature. This method implicitely assumes that the ECDSA
   * signature is DER encoded. and that the order of the curve is smaller than 2^1024.
   */
  BigInteger extractR(byte[] signature) throws Exception {
    int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
    int lengthR = signature[startR + 1];
    return new BigInteger(Arrays.copyOfRange(signature, startR + 2, startR + 2 + lengthR));
  }

  BigInteger extractS(byte[] signature) throws Exception {
    int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
    int lengthR = signature[startR + 1];
    int startS = startR + 2 + lengthR;
    int lengthS = signature[startS + 1];
    return new BigInteger(Arrays.copyOfRange(signature, startS + 2, startS + 2 + lengthS));
  }

  /** Extract the k that was used to sign the signature. */
  BigInteger extractK(byte[] signature, BigInteger h, ECPrivateKey priv) throws Exception {
    BigInteger x = priv.getS();
    BigInteger n = priv.getParams().getOrder();
    BigInteger r = extractR(signature);
    BigInteger s = extractS(signature);
    BigInteger k = x.multiply(r).add(h).multiply(s.modInverse(n)).mod(n);
    return k;
  }

  public ECPublicKeySpec publicKey1() throws Exception {
    ECParameterSpec params = EcUtil.getNistP256Params();
    ECPoint w = new ECPoint(PubX, PubY);
    return new ECPublicKeySpec(w, params);
  }

  public void testVectors(
      String[] signatures,
      ECPublicKeySpec pubSpec,
      String message,
      String algorithm,
      String signatureType,
      boolean isValid)
      throws Exception {
    byte[] messageBytes = message.getBytes("UTF-8");
    Signature verifier = Signature.getInstance(algorithm);
    KeyFactory kf = KeyFactory.getInstance("EC");
    ECPublicKey pub = (ECPublicKey) kf.generatePublic(pubSpec);
    int errors = 0;
    for (String signature : signatures) {
      byte[] signatureBytes = TestUtil.hexToBytes(signature);
      verifier.initVerify(pub);
      verifier.update(messageBytes);
      boolean verified = false;
      try {
        verified = verifier.verify(signatureBytes);
      } catch (SignatureException ex) {
        // verify can throw SignatureExceptions if the signature is malformed.
        // We don't flag these cases and simply consider the signature as invalid.
        verified = false;
      }
      //
      if (isValid && !verified) {
        System.out.println(signatureType + " was not verified:" + signature);
        errors++;
      } else if (!isValid && verified) {
        System.out.println(signatureType + " was verified:" + signature);
        errors++;
      }
    }
    assertEquals(0, errors);
  }

  public void testValidSignatures() throws Exception {
    testVectors(
        VALID_SIGNATURES, publicKey1(), "Hello", "SHA256WithECDSA", "Valid ECDSA signature", true);
  }

  public void testInvalidSignatures() throws Exception {
    testVectors(
        INVALID_SIGNATURES,
        publicKey1(),
        "Hello",
        "SHA256WithECDSA",
        "Invalid ECDSA signature",
        false);
  }

  /**
   * This test checks the basic functionality of ECDSA. It can also be used to generate simple test
   * vectors.
   */
  public void testBasic() throws Exception {
    String algorithm = "SHA256WithECDSA";
    String hashAlgorithm = "SHA-256";
    String message = "Hello";
    String curve = "secp256r1";

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
    keyGen.initialize(ecSpec);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

    byte[] messageBytes = message.getBytes("UTF-8");
    Signature signer = Signature.getInstance(algorithm);
    Signature verifier = Signature.getInstance(algorithm);
    signer.initSign(priv);
    signer.update(messageBytes);
    byte[] signature = signer.sign();
    verifier.initVerify(pub);
    verifier.update(messageBytes);
    assertTrue(verifier.verify(signature));

    // Extract some parameters.
    byte[] rawHash = MessageDigest.getInstance(hashAlgorithm).digest(messageBytes);
    ECParameterSpec params = priv.getParams();

    // Print keys and signature, so that it can be used to generate new test vectors.
    System.out.println("Message:" + message);
    System.out.println("Hash:" + TestUtil.bytesToHex(rawHash));
    System.out.println("Curve:" + curve);
    System.out.println("Order:" + params.getOrder().toString());
    System.out.println("Private key:");
    System.out.println("S:" + priv.getS().toString());
    System.out.println("encoded:" + TestUtil.bytesToHex(priv.getEncoded()));
    System.out.println("Public key:");
    ECPoint w = pub.getW();
    System.out.println("X:" + w.getAffineX().toString());
    System.out.println("Y:" + w.getAffineY().toString());
    System.out.println("encoded:" + TestUtil.bytesToHex(pub.getEncoded()));
    System.out.println("Signature:" + TestUtil.bytesToHex(signature));
    System.out.println("r:" + extractR(signature).toString());
    System.out.println("s:" + extractS(signature).toString());
  }

  /** Checks whether the one time key k in ECDSA is biased. */
  public void testBias(String algorithm, String curve, ECParameterSpec ecParams) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    try {
      keyGen.initialize(ecParams);
    } catch (InvalidAlgorithmParameterException ex) {
      System.out.println("This provider does not support curve:" + curve);
      return;
    }
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    // If we throw a fair coin tests times then the probability that
    // either heads or tails appears less than mincount is less than 2^{-32}.
    // Therefore the test below is not expected to fail unless the generation
    // of the one time keys is indeed biased.
    final int tests = 1024;
    final int mincount = 410;

    String hashAlgorithm = getHashAlgorithm(algorithm);
    String message = "Hello";
    byte[] messageBytes = message.getBytes("UTF-8");
    byte[] digest = MessageDigest.getInstance(hashAlgorithm).digest(messageBytes);

    // TODO(bleichen): Truncate the digest if the digest size is larger than the
    //   curve size.
    BigInteger h = new BigInteger(1, digest);
    BigInteger q = priv.getParams().getOrder();
    BigInteger qHalf = q.shiftRight(1);

    Signature signer = Signature.getInstance(algorithm);
    signer.initSign(priv);
    int countLsb = 0; // count the number of k's with msb set
    int countMsb = 0; // count the number of k's with lsb set
    for (int i = 0; i < tests; i++) {
      signer.update(messageBytes);
      byte[] signature = signer.sign();
      BigInteger k = extractK(signature, h, priv);
      if (k.testBit(0)) {
        countLsb++;
      }
      if (k.compareTo(qHalf) == 1) {
        countMsb++;
      }
    }
    System.out.println(
        signer.getProvider().getName()
            + " curve:"
            + curve
            + " countLsb:"
            + countLsb
            + " countMsb:"
            + countMsb);
    if (countLsb < mincount || countLsb > tests - mincount) {
      fail("Bias detected in the least significant bit of k:" + countLsb);
    }
    if (countMsb < mincount || countMsb > tests - mincount) {
      fail("Bias detected in the most significant bit of k:" + countMsb);
    }
  }

  @SlowTest(providers = {ProviderType.BOUNCY_CASTLE, ProviderType.CONSCRYPT, ProviderType.OPENJDK,
    ProviderType.SPONGY_CASTLE})
  public void testBiasAll() throws Exception {
    testBias("SHA256WithECDSA", "secp256r1", EcUtil.getNistP256Params());
    testBias("SHA224WithECDSA", "secp224r1", EcUtil.getNistP224Params());
    testBias("SHA384WithECDSA", "secp384r1", EcUtil.getNistP384Params());
    testBias("SHA512WithECDSA", "secp521r1", EcUtil.getNistP521Params());
    testBias("SHA256WithECDSA", "brainpoolP256r1", EcUtil.getBrainpoolP256r1Params());
  }
}
