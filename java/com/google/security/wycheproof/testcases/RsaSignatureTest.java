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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests PKCS #1 v 1.5 signatures
 *
 * <p>Most of the tests that were previously in this class have been replaced by test vectors and
 * are now tested in JsonSignatureTest.java.
 */
@RunWith(JUnit4.class)
public class RsaSignatureTest {

  @Test
  public void testBasic() throws Exception {
    final String algorithm = "SHA256WithRSA";
    int keysize = 2048;

    Signature signer;
    Signature verifier;
    RSAPrivateKey priv;
    RSAPublicKey pub;
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(keysize);
      KeyPair keyPair = keyGen.generateKeyPair();
      pub = (RSAPublicKey) keyPair.getPublic();
      priv = (RSAPrivateKey) keyPair.getPrivate();
      signer = Signature.getInstance(algorithm);
      verifier = Signature.getInstance(algorithm);
    } catch (GeneralSecurityException ex) {
      TestUtil.skipTest(algorithm + " is not supported:" + ex);
      return;
    }
    try {
      String message = "Hello";
      byte[] messageBytes = message.getBytes(UTF_8);
      signer.initSign(priv);
      signer.update(messageBytes);
      byte[] signature = signer.sign();
      verifier.initVerify(pub);
      verifier.update(messageBytes);
      assertTrue(verifier.verify(signature));
    } catch (GeneralSecurityException ex) {
      throw new AssertionError("Failed to sign a message with " + algorithm, ex);
    }
  }

  /**
   * Faults during the generation of a signature can leak the information about the private key. A.
   * K. Lenstra showed in "Memo on RSA signature generation in the presence of faults",
   * (https://infoscience.epfl.ch/record/164524/files/nscan20.PDF) that PKCS #1 signatures are
   * especially susceptible to faults when the Chinese Remainder Theorem is used to compute the
   * signature: one single faulty signature is sufficient to leak the private key.
   *
   * <p>One countermeasure that is often used in libraries is to blind the RSA computation and
   * verify the signature before returning it. Nowadays, libraries are expected to have at least
   * some countermeasures against faulty computations. In some cases (e.g. OpenSSL) the library
   * tries to fix a faulty computation by generating a correct signature without using Chinese
   * remaindering.
   *
   * <p>The test here does not induce a fault. Instead it tries to sign with a faulty private key.
   * The expected outcome of the test is that underlying provider either detects that the fault or
   * generates a valid signature by ignoring the faulty parameter.
   *
   * <p>Since the test only simulates a fault, but does not actually induce a fault it is somewhat
   * incomplete. It does not detect all vulnerable implementations. The test should nonetheless
   * detect implementations that include no verification at all.
   */
  @Test
  public void testFaultySigner() {
    BigInteger e = new BigInteger("65537");
    BigInteger d = new BigInteger(
        "1491581187972832788084570222215155297353839087630599492610691218"
            + "6098027383804966741416365668088258821394558334495197493887270311"
            + "7558637148793177374456685063919969705672268324029058661801838398"
            + "1099187046803818325657704350675941092582695993374867459573741707"
            + "2513551423973482044545986645893321692393572214394692273248819124"
            + "5866638922766330300631727125395012955305761836925591665625409882"
            + "5987442083465656021724458811783361811914866856391248003733867121"
            + "5531501554906114868306919889638573670925006068497222709802245970"
            + "0014474779292382225845722344584808716054088377124806520166137504"
            + "58797849822813881641713404303944154638273");
    BigInteger q = new BigInteger(
        "1327930250247153291239240833779228146841620599139480980326615632"
            + "6868823273498280322301518048955331731683358443542450740927959439"
            + "3056349447047388914345605165927201322192706870545643991584573901"
            + "9099563807204264522234257863225478717589651408831271029849307682"
            + "13198832542217762257092135384802889866043941823057701");
    BigInteger p = new BigInteger(
        "1546732137638443281784728718025150988901748595222448633054370906"
            + "7724307988669542799529278238746541544956234718616481585427107180"
            + "6134464028933334724614223213582911567222033332353858049787180486"
            + "8311341830570208335451999930773903649599388066890163502238099141"
            + "76306676019969635213034585825883528127235874684082417");

    BigInteger n = p.multiply(q);
    BigInteger dp = d.mod(p.subtract(BigInteger.ONE));
    BigInteger dq = d.mod(q.subtract(BigInteger.ONE));
    BigInteger crt = q.modInverse(p);
    RSAPrivateCrtKeySpec validKey = new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, crt);
    byte[] message = "Test".getBytes(UTF_8);
    Signature signer;
    byte[] signature;
    KeyFactory kf;
    try {
      kf = KeyFactory.getInstance("RSA");
      PrivateKey validPrivKey = kf.generatePrivate(validKey);
      signer = Signature.getInstance("SHA256WithRSA");
      signer.initSign(validPrivKey);
      signer.update(message);
      signature = signer.sign();
    } catch (GeneralSecurityException ex) {
      TestUtil.skipTest("Could not generate valid signature:" + ex);
      return;
    }
    PrivateKey invalidPrivKey;
    BigInteger two = BigInteger.valueOf(2);
    RSAPrivateCrtKeySpec[] invalidKeySpec =
        new RSAPrivateCrtKeySpec[] {
          new RSAPrivateCrtKeySpec(BigInteger.ONE, e, d, p, q, dp, dq, crt),
          new RSAPrivateCrtKeySpec(n, BigInteger.ONE, d, p, q, dp, dq, crt),
          new RSAPrivateCrtKeySpec(n, e, BigInteger.ONE, p, q, dp, dq, crt),
          new RSAPrivateCrtKeySpec(n, e, d, BigInteger.ONE, q, dp, dq, crt),
          new RSAPrivateCrtKeySpec(n, e, d, p, BigInteger.ONE, dp, dq, crt),
          new RSAPrivateCrtKeySpec(n, e, d, p, q, BigInteger.ONE, dq, crt),
          new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, BigInteger.ONE, crt),
          new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, BigInteger.ONE),
          new RSAPrivateCrtKeySpec(n.add(two), e, d, p, q, dp, dq, crt),
          new RSAPrivateCrtKeySpec(n, e.add(two), d, p, q, dp, dq, crt),
          new RSAPrivateCrtKeySpec(n, e, d.add(two), p, q, dp, dq, crt),
          new RSAPrivateCrtKeySpec(n, e, d, p.add(two), q, dp, dq, crt),
          new RSAPrivateCrtKeySpec(n, e, d, p, q.add(two), dp, dq, crt),
          new RSAPrivateCrtKeySpec(n, e, d, p, q, dp.add(two), dq, crt),
          new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq.add(two), crt),
          new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, crt.add(two)),
        };
    for (RSAPrivateCrtKeySpec spec : invalidKeySpec) {
      byte[] invalidSignature;
      try {
        invalidPrivKey = kf.generatePrivate(spec);
        signer.initSign(invalidPrivKey);
        signer.update(message);
        invalidSignature = signer.sign();
      } catch (GeneralSecurityException | RuntimeException ex) {
        // We do not necessarily expect a checked exception here, since generating
        // an invalid signature typically indicates a programming error or even a hardware fault.
        // Thus RuntimeExceptions are fine here.
        System.out.println("Faulty RSA parameters correctly detected: " + ex);
        continue;
      }
      String signatureHex = TestUtil.bytesToHex(signature);
      String invalidSignatureHex = TestUtil.bytesToHex(invalidSignature);
      if (signatureHex.equals(invalidSignatureHex)) {
        // The provider generated a correct signature. This can happen if the provider does not use
        // the CRT parameters. This behavior is OK.
        System.out.println("Faulty parameter not used for signature generation");
        continue;
      }
      fail(
          "Generated faulty PKCS #1 signature with faulty parameters"
              + " valid signature:"
              + signatureHex
              + " invalid signature:"
              + invalidSignatureHex);
    }
  }
}
