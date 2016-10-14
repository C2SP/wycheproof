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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import junit.framework.TestCase;

/**
 * Tests RSA keys. Signatures and encryption are tested in different tests.
 *
 * @author bleichen@google.com (Daniel Bleichenbacher)
 */
// TODO(bleichen):
// - Add checks for bad random numbers
// - expect keys with e=1 to be rejected
// - expect keys with e=0 to be rejected
// - document stuff
// - Maybe also check encodings of private keys.
// - Test multi prime RSA
// - Tests for alternative representations:
//    many libraries sort the primes as: p > q (but not all)
//    some libraries compute d mod lambda(n)
//    paramaters p,q,... are not really required
// - checks for bad random number generation
public class RsaKeyTest extends TestCase {

  public static final String ENCODED_PUBLIC_KEY =
    "30819f300d06092a864886f70d010101050003818d0030818902818100ab9014"
        + "dc47d44b6d260fc1fef9ab022042fd9566e9d7b60c54100cb6e1d4edc9859046"
        + "7d0502c17fce69d00ac5efb40b2cb167d8a44ab93d73c4d0f109fb5a26c2f882"
        + "3236ff517cf84412e173679cfae42e043b6fec81f9d984b562517e6febe1f722"
        + "95dbc3fdfc19d3240aa75515563f31dad83563f3a315acf9a0b351a23f020301"
        + "0001";

  private void checkPrivateCrtKey(RSAPrivateCrtKey key, int expectedKeySize) throws Exception {
    BigInteger p = key.getPrimeP();
    BigInteger q = key.getPrimeQ();
    BigInteger n = key.getModulus();
    BigInteger e = key.getPublicExponent();
    BigInteger d = key.getPrivateExponent();
    BigInteger dp = key.getPrimeExponentP();
    BigInteger dq = key.getPrimeExponentQ();
    BigInteger crtCoeff = key.getCrtCoefficient();

    // Simple test that (n,d,e) is a valid RSA key.
    assertEquals(n, p.multiply(q));
    assertEquals(expectedKeySize, n.bitLength());
    int certainty = 80;
    assertTrue(p.isProbablePrime(certainty));
    assertTrue(q.isProbablePrime(certainty));
    // Very simple checks for weak random number generators.
    RandomUtil.checkPrime(p);
    RandomUtil.checkPrime(q);
    assertTrue(d.bitLength() > expectedKeySize / 2);
    // TODO(bleichen): Keys that are very imbalanced can be broken with elliptic curve factoring.
    //   Add other checks. E.g. for the size of dp and dq
    assertTrue(p.bitLength() > 256);
    assertTrue(q.bitLength() > 256);
    BigInteger p1 = p.subtract(BigInteger.ONE);
    BigInteger q1 = q.subtract(BigInteger.ONE);
    BigInteger phi = p1.multiply(q1);
    BigInteger order = phi.divide(p1.gcd(q1)); // maximal order of elements
    assertEquals(BigInteger.ONE, d.multiply(e).mod(order));
    assertEquals(d.mod(p1), dp.mod(p1));
    assertEquals(d.mod(q1), dq.mod(q1));
    assertEquals(q.multiply(crtCoeff).mod(p), BigInteger.ONE);
  }

  private void checkPublicKey(RSAPublicKey pub, RSAPrivateKey priv) {
    assertEquals(pub.getModulus(), priv.getModulus());
    BigInteger e = pub.getPublicExponent();
    // Checks that e > 1. [CVE-1999-1444]
    assertEquals(e.compareTo(BigInteger.ONE), 1);
  }

  private void checkKeyPair(KeyPair keypair, int keySizeInBits) throws Exception {
    RSAPublicKey pub = (RSAPublicKey) keypair.getPublic();
    RSAPrivateKey priv = (RSAPrivateKey) keypair.getPrivate();
    if (priv instanceof RSAPrivateCrtKey) {
      checkPrivateCrtKey((RSAPrivateCrtKey) priv, keySizeInBits);
    } else {
      // Using a CRT key leads to 6-7 times better performance than not using the CRT.
      // Such a perfomance loss makes a library almost useless. Thus we consider this
      // a bug.
      fail("Expecting an RSAPrivateCrtKey instead of " + priv.getClass().getName());
    }
    checkPublicKey(pub, priv);
  }

  public void testKeyGenerationSize(int keySizeInBits) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(keySizeInBits);
    KeyPair keypair = keyGen.genKeyPair();
    checkKeyPair(keypair, keySizeInBits);
  }

  public void testKeyGeneration() throws Exception {
    testKeyGenerationSize(1024);
    testKeyGenerationSize(2048);
  }

  /**
   * Checks whether decoding and again encoding an RSA public key results
   * in the same encoding.
   * This is a regression test. Failing this test implies that the encoding has changed.
   * Such a failure does not need to be a bug, since several encoding for the same key are
   * possible.
   */
  public void testEncodeDecodePublic() throws Exception {
    KeyFactory kf = KeyFactory.getInstance("RSA");
    byte[] encoded = TestUtil.hexToBytes(ENCODED_PUBLIC_KEY);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
    RSAPublicKey pub = (RSAPublicKey) kf.generatePublic(spec);
    assertEquals("The test assumes that the public key is in X.509 format",
                 "X.509", pub.getFormat());
    assertEquals(ENCODED_PUBLIC_KEY, TestUtil.bytesToHex(pub.getEncoded()));
  }
}
