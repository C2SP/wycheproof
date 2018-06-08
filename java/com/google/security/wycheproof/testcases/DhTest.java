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
import static org.junit.Assert.fail;

import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import com.google.security.wycheproof.WycheproofRunner.SlowTest;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Testing Diffie-Hellman key agreement.
 *
 * <p>Subgroup confinment attacks: The papers by van Oorshot and Wiener rsp. Lim and Lee show that
 * Diffie-Hellman keys can be found much faster if the short exponents are used and if the
 * multiplicative group modulo p contains small subgroups. In particular an attacker can try to send
 * a public key that is an element of a small subgroup. If the receiver does not check for such
 * elements then may be possible to find the private key modulo the order of the small subgroup.
 * Several countermeasures against such attacks have been proposed: For example IKE uses fields of
 * order p where p is a safe prime (i.e. q=(p-1)/2), hence the only elements of small order are 1
 * and p-1.
 *
 * <p>NIST SP 800-56A rev. 2, Section 5.5.1.1 only requires that the size of the subgroup generated
 * by the generator g is big enough to prevent the baby-step giant-step algorithm. I.e. for 80-bit
 * security p must be at least 1024 bits long and the prime q must be at least 160 bits long. A 2048
 * bit prime p and a 224 bit prime q are sufficient for 112 bit security. To avoid subgroup
 * confinment attacks NIST requires that public keys are validated, i.e. by checking that a public
 * key y satisfies the conditions 2 <= y <= p-2 and y^q mod p == 1 (Section 5.6.2.3.1). Further,
 * after generating the shared secret z = y_a ^ x_b mod p each party should check that z != 1. RFC
 * 2785 contains similar recommendations.
 *
 * <p>The public key validation described by NIST requires that the order q of the generator g is
 * known to the verifier. Unfortunately, the order q is missing in PKCS #3. PKCS #3 describes the
 * Diffie-Hellman parameters only by the values p, g and optionally the key size in bits.
 *
 * <p>The class DHParameterSpec that defines the Diffie-Hellman parameters in JCE contains the same
 * values as PKCS#3. In particular, it does not contain the order of the subgroup q. Moreover, the
 * SUN provider uses the minimal sizes specified by NIST for q. Essentially the provider reuses the
 * parameters for DSA.
 *
 * <p>Therefore, there is no guarantee that an implementation of Diffie-Hellman is secure against
 * subgroup confinement attacks. Without a key validation it is insecure to use the key-pair
 * generation from NIST SP 800-56A Section 5.6.1.1 (The key-pair generation there only requires that
 * static and ephemeral private keys are randomly chosen in the range 1..q-1).
 *
 * <p>To avoid big disasters the tests below require that key sizes are not minimal. I.e., currently
 * the tests require at least 512 bit keys for 1024 bit fields. We use this lower limit because that
 * is what the SUN provider is currently doing. TODO(bleichen): Find a reference supporting or
 * disproving that decision.
 *
 * <p>References: P. C. van Oorschot, M. J. Wiener, "On Diffie-Hellman key agreement with short
 * exponents", Eurocrypt 96, pp 332–343.
 *
 * <p>C.H. Lim and P.J. Lee, "A key recovery attack on discrete log-based schemes using a prime
 * order subgroup", CRYPTO' 98, pp 249–263.
 *
 * <p>NIST SP 800-56A, revision 2, May 2013
 * http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
 *
 * <p>PKCS #3, Diffie–Hellman Key Agreement
 * http://uk.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-3-diffie-hellman-key-agreement-standar.htm
 *
 * <p>RFC 2785, "Methods for Avoiding 'Small-Subgroup' Attacks on the Diffie-Hellman Key Agreement
 * Method for S/MIME", March 2000
 * https://www.ietf.org/rfc/rfc2785.txt
 *
 * <p>D. Adrian et al. "Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice"
 * https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf
 * A good analysis of various DH implementations. Some misconfigurations pointed out in the paper
 * are: p is composite, p-1 contains no large prime factor, q is used instead of the generator g.
 *
 * <p>Sources that might be used for additional tests:
 *
 * <p>CVE-2015-3193: The Montgomery squaring implementation in crypto/bn/asm/x86_64-mont5.pl in
 * OpenSSL 1.0.2 before 1.0.2e on the x86_64 platform, as used by the BN_mod_exp function,
 * mishandles carry propagation
 * https://blog.fuzzing-project.org/31-Fuzzing-Math-miscalculations-in-OpenSSLs-BN_mod_exp-CVE-2015-3193.html
 *
 * <p>CVE-2016-0739: libssh before 0.7.3 improperly truncates ephemeral secrets generated for the
 * (1) diffie-hellman-group1 and (2) diffie-hellman-group14 key exchange methods to 128 bits ...
 *
 * <p>CVE-2015-1787 The ssl3_get_client_key_exchange function in s3_srvr.c in OpenSSL 1.0.2 before
 * 1.0.2a, when client authentication and an ephemeral Diffie-Hellman ciphersuite are enabled,
 * allows remote attackers to cause a denial of service (daemon crash) via a ClientKeyExchange
 * message with a length of zero.
 *
 * <p>CVE-2015-0205 The ssl3_get_cert_verify function in s3_srvr.c in OpenSSL 1.0.0 before 1.0.0p
 * and 1.0.1 before 1.0.1k accepts client authentication with a Diffie-Hellman (DH) certificate
 * without requiring a CertificateVerify message, which allows remote attackers to obtain access
 * without knowledge of a private key via crafted TLS Handshake Protocol traffic to a server that
 * recognizes a Certification Authority with DH support.
 *
 * <p>CVE-2016-0701 The DH_check_pub_key function in crypto/dh/dh_check.c in OpenSSL 1.0.2 before
 * 1.0.2f does not ensure that prime numbers are appropriate for Diffie-Hellman (DH) key exchange,
 * which makes it easier for remote attackers to discover a private DH exponent by making multiple
 * handshakes with a peer that chose an inappropriate number, as demonstrated by a number in an
 * X9.42 file.
 *
 * <p>CVE-2006-1115 nCipher HSM before 2.22.6, when generating a Diffie-Hellman public/private key
 * pair without any specified DiscreteLogGroup parameters, chooses random parameters that could
 * allow an attacker to crack the private key in significantly less time than a brute force attack.
 *
 * <p>CVE-2015-1716 Schannel in Microsoft Windows Server 2003 SP2, Windows Vista SP2, Windows Server
 * 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, and
 * Windows RT Gold and 8.1 does not properly restrict Diffie-Hellman Ephemeral (DHE) key lengths,
 * which makes it easier for remote attackers to defeat cryptographic protection mechanisms via
 * unspecified vectors, aka "Schannel Information Disclosure Vulnerability.
 *
 * <p>CVE-2015-2419: Random generation of the prime p allows Pohlig-Hellman and probably other
 * stuff.
 *
 * <p>J. Fried et al. "A kilobit hidden SNFS discrete logarithm computation".
 * http://eprint.iacr.org/2016/961.pdf
 * Some crypto libraries use fields that can be broken with the SNFS.
 *
 * @author bleichen@google.com (Daniel Bleichenbacher)
 */
@RunWith(JUnit4.class)
public class DhTest {
  public DHParameterSpec ike1536() {
    final BigInteger p =
        new BigInteger(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
                + "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
                + "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
                + "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
                + "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
                + "9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff",
            16);
    final BigInteger g = new BigInteger("2");
    return new DHParameterSpec(p, g);
  }

  public DHParameterSpec ike2048() {
    final BigInteger p =
        new BigInteger(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
                + "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
                + "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
                + "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
                + "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
                + "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
                + "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
                + "3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff",
            16);
    final BigInteger g = new BigInteger("2");
    return new DHParameterSpec(p, g);
  }

  // The default parameters returned for 1024 bit DH keys from OpenJdk as defined in
  // openjdk7/releases/v6/trunk/jdk/src/share/classes/sun/security/provider/ParameterCache.java
  // I.e., these are the same parameters as used for DSA.
  public DHParameterSpec openJdk1024() {
    final BigInteger p =
        new BigInteger(
            "fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669"
                + "455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b7"
                + "6b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb"
                + "83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7",
            16);
    final BigInteger unusedQ = new BigInteger("9760508f15230bccb292b982a2eb840bf0581cf5", 16);
    final BigInteger g =
        new BigInteger(
            "f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d078267"
                + "5159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e1"
                + "3c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243b"
                + "cca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a",
            16);
    return new DHParameterSpec(p, g);
  }

  /** Check that key agreement using DH works. */
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testDh() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
    DHParameterSpec dhparams = ike2048();
    keyGen.initialize(dhparams);
    KeyPair keyPairA = keyGen.generateKeyPair();
    KeyPair keyPairB = keyGen.generateKeyPair();

    KeyAgreement kaA = KeyAgreement.getInstance("DH");
    KeyAgreement kaB = KeyAgreement.getInstance("DH");
    kaA.init(keyPairA.getPrivate());
    kaB.init(keyPairB.getPrivate());
    kaA.doPhase(keyPairB.getPublic(), true);
    kaB.doPhase(keyPairA.getPublic(), true);
    byte[] kAB = kaA.generateSecret();
    byte[] kBA = kaB.generateSecret();
    assertEquals(TestUtil.bytesToHex(kAB), TestUtil.bytesToHex(kBA));
  }

  /**
   * Returns the product of primes that can be found by a simple variant of Pollard-rho. The result
   * should contain all prime factors of n smaller than 10^8. This method is heuristic, since it
   * could in principle find large prime factors too. However, for a random 160-bit prime q the
   * probability of this should be less than 2^{-100}.
   */
  private BigInteger smoothDivisor(BigInteger n) {
    // By examination we verified that for every prime p < 10^8
    // the iteration x_n = x_{n-1}^2 + 1 mod p enters a cycle of size < 50000 after at
    // most 50000 steps.
    int pollardRhoSteps = 50000;
    BigInteger u = new BigInteger("2");
    for (int i = 0; i < pollardRhoSteps; i++) {
      u = u.multiply(u).add(BigInteger.ONE).mod(n);
    }
    BigInteger v = u;
    BigInteger prod = BigInteger.ONE;
    for (int i = 0; i < pollardRhoSteps; i++) {
      v = v.multiply(v).add(BigInteger.ONE).mod(n);
      // This implementation is only looking for the product of small primes.
      // Therefore, instead of continuously computing gcds of v-u and n, it is sufficient
      // and more efficient to compute the product of v-u for all v and compute the gcd
      // at the end.
      prod = prod.multiply(v.subtract(u).abs()).mod(n);
    }
    BigInteger result = BigInteger.ONE;
    while (true) {
      BigInteger f = n.gcd(prod);
      if (f.equals(BigInteger.ONE)) {
        return result;
      }
      result = result.multiply(f);
      n = n.divide(f);
    }
  }

  private void testKeyPair(KeyPair keyPair, int expectedKeySize) throws Exception {
    DHPrivateKey priv = (DHPrivateKey) keyPair.getPrivate();
    BigInteger p = priv.getParams().getP();
    BigInteger g = priv.getParams().getG();
    int keySize = p.bitLength();
    assertEquals("wrong key size", expectedKeySize, keySize);

    // Checks the key size of the private key.
    // NIST SP 800-56A requires that x is in the range (1, q-1).
    // Such a choice would require a full key validation. Since such a validation
    // requires the value q (which is not present in the DH parameters) larger keys
    // should be chosen to prevent attacks.
    int minPrivateKeyBits = keySize / 2;
    BigInteger x = priv.getX();
    assertTrue(x.bitLength() >= minPrivateKeyBits - 32);
    // TODO(bleichen): add tests for weak random number generators.

    // Verify the DH parameters.
    System.out.println("p=" + p.toString(16));
    System.out.println("g=" + g.toString(16));
    System.out.println("testKeyPairGenerator L=" + priv.getParams().getL());
    // Basic parameter checks
    assertTrue("Expecting g > 1", g.compareTo(BigInteger.ONE) > 0);
    assertTrue("Expecting g < p - 1", g.compareTo(p.subtract(BigInteger.ONE)) < 0);
    // Expecting p to be prime.
    // No high certainty is needed, since this is a unit test.
    assertTrue(p.isProbablePrime(4));
    // The order of g should be a large prime divisor q of p-1.
    // (see e.g. NIST SP 800-56A, section 5.5.1.1.)
    // If the order of g is composite then the Decision Diffie Hellman assumption is
    // not satisfied for the group generated by g. Moreover, attacks using Pohlig-Hellman
    // might be feasible.
    // A good way to achieve these requirements is to select a safe prime p (i.e. a prime
    // where q=(p-1)/2 is prime too. NIST SP 800-56A does not require (or even recommend)
    // safe primes and allows Diffie-Hellman parameters where q is significantly smaller.
    // Unfortunately, the key does not contain q and thus the conditions above  cannot be
    // tested easily.
    // We perform a partial test that performs a partial factorization of p-1 and then
    // test whether one of the small factors found by the partial factorization divides
    // the order of g.
    boolean isSafePrime = p.shiftRight(1).isProbablePrime(4);
    System.out.println("p is a safe prime:" + isSafePrime);
    BigInteger r; // p-1 divided by small prime factors.
    if (isSafePrime) {
      r = p.shiftRight(1);
    } else {
      BigInteger p1 = p.subtract(BigInteger.ONE);
      r = p1.divide(smoothDivisor(p1));
    }
    System.out.println("r=" + r.toString(16));
    assertEquals(
        "g likely does not generate a prime oder subgroup", BigInteger.ONE, g.modPow(r, p));

    // Checks that there are not too many short prime factors.
    // I.e., subgroup confinment attacks can find at least keySize - r.bitLength() bits of the key.
    // At least 160 unknown bits should remain.
    // Only very weak parameters are detected here, since the factorization above only finds small
    // prime factors.
    assertTrue(minPrivateKeyBits - (keySize - r.bitLength()) > 160);

    // DH parameters are sometime misconfigures and g and q are swapped.
    // A large g that divides p-1 is suspicious.
    if (g.bitLength() >= 160) {
      assertTrue(p.mod(g).compareTo(BigInteger.ONE) > 0);
    }
  }

  /**
   * Tests Diffie-Hellman key pair generation.
   *
   * <p>This is a slow test since some providers (e.g. BouncyCastle) generate new safe primes for
   * each new key.
   */
  @SuppressWarnings("InsecureCryptoUsage")
  @SlowTest(providers = {ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE})
  @Test
  public void testKeyPairGenerator() throws Exception {
    int keySize = 1024;
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
    keyGen.initialize(keySize);
    KeyPair keyPair = keyGen.generateKeyPair();
    testKeyPair(keyPair, keySize);
  }

  /**
   * Tests the default Diffie-Hellman key pair generation.
   *
   * <p>This test uses NIST SP 800-57 part1, revision 4
   * http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf . Table 2 on page
   * 53 recommends 2048 bits as the minimal key length for Diffie-Hellman for new keys that expire
   * before the year 2030.
   *
   * <p>Note that JCE documentation is outdated. According to
   * https://docs.oracle.com/javase/7/docs/api/java/security/KeyPairGenerator.html an implementation
   * of the Java platform is only required to support 1024 bit keys.
   */
  @NoPresubmitTest(
    providers = {ProviderType.OPENJDK, ProviderType.BOUNCY_CASTLE},
    bugs = {"b/33190860", "b/33190677"}
  )
  @SlowTest(providers = {ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE})
  @Test
  public void testDefaultKeyPairGenerator() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
    KeyPair keyPair;
    try {
      keyPair = keyGen.generateKeyPair();
    } catch (Exception ex) {
      // When a provider decides not to implement a default key size then this is still better than
      // implementing a default that is out of date. Hence the test should not fail in this case.
      System.out.println("Cannot generate a DH key without initialize: " + ex.getMessage());
      return;
    }
    DHPrivateKey priv = (DHPrivateKey) keyPair.getPrivate();
    int keySize = priv.getParams().getP().bitLength();
    assertTrue("Default key size for DH is too small. Key size = " + keySize, keySize >= 2048);
    testKeyPair(keyPair, keySize);
  }

  /** This test tries a key agreement with keys using distinct parameters. */
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testDHDistinctParameters() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
    keyGen.initialize(ike1536());
    KeyPair keyPairA = keyGen.generateKeyPair();

    keyGen.initialize(ike2048());
    KeyPair keyPairB = keyGen.generateKeyPair();

    KeyAgreement kaA = KeyAgreement.getInstance("DH");
    kaA.init(keyPairA.getPrivate());
    try {
      kaA.doPhase(keyPairB.getPublic(), true);
      byte[] kAB = kaA.generateSecret();
      fail("Generated secrets with mixed keys " + TestUtil.bytesToHex(kAB) + ", ");
    } catch (java.security.GeneralSecurityException ex) {
      // This is expected.
    }
  }

  /**
   * Tests whether a provider accepts invalid public keys that result in predictable shared secrets.
   * This test is based on RFC 2785, Section 4 and NIST SP 800-56A, If an attacker can modify both
   * public keys in an ephemeral-ephemeral key agreement scheme then it may be possible to coerce
   * both parties into computing the same predictable shared key.
   *
   * <p>Note: the test is quite whimsical. If the prime p is not a safe prime then the provider
   * itself cannot prevent all small-subgroup attacks because of the missing parameter q in the
   * Diffie-Hellman parameters. Implementations must add additional countermeasures such as the ones
   * proposed in RFC 2785.
   *
   * <p>CVE-2016-1000346: BouncyCastle before v.1.56 did not validate the other parties public key.
   */
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testSubgroupConfinement() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
    DHParameterSpec params = ike2048();
    BigInteger p = params.getP();
    BigInteger g = params.getG();
    keyGen.initialize(params);
    PrivateKey priv = keyGen.generateKeyPair().getPrivate();
    KeyAgreement ka = KeyAgreement.getInstance("DH");
    BigInteger[] weakPublicKeys = {
      BigInteger.ZERO,
      BigInteger.ONE,
      p.subtract(BigInteger.ONE),
      p,
      p.add(BigInteger.ONE),
      BigInteger.ONE.negate()
    };
    for (BigInteger weakKey : weakPublicKeys) {
      ka.init(priv);
      try {
        KeyFactory kf = KeyFactory.getInstance("DH");
        DHPublicKeySpec weakSpec = new DHPublicKeySpec(weakKey, p, g);
        PublicKey pub = kf.generatePublic(weakSpec);
        ka.doPhase(pub, true);
        byte[] kAB = ka.generateSecret();
        fail(
            "Generated secrets with weak public key:"
                + weakKey.toString()
                + " secret:"
                + TestUtil.bytesToHex(kAB));
      } catch (GeneralSecurityException ex) {
        // this is expected
      }
    }
  }
}
