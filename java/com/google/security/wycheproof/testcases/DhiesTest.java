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
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Locale;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Testing DHIES.
 *
 * @author bleichen@google.com (Daniel Bleichenbacher)
 */
// TODO(bleichen): DHIES does not have a lot of test coverage.
//   The algorithm is not widely used since there are better encryption
//   mode. A few things that could be tested are:
// - test against CipherInputStream, CipherOutputStream:
//   CipherInputStream and CipherOutputStream sometimes ignore tag verification.
// - test against byteBuffer: sometimes small ByteBuffers are rejected even
//   if they contain enough space for the actual plaintext.
// - Exception handling: BouncyCastle suffered from a padding oracle bug in
//   version 1.56 (CVE-2016-1000345). This should be fixed.
// - Regression tests: Not sure if the implemented version is compatible
//   with other libraries.
@RunWith(JUnit4.class)
public class DhiesTest {

  // TODO(bleichen): This is the same as DhTest.java
  //   We could move this into some TestUtil.
  private DHParameterSpec ike2048() {
    final BigInteger p =
        new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                + "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
            16);
    final BigInteger g = new BigInteger("2");
    return new DHParameterSpec(p, g);
  }

  // Known algorithm names for DHIES variants.
  private static final String[] ALGORITHM_NAMES = {
    "DHIES", "DHIESwithAES-CBC", "DHIESwithDESEDE-CBC",
  };

  /**
   * Returns a set of algorithm parameters for a given algorithmName.
   *
   * <p>This function uses BouncyCastle specific encodings. AlgorithmParameters are an ASN.1 encoded
   * list containing the size of the symmetric key, the HMAC key and the nonce.
   */
  AlgorithmParameters getAlgorithmParameters(String algorithmName) throws Exception {
    String paramsHex;
    switch (algorithmName.toUpperCase(Locale.ENGLISH)) {
      case "DHIES":
        // No algorithm parameters necessary.
        return null;
      case "DHIESWITHAES-CBC":
        // 256-bit AES key, 256-bit HMAC key, all zero nonce
        paramsHex = "301c02020100301602020100041000000000000000000000000000000000";
        break;
      case "DHIESWITHDESEDE-CBC":
        // 24 byte 3DES key, 256-bit HMAC key, all zero nonce
        paramsHex = "301402020100300e020200c004080000000000000000";
        break;
      default:
        fail("Unknown algorithm:" + algorithmName);
        return null;
    }
    AlgorithmParameters params = AlgorithmParameters.getInstance("IES");
    params.init(TestUtil.hexToBytes(paramsHex), "ASN.1");
    return params;
  }

  /**
   * Old versions of BouncyCastle used to implement DHIES with symmetric ciphers using ECB. Quite
   * problematic was that the algorithm names did not indicate the encryption mode and hence users
   * might have chosen these DHIES variants without suspecting any weaknesses. BouncyCastle has
   * removed these variants.
   *
   * <p>This test simply ensures that old DHIES variants using ECB no longer exist.
   */
  @Test
  public void testDeprecatedVariants() throws Exception {
    try {
      Cipher.getInstance("DHIESwithAES");
      fail("DHIESwithAES should not exist");
    } catch (NoSuchAlgorithmException ex) {
      // Expected behaviour
    }
    try {
      Cipher.getInstance("DHIESwithDESede");
      fail("DHIESwithDESede should not exist");
    } catch (NoSuchAlgorithmException ex) {
      // Expected behaviour
    }
  }

  /** Checks DHIES variants with no (rsp. fixed) parameters */
  @SuppressWarnings("InsecureCryptoUsage")
  public void testDhiesNoParameters(String algorithmName) throws Exception {
    DHParameterSpec params = ike2048();
    KeyPairGenerator kf = KeyPairGenerator.getInstance("DH");
    kf.initialize(params);
    KeyPair keyPair = kf.generateKeyPair();
    PrivateKey priv = keyPair.getPrivate();
    PublicKey pub = keyPair.getPublic();
    byte[] message = "Hello".getBytes("UTF-8");
    Cipher dhies;
    try {
      dhies = Cipher.getInstance(algorithmName);
    } catch (NoSuchAlgorithmException ex) {
      // The algorithm isn't supported.
      TestUtil.skipTest(algorithmName + " is not supported");
      return; // fallback for legacy test setups where skipTest does not throw an exception.
    }
    dhies.init(Cipher.ENCRYPT_MODE, pub);
    byte[] ciphertext = dhies.doFinal(message);
    System.out.println(
        algorithmName + " : " + TestUtil.bytesToHex(dhies.getParameters().getEncoded()));
    dhies.init(Cipher.DECRYPT_MODE, priv);
    byte[] decrypted = dhies.doFinal(ciphertext);
    assertEquals(TestUtil.bytesToHex(message), TestUtil.bytesToHex(decrypted));
  }

  @SuppressWarnings("InsecureCryptoUsage")
  public void testDhiesWithParameters(String algorithmName) throws Exception {
    DHParameterSpec dhParams = ike2048();
    KeyPairGenerator kf = KeyPairGenerator.getInstance("DH");
    kf.initialize(dhParams);
    KeyPair keyPair = kf.generateKeyPair();
    PrivateKey priv = keyPair.getPrivate();
    PublicKey pub = keyPair.getPublic();
    byte[] message = "Hello".getBytes("UTF-8");
    Cipher dhies;
    try {
      dhies = Cipher.getInstance(algorithmName);
    } catch (NoSuchAlgorithmException ex) {
      // The algorithm isn't supported.
      TestUtil.skipTest(algorithmName + " is not supported");
      return; // fallback for legacy test setups where skipTest does not throw an exception.
    }
    AlgorithmParameters dhiesParams = getAlgorithmParameters(algorithmName);
    dhies.init(Cipher.ENCRYPT_MODE, pub, dhiesParams);
    byte[] ciphertext = dhies.doFinal(message);
    dhies.init(Cipher.DECRYPT_MODE, priv, dhiesParams);
    byte[] decrypted = dhies.doFinal(ciphertext);
    assertEquals(TestUtil.bytesToHex(message), TestUtil.bytesToHex(decrypted));
  }

  @Test
  public void testPlainDhies() throws Exception {
    testDhiesNoParameters("DHIES");
  }

  @Test
  public void testDhiesAesCbc() throws Exception {
    testDhiesWithParameters("DHIESwithAES-CBC");
  }

  @Test
  public void testDhiesDesEdeCbc() throws Exception {
    testDhiesWithParameters("DHIESwithDESede-CBC");
  }

  /** Modifies the ciphertext and determines if the modification is detected. */
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testDhiesCorrupt() throws Exception {
    KeyPairGenerator kf = KeyPairGenerator.getInstance("DH");
    kf.initialize(ike2048());
    KeyPair keyPair = kf.generateKeyPair();
    PrivateKey priv = keyPair.getPrivate();
    PublicKey pub = keyPair.getPublic();
    byte[] message = new byte[32];
    int testsPerformed = 0;
    for (String algorithmName : ALGORITHM_NAMES) {
      Cipher dhies;
      try {
        dhies = Cipher.getInstance(algorithmName);
      } catch (NoSuchAlgorithmException ex) {
        continue;
      }
      AlgorithmParameters params = getAlgorithmParameters(algorithmName);
      dhies.init(Cipher.ENCRYPT_MODE, pub, params);
      byte[] ciphertext = dhies.doFinal(message);
      for (int i = 0; i < ciphertext.length; i++) {
        byte[] corrupt = Arrays.copyOf(ciphertext, ciphertext.length);
        corrupt[i] ^= (byte) 1;
        try {
          dhies.init(Cipher.DECRYPT_MODE, priv, params);
          dhies.doFinal(corrupt);
          fail("Corrupt ciphertext accepted:" + i);
        } catch (GeneralSecurityException ex) {
          // This is expected
        }
        testsPerformed++;
      }
    }
    if (testsPerformed == 0) {
      TestUtil.skipTest("No tests performed.");
      return;
    }
  }

  /**
   * Tries to detect if an algorithm is using ECB. Unfortunately, many JCE algorithms use ECB if no
   * encryption mode is specified.
   */
  @Test
  @SuppressWarnings("InsecureCryptoUsage")
  public void testNotEcb() throws Exception {
    KeyPairGenerator kf = KeyPairGenerator.getInstance("DH");
    kf.initialize(ike2048());
    KeyPair keyPair = kf.generateKeyPair();
    PublicKey pub = keyPair.getPublic();
    int testsPerformed = 0;
    for (String algorithmName : ALGORITHM_NAMES) {
      Cipher dhies;
      try {
        dhies = Cipher.getInstance(algorithmName);
      } catch (NoSuchAlgorithmException ex) {
        continue;
      }
      byte[] message = new byte[128];
      dhies.init(Cipher.ENCRYPT_MODE, pub);
      byte[] ciphertext = dhies.doFinal(message);
      int blockSize = 16;
      for (int i = 0; i < ciphertext.length - 2 * blockSize + 1; i++) {
        byte[] block1 = Arrays.copyOfRange(ciphertext, i, i + blockSize);
        byte[] block2 = Arrays.copyOfRange(ciphertext, i + blockSize, i + 2 * blockSize);
        boolean sameBlock = Arrays.equals(block1, block2);
        assertTrue("Ciphertext repeats at position:" + i + " for " + algorithmName, !sameBlock);
      }
      testsPerformed++;
    }
    if (testsPerformed == 0) {
      TestUtil.skipTest("No tests performed.");
      return;
    }
  }

  /**
   * Tests the malleability of DHIES implementations.
   *
   * <p>The test is based on a potentially deceptive interface in BouncyCastle. The issue is that
   * some DHIES variants generate randomized algorithm parameters. In particular, the CBC variants
   * generate and use a random nonce for the encryption. It is tempting to retrieve the algorithm
   * parameters used for encryption with .getParameters() encode them and and send them together
   * with the ciphertext to the receiver. The test checks if this usage pattern leads to malleable
   * ciphertexts.
   *
   * <p>The expectation is that DHIES implementations either do not generate randomized parameters
   * or that the randomized parameters are included in the integrity check.
   */
  @NoPresubmitTest(
      providers = {ProviderType.BOUNCY_CASTLE},
      bugs = {"b/238881562"})
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testMalleability() throws Exception {
    KeyPairGenerator kf = KeyPairGenerator.getInstance("DH");
    kf.initialize(ike2048());
    KeyPair keyPair = kf.generateKeyPair();
    PublicKey pub = keyPair.getPublic();
    PrivateKey priv = keyPair.getPrivate();

    int testsPerformed = 0;
    int failures = 0;
    for (String algorithmName : ALGORITHM_NAMES) {
      Cipher dhiesA;
      Cipher dhiesB;
      try {
        dhiesA = Cipher.getInstance(algorithmName);
        dhiesB = Cipher.getInstance(algorithmName);
      } catch (NoSuchAlgorithmException ex) {
        continue;
      }
      testsPerformed++;
      byte[] message = new byte[32];
      dhiesA.init(Cipher.ENCRYPT_MODE, pub);
      byte[] ciphertext = dhiesA.doFinal(message);

      // Tries to generate a different test of parameters.
      dhiesB.init(Cipher.ENCRYPT_MODE, pub);
      AlgorithmParameters paramsB = dhiesB.getParameters();

      // Tries to decrypt with the (possibly) modified parameters.
      byte[] decrypted;
      try {
        dhiesB.init(Cipher.DECRYPT_MODE, priv, paramsB);
        decrypted = dhiesB.doFinal(ciphertext);
      } catch (IllegalArgumentException | BadPaddingException ex) {
        // Correct behavior if dhiesA and dhiesB use distinct parameters.
        continue;
      }
      // Otherwise check if modifying the parameters made the encryption
      // mode malleable.
      if (!Arrays.equals(message, decrypted)) {
        System.out.println(algorithmName + " is malleable");
        System.out.println("message:  " + TestUtil.bytesToHex(message));
        System.out.println("decrypted:" + TestUtil.bytesToHex(decrypted));
        failures++;
      }
    }
    assertEquals("Malleable DHIES algorithms found", 0, failures);
    if (testsPerformed == 0) {
      TestUtil.skipTest("No tests performed");
    }
  }

  /**
   * Old versions of BouncyCastle accepted algorithm names with paddings and simply ignored the
   * padding in the algorithm name (e.g., always used PKCS5Padding). This was confusing. The
   * situation is better now: DHIESWithAES-CBC/None/NoPadding is still accepted as algorithm name
   * (and uses PKCS5Padding). Other than this, no irregular names are accepted.
   */
  @Test
  @SuppressWarnings("InsecureCryptoUsage")
  public void testInvalidPaddings() throws Exception {
    String[] invalidNames = {
      "DHIESWithAES/ECB/NoPadding",
      "DHIESWithAES/CTR/NoPadding",
      "DHIESWithAES/CBC/NoPadding",
      "DHIESWithAES-CBC/None/Pkcs1Padding",
      "DHIESWithAES-CBC/None/iso10126padding",
      "DHIESWithAES-CBC/None/iso10126dpadding",
      "DHIESWithAES-CBC/CTR/NoPadding",
      "DHIESWithAES-CBC/GCM/NoPadding",
    };

    for (String name : invalidNames) {
      try {
        Cipher.getInstance(name);
        fail("Cipher implements invalid algorithm name: " + name);
      } catch (NoSuchAlgorithmException ex) {
        // expected
      }
    }
  }

}
