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
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.HashSet;
import javax.crypto.Cipher;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Testing ECIES.
 *
 * @author bleichen@google.com (Daniel Bleichenbacher)
 */
// Tested providers:
// BouncyCastle v 1.52: IESCipher is amazingly buggy, both from a crypto
// viewpoint and from an engineering viewpoint. It uses encryption modes that are completely
// inapproriate for ECIES or DHIES (i.e. ECB), the CBC implementation distinguishes between
// padding and MAC failures allowing adaptive chosen-ciphertext attacks. The implementation
// allows to specify paddings, but ignores them, encryption using ByteBuffers doesn't even work
// without exceptions, indicating that this hasn't even tested.
//
// <p>TODO(bleichen):
// - compressed points,
// - maybe again CipherInputStream, CipherOutputStream,
// - BouncyCastle has a KeyPairGenerator for ECIES. Is this one different from EC?
@RunWith(JUnit4.class)
public class EciesTest {

  int expectedCiphertextLength(String algorithm, int coordinateSize, int messageLength)
      throws Exception {
    switch (algorithm.toUpperCase()) {
      case "ECIESWITHAES-CBC":
        // Uses the encoding
        // 0x04 || coordinate x || coordinate y || PKCS5 padded ciphertext || 20-byte HMAC-digest.
        return 1 + (2 * coordinateSize) + (messageLength - messageLength % 16 + 16) + 20;
      default:
        fail("Not implemented");
    }
    return -1;
  }

  /**
   * Check that key agreement using ECIES works. This example does not specify an IESParametersSpec.
   * BouncyCastle v.1.52 uses the following algorithms: KDF2 with SHA1 for the key derivation
   * AES-CBC with PKCS #5 padding. HMAC-SHA1 with a 20 byte digest. The AES and the HMAC key are
   * both 128 bits.
   */
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testEciesBasic() throws Exception {
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
    KeyPairGenerator kf = KeyPairGenerator.getInstance("EC");
    kf.initialize(ecSpec);
    KeyPair keyPair = kf.generateKeyPair();
    PrivateKey priv = keyPair.getPrivate();
    PublicKey pub = keyPair.getPublic();
    byte[] message = "Hello".getBytes("UTF-8");
    Cipher ecies = Cipher.getInstance("ECIESwithAES-CBC");
    ecies.init(Cipher.ENCRYPT_MODE, pub);
    byte[] ciphertext = ecies.doFinal(message);
    System.out.println("testEciesBasic:" + TestUtil.bytesToHex(ciphertext));
    ecies.init(Cipher.DECRYPT_MODE, priv, ecies.getParameters());
    byte[] decrypted = ecies.doFinal(ciphertext);
    assertEquals(TestUtil.bytesToHex(message), TestUtil.bytesToHex(decrypted));
  }

  /**
   * ECIES does not allow encryption modes and paddings. If this test fails then we should add
   * additional tests covering the new algorithms.
   */
  // TODO(bleichen): This test describes BouncyCastles behaviour, but not necessarily what we
  // expect.
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testInvalidNames() throws Exception {
    String[] invalidNames =
        new String[] {
          "ECIESWITHAES/CBC/PKCS5PADDING",
          "ECIESWITHAES/CBC/PKCS7PADDING",
          /* MOE:insert "ECIESWITHAES/DHAES/NOPADDING", */
          /* MOE:insert "ECIESWITHDESEDE/DHAES/NOPADDING", */
          "ECIESWITHAES/ECB/NOPADDING",
          "ECIESWITHAES/CTR/NOPADDING",
        };
    for (String algorithm : invalidNames) {
      try {
        Cipher.getInstance(algorithm);
        fail("unexpected algorithm:" + algorithm);
      } catch (NoSuchAlgorithmException ex) {
        // this is expected
      }
    }
  }

  /** Here are a few names that BouncyCastle accepts. */
  // TODO(bleichen): This test describes BouncyCastles behaviour, but not necessarily what we
  // expect.
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testValidNames() throws Exception {
    String[] validNames =
        new String[] {
          "ECIES/DHAES/PKCS7PADDING", "ECIESWITHAES-CBC/NONE/NOPADDING",
        };
    for (String algorithm : validNames) {
      Cipher.getInstance(algorithm);
    }
  }

  /**
   * BouncyCastle has a key generation algorithm "ECIES". This test checks that the result are
   * ECKeys in both cases.
   */
  @Test
  public void testKeyGeneration() throws Exception {
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
    KeyPairGenerator kf = KeyPairGenerator.getInstance("ECIES");
    kf.initialize(ecSpec);
    KeyPair keyPair = kf.generateKeyPair();
    ECPrivateKey unusedPriv = (ECPrivateKey) keyPair.getPrivate();
    ECPublicKey unusedPub = (ECPublicKey) keyPair.getPublic();
  }

  /**
   * Tries to decrypt ciphertexts where the symmetric part has been randomized. If this
   * randomization leads to distinguishable exceptions then this may indicate that the
   * implementation is vulnerable to a padding attack.
   *
   * <p>Problems detected:
   *
   * <ul>
   *   <li>CVE-2016-1000345 BouncyCastle before v.1.56 is vulnerable to a padding oracle attack.
   * </ul>
   */
  @SuppressWarnings("InsecureCryptoUsage")
  public void testExceptions(String algorithm) throws Exception {
    Cipher ecies;
    try {
      ecies = Cipher.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      // Allowing to skip the algorithm
      System.out.println("No implementation for:" + algorithm);
      return;
    }
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
    final int kemSize = 65;
    KeyPairGenerator kf = KeyPairGenerator.getInstance("EC");
    kf.initialize(ecSpec);
    KeyPair keyPair = kf.generateKeyPair();
    PrivateKey priv = keyPair.getPrivate();
    PublicKey pub = keyPair.getPublic();
    byte[] message = new byte[40];
    ecies.init(Cipher.ENCRYPT_MODE, pub);
    byte[] ciphertext = ecies.doFinal(message);
    System.out.println(TestUtil.bytesToHex(ciphertext));
    ecies.init(Cipher.DECRYPT_MODE, priv, ecies.getParameters());
    HashSet<String> exceptions = new HashSet<String>();
    for (int byteNr = kemSize; byteNr < ciphertext.length; byteNr++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] corrupt = Arrays.copyOf(ciphertext, ciphertext.length);
        corrupt[byteNr] ^= (byte) (1 << bit);
        ecies.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        try {
          ecies.doFinal(corrupt);
          fail("Decrypted:" + TestUtil.bytesToHex(corrupt));
        } catch (Exception ex) {
          String exception = ex.toString();
          if (exceptions.add(exception)) {
            System.out.println(algorithm + ":" + exception);
          }
        }
      }
    }
    assertEquals(1, exceptions.size());
  }

  @Test
  public void testEciesCorruptDefault() throws Exception {
    testExceptions("ECIES");
  }

  @NoPresubmitTest(
    providers = {ProviderType.BOUNCY_CASTLE},
    bugs = {"b/30424901: won't fix, all BC ECIES modes are banned"}
  )
  @Test
  public void testEciesCorruptAesCbc() throws Exception {
    testExceptions("ECIESWithAES-CBC");
  }

  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testModifyPoint() throws Exception {
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
    KeyPairGenerator kf = KeyPairGenerator.getInstance("EC");
    kf.initialize(ecSpec);
    KeyPair keyPair = kf.generateKeyPair();
    PrivateKey priv = keyPair.getPrivate();
    PublicKey pub = keyPair.getPublic();
    byte[] message = "This is a long text since we need 32 bytes.".getBytes("UTF-8");
    Cipher ecies = Cipher.getInstance("ECIESwithAES-CBC");
    ecies.init(Cipher.ENCRYPT_MODE, pub);
    byte[] ciphertext = ecies.doFinal(message);
    ciphertext[2] ^= (byte) 1;
    ecies.init(Cipher.DECRYPT_MODE, priv, ecies.getParameters());
    try {
      ecies.doFinal(ciphertext);
      fail("This should not work");
    } catch (GeneralSecurityException ex) {
      // This is as expected
      // Bouncy Castle 1.56 throws this exception
      // MOE:begin_strip
      // strip this catch from open source release,
      // until third_party/java/bouncycastle is upgraded to 1.56 or later.
    } catch (java.lang.IllegalArgumentException ex) {
      // This is what BouncyCastle < 1.56 throws when the points are not on the curve.
      // Maybe GeneralSecurityException would be better.
      // MOE:end_strip
    } catch (Exception ex) {
      fail(
          "Expected subclass of java.security.GeneralSecurityException, but got: "
              + ex.getClass().getName());
    }
  }

  /**
   * This test tries to detect ECIES implementations using ECB. This is insecure and also violates
   * the claims of ECIES, since ECIES is secure agains adaptive chosen-ciphertext attacks.
   */
  @SuppressWarnings("InsecureCryptoUsage")
  public void testNotEcb(String algorithm) throws Exception {
    Cipher ecies;
    try {
      ecies = Cipher.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      // This test is called with short algorithm names such as just "ECIES".
      // Requiring full names is typically a good practice. Hence it is OK
      // to not assigning default algorithms.
      System.out.println("No implementation for:" + algorithm);
      return;
    }
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
    KeyPairGenerator kf = KeyPairGenerator.getInstance("EC");
    kf.initialize(ecSpec);
    KeyPair keyPair = kf.generateKeyPair();
    PublicKey pub = keyPair.getPublic();
    byte[] message = new byte[512];
    ecies.init(Cipher.ENCRYPT_MODE, pub);
    byte[] ciphertext = ecies.doFinal(message);
    String block1 = TestUtil.bytesToHex(Arrays.copyOfRange(ciphertext, 241, 257));
    String block2 = TestUtil.bytesToHex(Arrays.copyOfRange(ciphertext, 257, 273));
    assertTrue("Ciphertext repeats:" + TestUtil.bytesToHex(ciphertext), !block1.equals(block2));
  }

  @Test
  public void testDefaultEcies() throws Exception {
    testNotEcb("ECIES");
  }

  /** BouncyCastle v1.52 uses ECB as default for ECIES with AES. */
  @NoPresubmitTest(
    providers = {ProviderType.BOUNCY_CASTLE},
    bugs = {"b/30424901: won't fix, all BC ECIES modes are banned"}
  )
  @Test
  public void testDefaultEciesWithAes() throws Exception {
    testNotEcb("ECIESWithAES");
  }
  /** BouncyCastle v1.52 uses ECB as default for ECIES with DESede. */
  @NoPresubmitTest(
    providers = {ProviderType.BOUNCY_CASTLE},
    bugs = {"b/30424901: won't fix, all BC ECIES modes are banned"}
  )
  @Test
  public void testDefaultEciesWithDESede() throws Exception {
    testNotEcb("ECIESwithDESede");
  }

  /**
   * Tests whether algorithmA is an alias of algorithmB by encrypting with algorithmA and decrypting
   * with algorithmB.
   */
  @SuppressWarnings("InsecureCryptoUsage")
  public void testIsAlias(String algorithmA, String algorithmB) throws Exception {
    Cipher eciesA;
    Cipher eciesB;
    // Allowing tests to be skipped, because we don't want to encourage abbreviations.
    try {
      eciesA = Cipher.getInstance(algorithmA);
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("Skipping because of:" + ex.toString());
      return;
    }
    try {
      eciesB = Cipher.getInstance(algorithmB);
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("Skipping because of:" + ex.toString());
      return;
    }
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
    KeyPairGenerator kf = KeyPairGenerator.getInstance("EC");
    kf.initialize(ecSpec);
    KeyPair keyPair = kf.generateKeyPair();
    byte[] message = "Hello".getBytes("UTF-8");
    eciesA.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    byte[] ciphertext = eciesA.doFinal(message);
    eciesB.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), eciesA.getParameters());
    byte[] decrypted = eciesB.doFinal(ciphertext);
    assertEquals(TestUtil.bytesToHex(message), TestUtil.bytesToHex(decrypted));
  }

  /** Tests whether two distinct algorithm names implement the same cipher */
  @Test
  public void testAlias() throws Exception {
    testIsAlias("ECIESWITHAES-CBC", "ECIESWithAES-CBC");
    testIsAlias("ECIESWITHAES", "ECIESWithAES");
    // BouncyCastle v 1.52 ignores mode and padding and considers the following
    // names as equivalent:
    // testIsAlias("ECIES/DHAES/PKCS7PADDING", "ECIES");
    testIsAlias("ECIESWITHAES-CBC/NONE/PKCS7PADDING", "ECIESWITHAES-CBC/NONE/NOPADDING");
  }

  /**
   * Encryption with ByteBuffers. This currently fails with BouncyCastle. Possibly this is the same
   * bug as http://www.bouncycastle.org/jira/browse/BJA-577 and should be fixed in version 1.53.
   */
  @NoPresubmitTest(
    providers = {ProviderType.BOUNCY_CASTLE},
    bugs = {"b/30424901: won't fix, all BC ECIES modes are banned"}
  )
  @Test
  public void testByteBuffer() throws Exception {
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
    // TODO(bleichen): Not sure what is better here:
    //   BouncyCastle allows EC and ECIES. So far I can't see a difference.
    //   In both cases the test is broken.
    KeyPairGenerator kf = KeyPairGenerator.getInstance("ECIES");
    kf.initialize(ecSpec);
    KeyPair keyPair = kf.generateKeyPair();
    PrivateKey priv = keyPair.getPrivate();
    PublicKey pub = keyPair.getPublic();
    byte[] message = "Hello".getBytes("UTF-8");

    // Encryption
    Cipher cipher = Cipher.getInstance("ECIESwithAES-CBC");
    cipher.init(Cipher.ENCRYPT_MODE, pub);
    ByteBuffer ptBuffer = ByteBuffer.wrap(message);
    ByteBuffer ctBuffer = ByteBuffer.allocate(1024);
    cipher.doFinal(ptBuffer, ctBuffer);

    // Decryption
    ctBuffer.flip();
    ByteBuffer decrypted = ByteBuffer.allocate(message.length);
    cipher.init(Cipher.DECRYPT_MODE, priv);
    cipher.doFinal(ctBuffer, decrypted);
    assertEquals(TestUtil.bytesToHex(message), TestUtil.bytesToHex(decrypted.array()));
  }

  /**
   * Cipher.doFinal(ByteBuffer, ByteBuffer) should be copy-safe according to
   * https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html
   *
   * <p>This test tries to verify this.
   */
  @NoPresubmitTest(
    providers = {ProviderType.BOUNCY_CASTLE},
    bugs = {"b/30424901: won't fix, all BC ECIES modes are banned"}
  )
  @Test
  public void testByteBufferAlias() throws Exception {
    byte[] message = "Hello".getBytes("UTF-8");
    String algorithm = "ECIESWithAES-CBC";
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
    KeyPairGenerator kf = KeyPairGenerator.getInstance("EC");
    kf.initialize(ecSpec);
    KeyPair keyPair = kf.generateKeyPair();
    Cipher ecies = Cipher.getInstance(algorithm);

    int ciphertextLength = expectedCiphertextLength(algorithm, 32, message.length);
    byte[] backingArray = new byte[ciphertextLength];
    ByteBuffer ptBuffer = ByteBuffer.wrap(backingArray);
    ptBuffer.put(message);
    ptBuffer.flip();

    ecies.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    ByteBuffer ctBuffer = ByteBuffer.wrap(backingArray);
    ecies.doFinal(ptBuffer, ctBuffer);
    ctBuffer.flip();

    ecies.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
    byte[] decrypted = ecies.doFinal(backingArray, 0, ctBuffer.remaining());
    assertEquals(TestUtil.bytesToHex(message), TestUtil.bytesToHex(decrypted));
  }
}
