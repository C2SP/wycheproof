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

import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * RSA encryption tests
 *
 * @author bleichen@google.com (Daniel Bleichenbacher)
 */
// TODO(bleichen): test vectors check special cases:
// - ciphertext too long
// - plaintext too long
// - ciphertext 0
// - ciphertext == modulus timing attacks
@RunWith(JUnit4.class)
public class RsaEncryptionTest {

  /**
   * Providers that implement RSA with PKCS1Padding but not OAEP are outdated and should be avoided
   * even if RSA is currently not used in a project. Such providers promote using an insecure
   * cipher. There is a great danger that PKCS1Padding is used as a temporary workaround, but later
   * stays in the project for much longer than necessary.
   */
  @Test
  public void testOutdatedProvider() throws Exception {
    try {
      Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      try {
        Cipher.getInstance("RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING");
      } catch (NoSuchPaddingException | NoSuchAlgorithmException ex) {
        fail("Provider " + c.getProvider().getName() + " is outdated and should not be used.");
      }
    } catch (NoSuchPaddingException | NoSuchAlgorithmException ex) {
      System.out.println("RSA/ECB/PKCS1Padding is not implemented");
    }
  }

  /**
   * Tries decrypting random messages with a given algorithm. Counts the number of distinct error
   * messages and expects this number to be 1.
   *
   * <p><b>References:</b>
   *
   * <ul>
   *   <li>Bleichenbacher, "Chosen ciphertext attacks against protocols based on the RSA encryption
   *       standard PKCS# 1" Crypto 98
   *   <li>Manger, "A chosen ciphertext attack on RSA optimal asymmetric encryption padding (OAEP)
   *       as standardized in PKCS# 1 v2.0", Crypto 2001 This paper shows that OAEP is susceptible
   *       to a chosen ciphertext attack if error messages distinguish between different failure
   *       condidtions.
   *   <li>Bardou, Focardi, Kawamoto, Simionato, Steel, Tsay "Efficient Padding Oracle Attacks on
   *       Cryptographic Hardware", Crypto 2012 The paper shows that small differences on what
   *       information an attacker receives can make a big difference on the number of chosen
   *       message necessary for an attack.
   *   <li>Smart, "Errors matter: Breaking RSA-based PIN encryption with thirty ciphertext validity
   *       queries" RSA conference, 2010 This paper shows that padding oracle attacks can be
   *       successful with even a small number of queries.
   * </ul>
   *
   * <p><b>Some recent bugs:</b> CVE-2012-5081: Java JSSE provider leaked information through
   * exceptions and timing. Both the PKCS #1 padding and the OAEP padding were broken:
   * http://www-brs.ub.ruhr-uni-bochum.de/netahtml/HSS/Diss/MeyerChristopher/diss.pdf
   *
   * <p><b>What this test does not (yet) cover:</b>
   *
   * <ul>
   *   <li>A previous version of one of the provider leaked the block type. (when was this fixed?)
   *   <li>Some attacks require a large number of ciphertexts to be detected if random ciphertexts
   *       are used. Such problems require specifically crafted ciphertexts to run in a unit test.
   *       E.g. "Attacking RSA-based Sessions in SSL/TLS" by V. Klima, O. Pokorny, and T. Rosa:
   *       https://eprint.iacr.org/2003/052/
   *   <li>Timing leakages because of differences in parsing the padding (e.g. CVE-2015-7827) Such
   *       differences are too small to be reliably detectable in unit tests.
   * </ul>
   */
  @SuppressWarnings("InsecureCryptoUsage")
  public void testExceptions(String algorithm) throws Exception {
    KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
    keygen.initialize(1024);
    KeyPair keypair = keygen.genKeyPair();
    SecureRandom rand = new SecureRandom();
    Cipher c = Cipher.getInstance(algorithm);
    byte[] ciphertext = new byte[1024 / 8];
    HashSet<String> exceptions = new HashSet<String>();
    final int samples = 1000;
    for (int i = 0; i < samples; i++) {
      rand.nextBytes(ciphertext);
      ciphertext[0] &= (byte) 0x7f;
      try {
        c.init(Cipher.DECRYPT_MODE, keypair.getPrivate());
        c.doFinal(ciphertext);
      } catch (Exception ex) {
        exceptions.add(ex.toString());
      }
    }
    Cipher enc = Cipher.getInstance("RSA/ECB/NOPADDING");
    byte[][] paddedKeys = generatePkcs1Vectors(1024 / 8);
    for (int i = 0; i < paddedKeys.length; i++) {
      enc.init(Cipher.ENCRYPT_MODE, keypair.getPublic());
      ciphertext = enc.doFinal(paddedKeys[i]);
      try {
        c.init(Cipher.DECRYPT_MODE, keypair.getPrivate());
        c.doFinal(ciphertext);
      } catch (Exception ex) {
        exceptions.add(ex.toString());
      }
    }
    if (exceptions.size() > 1) {
      System.out.println("Exceptions for " + algorithm);
      for (String s : exceptions) {
        System.out.println(s);
      }
      fail("Exceptions leak information about the padding for " + algorithm);
    }
  }

  /**
   * Tests the exceptions for RSA decryption with PKCS1Padding. PKCS1Padding is susceptible to
   * chosen message attacks. Nonetheless, to minimize the damage of such an attack an implementation
   * should minimize the information about the failure in the padding.
   */
  @Test
  public void testExceptionsPKCS1() throws Exception {
    testExceptions("RSA/ECB/PKCS1PADDING");
  }

  @Test
  public void testGetExceptionsOAEP() throws Exception {
    testExceptions("RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING");
  }

  /**
   * Generates PKCS#1 invalid vectors
   *
   * @param rsaKeyLength
   */
  private byte[][] generatePkcs1Vectors(int rsaKeyLength) {
    // create plain padded keys
    byte[][] plainPaddedKeys = new byte[13][];
    // no 0x00 byte to deliver a symmetric key
    plainPaddedKeys[0] = getEK_NoNullByte(rsaKeyLength);
    // 0x00 too early in the padding
    plainPaddedKeys[1] = getEK_NullByteInPadding(rsaKeyLength);
    // 0x00 too early in the PKCS#1 padding
    plainPaddedKeys[2] = getEK_NullByteInPkcsPadding(rsaKeyLength);
    // decrypted ciphertext starting with 0x17 0x02
    plainPaddedKeys[3] = getEK_WrongFirstByte(rsaKeyLength);
    // decrypted ciphertext starting with 0x00 0x17
    plainPaddedKeys[4] = getEK_WrongSecondByte(rsaKeyLength);
    // different lengths of the decrypted unpadded key
    plainPaddedKeys[5] = getPaddedKey(rsaKeyLength, 0);
    plainPaddedKeys[6] = getPaddedKey(rsaKeyLength, 1);
    plainPaddedKeys[7] = getPaddedKey(rsaKeyLength, 8);
    plainPaddedKeys[8] = getPaddedKey(rsaKeyLength, 16);
    plainPaddedKeys[9] = getPaddedKey(rsaKeyLength, 96);
    // the decrypted padded plaintext is shorter than RSA key
    plainPaddedKeys[10] = getPaddedKey(rsaKeyLength - 1, 16);
    plainPaddedKeys[11] = getPaddedKey(rsaKeyLength - 2, 16);
    // just 0x00 bytes
    plainPaddedKeys[12] = new byte[rsaKeyLength];
    return plainPaddedKeys;
  }

  private byte[] getPaddedKey(int rsaKeyLength, int symmetricKeyLength) {
    byte[] key = new byte[rsaKeyLength];
    // fill all the bytes with non-zero values
    Arrays.fill(key, (byte) 42);
    // set the first byte to 0x00
    key[0] = 0x00;
    // set the second byte to 0x02
    key[1] = 0x02;
    // set the separating byte
    if (symmetricKeyLength != -1) {
      key[rsaKeyLength - symmetricKeyLength - 1] = 0x00;
    }
    return key;
  }

  private byte[] getEK_WrongFirstByte(int rsaKeyLength) {
    byte[] key = getPaddedKey(rsaKeyLength, 16);
    key[0] = 23;
    return key;
  }

  private byte[] getEK_WrongSecondByte(int rsaKeyLength) {
    byte[] key = getPaddedKey(rsaKeyLength, 16);
    key[1] = 23;
    return key;
  }

  private byte[] getEK_NoNullByte(int rsaKeyLength) {
    byte[] key = getPaddedKey(rsaKeyLength, -1);
    return key;
  }

  private byte[] getEK_NullByteInPkcsPadding(int rsaKeyLength) {
    byte[] key = getPaddedKey(rsaKeyLength, 16);
    key[3] = 0x00;
    return key;
  }

  private byte[] getEK_NullByteInPadding(int rsaKeyLength) {
    byte[] key = getPaddedKey(rsaKeyLength, 16);
    key[11] = 0x00;
    return key;
  }
}
