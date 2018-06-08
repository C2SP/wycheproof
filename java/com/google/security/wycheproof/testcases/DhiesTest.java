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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
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
// TODO(bleichen):
// - maybe again CipherInputStream, CipherOutputStream,
// - byteBuffer.
// - Exception handling
// - Is DHIES using the key derivation function for the key stream?
// - BouncyCastle knows an algorithm IES. Is this the same as DHIES?
// - Bouncy fixed a padding oracle bug in version 1.56 (CVE-2016-1000345)
//   So far we have no test for this bug mainly because this cannot be tested
//   through the JCA interface. BC does not register and algorithm such as
//   Cipher.DHIESWITHAES-CBC.
// - So far only BouncyCastles is tesed because this is the only provider
//   we use that implements DHIES.
@RunWith(JUnit4.class)
public class DhiesTest {

  // TODO(bleichen): This is the same as DhTest.java
  //   We could move this into some TestUtil.
  public DHParameterSpec ike2048() {
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

  /**
   * WARNING: This test uses weak crypto (i.e. DHIESWithAES), if supported. Checks that key
   * agreement using DHIES works in the sense that it can decrypt what it encrypts. Unfortunately it
   * seems that there is no secure mode using AES.
   */
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testDhiesBasic() throws Exception {
    DHParameterSpec params = ike2048();
    KeyPairGenerator kf = KeyPairGenerator.getInstance("DH");
    kf.initialize(params);
    KeyPair keyPair = kf.generateKeyPair();
    PrivateKey priv = keyPair.getPrivate();
    PublicKey pub = keyPair.getPublic();
    byte[] message = "Hello".getBytes("UTF-8");
    Cipher dhies;
    try {
      dhies = Cipher.getInstance("DHIESwithAES");
    } catch (NoSuchAlgorithmException ex) {
      // The algorithm isn't supported - even better!
      return;
    }
    dhies.init(Cipher.ENCRYPT_MODE, pub);
    byte[] ciphertext = dhies.doFinal(message);
    System.out.println("testDhiesBasic:" + TestUtil.bytesToHex(ciphertext));
    dhies.init(Cipher.DECRYPT_MODE, priv);
    byte[] decrypted = dhies.doFinal(ciphertext);
    assertEquals(TestUtil.bytesToHex(message), TestUtil.bytesToHex(decrypted));
  }

  /**
   * WARNING: This test uses weak crypto (i.e. DHIESWithAES). DHIES should be secure against chosen
   * ciphertexts. Checks that a modification of the ciphertext is dectected.
   */
  @SlowTest(providers = {ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE})
  @SuppressWarnings("InsecureCryptoUsage")
  @Test
  public void testDhiesCorrupt() throws Exception {
    KeyPairGenerator kf = KeyPairGenerator.getInstance("DH");
    kf.initialize(ike2048());
    KeyPair keyPair = kf.generateKeyPair();
    PrivateKey priv = keyPair.getPrivate();
    PublicKey pub = keyPair.getPublic();
    byte[] message = new byte[32];
    Cipher dhies;
    try {
      dhies = Cipher.getInstance("DHIESwithAES");
    } catch (NoSuchAlgorithmException ex) {
      // The algorithm isn't supported - even better!
      return;
    }
    dhies.init(Cipher.ENCRYPT_MODE, pub);
    byte[] ciphertext = dhies.doFinal(message);
    for (int i = 0; i < ciphertext.length; i++) {
      byte[] corrupt = Arrays.copyOf(ciphertext, ciphertext.length);
      corrupt[i] ^= (byte) 1;
      try {
        dhies.init(Cipher.DECRYPT_MODE, priv);
        dhies.doFinal(corrupt);
        fail("Corrupt ciphertext accepted:" + i);
      } catch (GeneralSecurityException ex) {
        // This is expected
      }
    }
  }

  /**
   * Tries to detect if an algorithm is using ECB. Unfortunately, many JCE algorithms use ECB if no
   * encryption mode is specified.
   */
  @SuppressWarnings("InsecureCryptoUsage")
  public void testNotEcb(String algorithm) throws Exception {
    Cipher dhies;
    try {
      dhies = Cipher.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      // This test is called with short algorithm names such as just "DHIES".
      // Requiring full names is typically a good practice. Hence it is OK
      // to not assigning default algorithms.
      System.out.println("No implementation for:" + algorithm);
      return;
    }
    KeyPairGenerator kf = KeyPairGenerator.getInstance("DH");
    kf.initialize(ike2048());
    KeyPair keyPair = kf.generateKeyPair();
    PublicKey pub = keyPair.getPublic();
    byte[] message = new byte[512];
    dhies.init(Cipher.ENCRYPT_MODE, pub);
    byte[] ciphertext = dhies.doFinal(message);
    for (int i = 0; i + 32 <= ciphertext.length; i++) {
      String block1 = TestUtil.bytesToHex(Arrays.copyOfRange(ciphertext, i, i + 16));
      String block2 = TestUtil.bytesToHex(Arrays.copyOfRange(ciphertext, i + 16, i + 32));
      assertTrue(
          "Ciphertext repeats at " + i + ":" + TestUtil.bytesToHex(ciphertext),
          !block1.equals(block2));
    }
  }

  @Test
  public void testSemanticSecurityDhies() throws Exception {
    testNotEcb("DHIES");
  }

  /**
   * Tests whether DHIESWithAES uses a reasonable encryption mode.
   *
   * <p>Problems found:
   *
   * <ul>
   *   <li>CVE-2016-1000344 BouncyCaslte before v.1.56 used ECB mode as a default.
   * </ul>
   */
  @NoPresubmitTest(
    providers = {ProviderType.BOUNCY_CASTLE},
    bugs = {"b/31101111: won't fix, all BC DHIES modes are banned"}
  )
  @Test
  public void testSemanticSecurityDhiesWithAes() throws Exception {
    testNotEcb("DHIESWithAES");
  }

  @NoPresubmitTest(
    providers = {ProviderType.BOUNCY_CASTLE},
    bugs = {"b/31101111: won't fix, all BC DHIES modes are banned"}
  )
  @Test
  public void testSemanticSecurityDhiesWithDesede() throws Exception {
    testNotEcb("DHIESWITHDESEDE");
  }
}
