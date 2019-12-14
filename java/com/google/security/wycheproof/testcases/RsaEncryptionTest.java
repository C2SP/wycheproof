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
import static org.junit.Assert.fail;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Set;
import java.util.TreeSet;
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
   * Get a PublicKey from a JsonObject.
   *
   * <p>object contains the key in multiple formats: "key" : elements of the public key "keyDer":
   * the key in ASN encoding encoded hexadecimal "keyPem": the key in Pem format encoded hexadecimal
   * The test can use the format that is most convenient.
   */
  // This is a false positive, since errorprone cannot track values passed into a method.
  @SuppressWarnings("InsecureCryptoUsage")
  protected static PrivateKey getPrivateKey(JsonObject object) throws Exception {
    KeyFactory kf;
    kf = KeyFactory.getInstance("RSA");
    byte[] encoded = TestUtil.hexToBytes(object.get("privateKeyPkcs8").getAsString());
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
    return kf.generatePrivate(keySpec);
  }

  /** Convenience method to get a byte array from a JsonObject */
  protected static byte[] getBytes(JsonObject object, String name) throws Exception {
    return JsonUtil.asByteArray(object.get(name));
  }

  /**
   * Tries decrypting RSA-PKCS #1 v 1.5 encrypted ciphertext.
   * RSA-PKCS #1 v 1.5 is susceptible to chosen ciphertext attacks. The seriousness of the
   * attack depends on how much information is leaked when decrypting an invalid ciphertext.
   * The test vectors with invalid padding contain a flag "InvalidPkcs1Padding".
   * The test below expects that all test vectors with this flag throw an indistinguishable
   * exception. 
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
  public void testDecryption(String filename) throws Exception {
    final String expectedSchema = "rsaes_pkcs1_decrypt_schema.json";
    JsonObject test = JsonUtil.getTestVectors(filename);
    String schema = test.get("schema").getAsString();
    if (!schema.equals(expectedSchema)) {
      System.out.println(
          "Expecting test vectors with schema "
              + expectedSchema
              + " found vectors with schema "
              + schema);
    }
    // Padding oracle attacks become simpler when the decryption leaks detailed information about
    // invalid paddings. Hence implementations are expected to not include such information in the
    // exception thrown in the case of an invalid padding.
    // Test vectors with an invalid padding have a flag "InvalidPkcs1Padding".
    // Invalid test vectors without this flag are cases where the error are detected before
    // the ciphertext is decrypted, e.g. if the size of the ciphertext is incorrect.
    final String invalidPkcs1Padding = "InvalidPkcs1Padding";
    Set<String> exceptions = new TreeSet<String>();

    int errors = 0;
    Cipher decrypter = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      PrivateKey key = getPrivateKey(group);
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        int tcid = testcase.get("tcId").getAsInt();
        String messageHex = TestUtil.bytesToHex(getBytes(testcase, "msg"));
        byte[] ciphertext = getBytes(testcase, "ct");
        String ciphertextHex = TestUtil.bytesToHex(ciphertext);
        String result = testcase.get("result").getAsString();
        decrypter.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = null;
        String exception = "";
        try {
          decrypted = decrypter.doFinal(ciphertext);
        } catch (Exception ex) {
          // TODO(bleichen): The exception thrown should always be
          //   a GeneralSecurityException.
          //   However, BouncyCastle throws some non-conforming exceptions.
          //   For the moment we do not count this as a problem to avoid that
          //   more serious bugs remain hidden. In particular, the test expects
          //   that all ciphertexts with an invalid padding throw the same
          //   indistinguishable exception.
          decrypted = null;
          exception = ex.toString();
          for (JsonElement flag : testcase.getAsJsonArray("flags")) {
            if (flag.getAsString().equals(invalidPkcs1Padding)) {
              exceptions.add(exception);
              break;
            }
          }
        }
        if (decrypted == null && result.equals("valid")) {
            System.out.printf(
                "Valid ciphertext not decrypted. filename:%s tcId:%d ct:%s cause:%s\n",
                filename, tcid, ciphertextHex, exception);
          errors++;
        } else if (decrypted != null) {
          String decryptedHex = TestUtil.bytesToHex(decrypted);
          if (result.equals("invalid")) {
            System.out.printf(
                "Invalid ciphertext decrypted. filename:%s tcId:%d expected:%s decrypted:%s\n",
                filename, tcid, messageHex, decryptedHex);
             errors++;
          } else if (!decryptedHex.equals(messageHex)) {
            System.out.printf(
                "Incorrect decryption. filename:%s tcId:%d expected:%s decrypted:%s\n",
                filename, tcid, messageHex, decryptedHex);
             errors++;
          }
        }
      }
    }
    if (exceptions.size() != 1) {
      System.out.println("Exceptions for RSA/ECB/PKCS1Padding");
      for (String s : exceptions) {
        System.out.println(s);
      }
      fail("Exceptions leak information about the padding");
    }
    assertEquals(0, errors);
  }

  @Test
  public void testDecryption2048() throws Exception {
    testDecryption("rsa_pkcs1_2048_test.json");
  }

  @Test
  public void testDecryption3072() throws Exception {
    testDecryption("rsa_pkcs1_3072_test.json");
  }

  @Test
  public void testDecryption4096() throws Exception {
    testDecryption("rsa_pkcs1_4096_test.json");
  }
}
