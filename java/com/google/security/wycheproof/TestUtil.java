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


import java.nio.ByteBuffer;
import java.security.Provider;
import java.security.Security;
import org.junit.Assume;

/** Test utilities */
public class TestUtil {

  public static void skipTest(String reason) {
    // Skips a test for a given reason.
    // This method never returns (i.e. in kotlin it would have return
    // type Nothing). Java does not seem to allow an equivalent declaration.
    // Hence a caller should generally call this function as
    //    skipTest("some reason");
    //    return;
    Assume.assumeTrue(reason, false);
  }

  public static String bytesToHex(byte[] bytes) {
    // bytesToHex is used to convert output from Cipher.
    // cipher.update can return null, which is equivalent to returning
    // no plaitext rsp. ciphertext.
    if (bytes == null) {
      return "";
    }
    String chars = "0123456789abcdef";
    StringBuilder result = new StringBuilder(2 * bytes.length);
    for (byte b : bytes) {
      // convert to unsigned
      int val = b & 0xff;
      result.append(chars.charAt(val / 16));
      result.append(chars.charAt(val % 16));
    }
    return result.toString();
  }

  /**
   * Returns a hexadecimal representation of the bytes written to ByteBuffer (i.e. all the bytes
   * before position()).
   */
  public static String byteBufferToHex(ByteBuffer buffer) {
    ByteBuffer tmp = buffer.duplicate();
    tmp.flip();
    byte[] bytes = new byte[tmp.remaining()];
    tmp.get(bytes);
    return bytesToHex(bytes);
  }

  public static byte[] hexToBytes(String hex) throws IllegalArgumentException {
    if (hex.length() % 2 != 0) {
      throw new IllegalArgumentException("Expected a string of even length");
    }
    int size = hex.length() / 2;
    byte[] result = new byte[size];
    for (int i = 0; i < size; i++) {
      int hi = Character.digit(hex.charAt(2 * i), 16);
      int lo = Character.digit(hex.charAt(2 * i + 1), 16);
      if ((hi == -1) || (lo == -1)) {
        throw new IllegalArgumentException("input is not hexadecimal");
      }
      result[i] = (byte) (16 * hi + lo);
    }
    return result;
  }

  public static void removeAllProviders() {
    for (Provider p : Security.getProviders()) {
      System.out.println("Removing provider: " + p.getName());
      Security.removeProvider(p.getName());
    }
  }

  public static void installOnlyThisProvider(Provider provider) {
    removeAllProviders();
    Security.insertProviderAt(provider, 1);
  }

  /**
   * Installs a set of OpenJDK providers.
   *
   * <p>The list of providers added to test OpenJDK is based on
   * https://docs.oracle.com/en/java/javase/11/security/oracle-providers.html Below is the list of
   * providers and algorithms that are tested.
   *
   * <ul>
   *   <li>sun.security.provider.Sun: SecureRandom, DSA. Also implements SHA-1, SHA-2 and SHA-3,
   *       which are used in many cryptographic primitives.
   *   <li>com.sun.crypto.provider.SunJCE: AES (CBC, GCM, KW, KWP), Chacha-Poly1305, DH, RSA
   *       encryption (PKCS#1 and OAEP). Algorithms that are not tested include: ARCFOUR, Blowfish,
   *       RC2, DES and PBE.
   *   <li>sun.security.ec.SunEC: ECDH, XDH, ECDSA, EdDSA
   *   <li>sun.security.rsa.SunRsaSign: RSA PKCS#1, RSASSA-PSS.
   * </ul>
   *
   * Sun providers that do not implement cryptographic primitives that are tested here are:
   *
   * <ul>
   *   <li>com.sun.security.sasl.Provider: implements CRAM-MD5 DIGEST-MD5, NTLM.
   *   <li>sun.security.jgss.SunProvider
   *   <li>sun.security.smartcardio.SunPCSC
   *   <li>org.jcp.xml.dsig.internal.dom.XMLDSigRI
   *   <li>SunPKCS11: PKCS #11 Cryptoki interface.
   *   <li>JdkLDAP: implements the LDAP CertStore
   *   <li>JdkSASL: implements SASL client and server
   *   <li>Apple provider: implements a keystore that provides acces to the macOS keychain.
   *   <li>SunJSSE is a provider that is backwards compatible with older releases. Oracle recommends
   *       to no longer use it for most use cases. Because of this it is not added as a provider.
   *   <li>com.oracle.security.ucrypto.UcryptoProvider: leverages the Solaris Ucrypto library.
   * </ul>
   */
  public static void installOnlyOpenJDKProviders() throws Exception {
    removeAllProviders();
    installOpenJDKProvider("sun.security.provider.Sun");
    installOpenJDKProvider("com.sun.crypto.provider.SunJCE");
    installOpenJDKProvider("sun.security.rsa.SunRsaSign");
    installOpenJDKProvider("sun.security.ec.SunEC");
  }

  private static void installOpenJDKProvider(String className) throws Exception {
    Provider provider = (Provider) Class.forName(className).getConstructor().newInstance();
    System.out.println("Adding provider: " + provider.getName() + " (" + className + ")");
    Security.addProvider(provider);
  }

  public static void printJavaInformation() {
    System.out.println("Running with: ");
    System.out.println("  java.runtime.name: " + System.getProperty("java.runtime.name"));
    System.out.println("  java.runtime.version: " + System.getProperty("java.runtime.version"));
  }
}
