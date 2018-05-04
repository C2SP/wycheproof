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

/** Test utilities */
public class TestUtil {

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

  public static void installOnlyThisProvider(Provider provider) {
    for (Provider p : Security.getProviders()) {
      Security.removeProvider(p.getName());
    }
    Security.insertProviderAt(provider, 1);
  }

  public static void installOnlyOpenJDKProviders() throws Exception {
    for (Provider p : Security.getProviders()) {
      Security.removeProvider(p.getName());
    }
    installOpenJDKProvider("com.sun.net.ssl.internal.ssl.Provider");
    installOpenJDKProvider("com.sun.crypto.provider.SunJCE");
    installOpenJDKProvider("com.sun.security.sasl.Provider");
    installOpenJDKProvider("org.jcp.xml.dsig.internal.dom.XMLDSigRI");
    installOpenJDKProvider("sun.security.ec.SunEC");
    installOpenJDKProvider("sun.security.jgss.SunProvider");
    installOpenJDKProvider("sun.security.provider.Sun");
    installOpenJDKProvider("sun.security.rsa.SunRsaSign");
    installOpenJDKProvider("sun.security.smartcardio.SunPCSC");
  }

  private static void installOpenJDKProvider(String className) throws Exception {
    Provider provider = (Provider) Class.forName(className).getConstructor().newInstance();
    Security.insertProviderAt(provider, 1);
  }

  public static void printJavaInformation() {
    System.out.println("Running with: ");
    System.out.println("  java.runtime.name: " + System.getProperty("java.runtime.name"));
    System.out.println("  java.runtime.version: " + System.getProperty("java.runtime.version"));
  }
}
