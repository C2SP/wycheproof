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

import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Checks implementations of RSA-PKCS #1 v1.5. */
@RunWith(JUnit4.class)
public class RsaEncryptionTest {

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
}
