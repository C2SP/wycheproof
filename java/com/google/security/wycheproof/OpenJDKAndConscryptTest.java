/**
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.security.wycheproof;

import com.google.security.wycheproof.WycheproofRunner.Fast;
import com.google.security.wycheproof.WycheproofRunner.Provider;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import java.security.Security;
import org.conscrypt.OpenSSLProvider;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite.SuiteClasses;

/**
 * Tests for OpenJDK and Conscrypt provider.
 *
 * <p>This test installs Conscrypt after OpenJDK. The goal of the test is to find primitives that
 * don't perform properly if OpenJDK has priority. One example are EC primitives with secp224r1.
 * OpenJDK no longer supports this curve, but Conscrypt still does.
 */
@RunWith(WycheproofRunner.class)
@SuiteClasses({
  AesGcmTest.class,
  BasicTest.class,
  CipherInputStreamTest.class,
  CipherOutputStreamTest.class,
  DhTest.class,
  DsaTest.class,
  EcKeyTest.class,
  EcdhTest.class,
  EcdsaTest.class,
  JsonAeadTest.class,
  JsonCipherTest.class,
  JsonEcdhTest.class,
  JsonKeyWrapTest.class,
  JsonMacTest.class,
  JsonRsaEncryptionTest.class,
  JsonSignatureTest.class,
  JsonXdhTest.class,
  MacTest.class,
  MessageDigestTest.class,
  RsaKeyTest.class,
  RsaPssTest.class,
  RsaOaepTest.class,
  RsaSignatureTest.class,
  SecureRandomTest.class,
})
@Provider(ProviderType.OPENJDK_AND_CONSCRYPT)
@Fast
public final class OpenJDKAndConscryptTest {
  @BeforeClass
  public static void setUp() throws Exception {
    TestUtil.installOnlyOpenJDKProviders();
    Security.addProvider(new OpenSSLProvider());
  }
}
