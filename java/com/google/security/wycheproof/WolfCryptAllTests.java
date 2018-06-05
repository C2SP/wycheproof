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

import com.google.security.wycheproof.WycheproofRunner.Provider;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import com.wolfssl.provider.jce.WolfCryptProvider;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite.SuiteClasses;

/**
 * Tests for wolfSSL's crypto library: wolfCrypt
 * wolfCryptAllTests runs all tests.
 */
@RunWith(WycheproofRunner.class)
@SuiteClasses({
//AesGcmTest.class, //need AES/GCM/NoPadding
  BasicTest.class,
//CipherInputStreamTest.class, //err constructing HashDRBG
//CipherOutputStreamTest.class,  //err constructing HashDRBG
//DhTest.class, //err constructing DH
//DsaTest.class,  // DSA keyPairGenerator not available
//EcKeyTest.class,
//EcdhTest.class,
//EcdsaTest.class,
  JsonAeadTest.class,
  JsonCipherTest.class,
//JsonEcdhTest.class,
  JsonKeyWrapTest.class,
//JsonSignatureTest.class,
//MessageDigestTest.class,
//RsaEncryptionTest.class,
//RsaKeyTest.class,
//RsaSignatureTest.class
})
@Provider(ProviderType.WOLFCRYPT)
public final class WolfCryptAllTests {
  @BeforeClass
  public static void setUp() throws Exception {
    TestUtil.installOnlyThisProvider(new WolfCryptProvider());
  }
}
