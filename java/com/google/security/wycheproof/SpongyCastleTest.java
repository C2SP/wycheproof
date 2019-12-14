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

import com.google.security.wycheproof.WycheproofRunner.Fast;
import com.google.security.wycheproof.WycheproofRunner.Provider;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite.SuiteClasses;
import org.spongycastle.jce.provider.BouncyCastleProvider;

/**
 * Spongy Castle is a Bouncy Castle clone with a few changes to make it work on Android.
 * SpongyCastleTest excludes {@code @SlowTest} tests.
 */
@RunWith(WycheproofRunner.class)
@SuiteClasses({
  AesEaxTest.class,
  AesGcmTest.class,
  BasicTest.class,
  CipherInputStreamTest.class,
  CipherOutputStreamTest.class,
  DhTest.class,
  DhiesTest.class,
  DsaTest.class,
  EcKeyTest.class,
  EcdhTest.class,
  EcdsaTest.class,
  EciesTest.class,
  JsonAeadTest.class,
  JsonCipherTest.class,
  JsonEcdhTest.class,
  JsonKeyWrapTest.class,
  JsonMacTest.class,
  JsonSignatureTest.class,
  MacTest.class,
  MessageDigestTest.class,
  RsaEncryptionTest.class,
  RsaKeyTest.class,
  RsaOaepTest.class,
  RsaPssTest.class,
  RsaSignatureTest.class,
  SecureRandomTest.class,
})
@Provider(ProviderType.SPONGY_CASTLE)
@Fast
public final class SpongyCastleTest {
  @BeforeClass
  public static void setUp() throws Exception {
    TestUtil.installOnlyThisProvider(new BouncyCastleProvider());
  }
}
