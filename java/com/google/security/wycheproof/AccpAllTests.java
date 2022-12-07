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

import com.google.security.wycheproof.WycheproofRunner.Provider;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite.SuiteClasses;

/**
 * Amazon Corretto Crypto Provider is a Java security provider from Amazon which uses OpenSSL. See
 * {@link https://github.com/corretto/amazon-corretto-crypto-provider}.
 *
 * <p>AccpAllTests runs all tests, except that tests that are explicitly excluded.
 * The list of test classes below contains tests for primitives that are implemented by OpenSSL,
 * but are not listed as implemented by the Amazon Corretto Crypto Provider. Tests for primitives
 * that are not implemented are simply skipped. The reason for including the tests anyway is
 * to catch accidential, experimental additions.
 */
@RunWith(WycheproofRunner.class)
@SuiteClasses({
  AesGcmTest.class,
  BasicTest.class,
  CipherInputStreamTest.class,
  CipherOutputStreamTest.class,
  // Diffie-Hellman is not implemented by the provider.
  DhTest.class,
  // DSA is not implemented by the provider.
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
  // XDH is not implemented by the provider.
  JsonXdhTest.class,
  MacTest.class,
  MessageDigestTest.class,
  RsaKeyTest.class,
  RsaPssTest.class,
  RsaSignatureTest.class,
  SecureRandomTest.class
})
@Provider(ProviderType.AMAZON_CORRETTO_CRYPTO_PROVIDER)
public final class AccpAllTests {
  @BeforeClass
  public static void setUp() throws Exception {
    TestUtil.installOnlyOpenJDKProviders();
    com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider.install();
    com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider.INSTANCE.assertHealthy();
  }
}
