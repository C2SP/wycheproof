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
//  AesGcmTest.class,             /* No Support. Skipped. */
    BasicTest.class,
//  CipherInputStreamTest.class,  /* SIG FAULT */
//  CipherOutputStreamTest.class, /* SIG FAULT */
    DhTest.class,
//  DsaTest.class,                /* No Support. Skipped */
    EcKeyTest.class,
    EcdhTest.class,               /* 2 failures, 2 Ignored tests */
    EcdsaTest.class,
    JsonAeadTest.class,           /* Pass. no modification. Skips 2 AES. */
    JsonCipherTest.class,         /* Pass. no modification. Skips 1 AES. */
//  JsonEcdhTest.class,           /* Fail 1 test. No support EC KeyFactory */
    JsonKeyWrapTest.class,
    JsonSignatureTest.class,      /* 1/7 fail, secp and DSA ignored */
//  MessageDigestTest.class,
    RsaEncryptionTest.class,      /* RSA KeyPairGenerator skip 2, 1 crit. fail*/
//  RsaKeyTest.class,       /*Fail all test. No RSA KeyFactory or KeyPairGenerator*/
//  RsaSignatureTest.class  /*Fail all test. No RSA KeyFactory or KeyPairGenerator*/
})

@Provider(ProviderType.WOLFCRYPT)
public final class WolfCryptAllTests {
  @BeforeClass
  public static void setUp() throws Exception {
    TestUtil.installOnlyWolfCryptProviders();
  }
}
