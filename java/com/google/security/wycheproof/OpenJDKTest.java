package com.google.security.wycheproof;

import com.google.security.wycheproof.WycheproofRunner.Fast;
import com.google.security.wycheproof.WycheproofRunner.Provider;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite.SuiteClasses;

/**
 * Tests for OpenJDK's providers: SunJCE, SunEC, etc.
 * OpenJDKTest excludes slow tests.
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
  RsaEncryptionTest.class,
  RsaKeyTest.class,
  RsaSignatureTest.class
})
@Provider(ProviderType.OPENJDK)
@Fast
public final class OpenJDKTest {
  @BeforeClass
  public static void setUp() throws Exception {
    TestUtil.installOnlyOpenJDKProviders();
  }
}
