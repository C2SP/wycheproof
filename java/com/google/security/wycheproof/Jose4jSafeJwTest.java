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

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.flogger.GoogleLogger;
import com.google.testing.testsize.MediumTest;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.VerificationJwkSelector;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

/**
 * Tests Jose.4.j directly to demonstrate what the jwcrypto wrapper protects against. The wrapper is
 * tested with {@link JwCryptoSafeJwTest}.
 */
@MediumTest
public class Jose4jSafeJwTest extends AbstractJsonWebTest {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @Override
  protected ImmutableSet<String> getSuppressedTests() {
    return ImmutableSet.of(
        // Nothing checks for weak keys during the verification process.
        "jws_rsa_roca_key_rejectsKeyWithRocaVulnerability_tcId46",
        // jose.4.j doesn't care if you mix inappropriate keys.
        "jws_mixedSymmetryKeyset_rejectsValid_tcId47");
  }

  @Override
  public boolean performKeysetVerification(String compactJws, String verificationKeyset) {
    JsonWebSignature verifier = new JsonWebSignature();

    try {
      verifier.setCompactSerialization(compactJws);
      JsonWebKeySet parsedKeyset = new JsonWebKeySet(verificationKeyset);

      VerificationJwkSelector jwkSelector = new VerificationJwkSelector();
      JsonWebKey usedVerificationKey;
      try {
        usedVerificationKey = jwkSelector.select(verifier, parsedKeyset.getJsonWebKeys());
      } catch (JoseException e) {
        throw new SecurityException("Verification key selection failed", e);
      }
      if (usedVerificationKey == null) {
        // The key selector would have caused this to fail but let's pretend we weren't using it.
        // This code isn't set up to work with keysets that don't select a key (so throw).
        usedVerificationKey = Iterables.getOnlyElement(parsedKeyset.getJsonWebKeys());
      }

      verifier.setKey(usedVerificationKey.getKey());
      return verifier.verifySignature();
    } catch (Exception e) {
      logger.atInfo().withCause(e).log(
          "Verification was unsuccessful.\njws: %s\njwk: %s", compactJws, verificationKeyset);
      return false;
    }
  }

  @Override
  public boolean performDecryption(String compactJwe, String decryptionJwk) {
    JsonWebEncryption decrypter = new JsonWebEncryption();

    try {
      decrypter.setCompactSerialization(compactJwe);
      JsonWebKey parsedKey = JsonWebKey.Factory.newJwk(decryptionJwk);
      decrypter.setKey(
          parsedKey instanceof PublicJsonWebKey
              ? ((PublicJsonWebKey) parsedKey).getPrivateKey()
              : parsedKey.getKey());
      decrypter.getPlaintextBytes();
      return true;
    } catch (Exception e) {
      logger.atInfo().withCause(e).log(
          "Decryption was unsuccessful.\njwe: %s\njwk: %s", compactJwe, decryptionJwk);
      return false;
    }
  }
}
