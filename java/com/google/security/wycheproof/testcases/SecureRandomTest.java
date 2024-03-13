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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Checks whether instances of SecureRandom follow the SecureRandom API.
 *
 * <p>The tests here are quite limited. They only test that instances are non-deterministic, when
 * required by the API. The tests do not attempt the determine whether the output is pseudorandom
 * and whether the seeds used are unpredictable.
 *
 * <p>Any instance of SecureRandom must self-seed itself if no seed is provided: hence the following
 * code must never result in deterministic or predictable behavior:
 *
 * <pre>{@code
 * // Safe use of SecureRandom
 * SecureRandom secureRandom = SecureRandom.getInstance(ALGORITHM);
 * byte[] randomOutput = new byte[SIZE];
 * secureRandom.nextBytes(randomOutput);
 * ...
 * }</pre>
 *
 * The code above is indeed a typical usage pattern and for example recommended here:
 * https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/SecureRandom.html
 *
 * <p>A legacy issue is that SecureRandom can sometimes behave deterministically. The constructur of
 * a SecureRandom instance does not necessarily seed the instance and self-seeding is only required
 * if the caller does not provide any seeds. For example it is possible to reproduce the output of
 * `SHA1PRNG` with
 *
 * <pre>{@code
 * // Legacy use case: the following code has deterministic behavior.
 * String ALGORITHM = "SHA1PRNG";
 * SecureRandom secureRandom = SecureRandom.getInstance(ALGORITHM);
 * secureRandom.setSeed(MY_SEED);
 * byte[] randomOutput = new byte[SIZE];
 * secureRandom.nextBytes(randomOutput);
 * ...
 * }</pre>
 *
 * This behavior is rather unusual. Algorithms other than `SHA1PRNG` often do not use the seed.
 * `SHA1PRNG` is not well defined and not a stable algorithm. Its output may change between jdk
 * versions. Different provider may use distinct implementations. Because of it is a bad idea to use
 * SecureRandom as a pseudorandom function. Applications that require reproducible pseudorandom
 * output should rather use well defined algorithms such as HMAC, HKDF or SHAKE depending on use
 * case and availiability.
 *
 * <p>The following code should also not be used. The behavior of the code depends on the class used
 * by `new SecureRandom()`. This class depends on the providers that are installed. E.g., if
 * `SHA1PRNG` is being used as the underlying PRNG then the behavior is deterministic, if
 * `NativePRNG` is being used then the behavior is non-deterministic. Thus the behavior can be
 * easily changed by installing new providers or switching their order.
 *
 * <pre>{@code
 * // Unsafe use of SecureRandom
 * SecureRandom rand = new SecureRandom(seed);
 * byte[] bytes = new byte[outputsize];
 * secureRandom.nextBytes(bytes);
 * }</pre>
 *
 * <p>Once a SecureRandom instance has been seeded, all further calls of setSeed must add additional
 * randomness. It is not acceptable if setSeed overrides the current seed of an instance. Hence the
 * following code must always be non-deterministic.
 *
 * <pre>{@code
 * // Safe way to add additional entropy
 * SecureRandom secureRandom = SecureRandom.getInstance(ALGORITHM);
 * // The next line forces secureRandom to self-seed.
 * secureRandom.nextBytes(new byte[1]);
 * // Adding an additional seed. The instance remains properly seeded and unpredictable even if
 * // MY_SEED is known or constant.
 * secureRandom.setSeed(MY_SEED);
 * byte[] randomOutput = new byte[SIZE];
 * secureRandom.nextBytes(randomOutput);
 * ...
 * }</pre>
 */
@RunWith(JUnit4.class)
public class SecureRandomTest {

  /** Returns a list of all implemented services of SecureRandom. */
  Collection<Provider.Service> secureRandomServices() {
    // TODO(bleichen): Check if all instances of SecureRandom are actually
    //   listed as services. In particular the default SecureRandom() and
    //   SecureRandom.getInstanceStrong() may not not be registered.
    ArrayList<Provider.Service> result = new ArrayList<>();
    for (Provider p : Security.getProviders()) {
      for (Provider.Service service : p.getServices()) {
        if (service.getType().equals("SecureRandom")) {
          result.add(service);
        }
      }
    }
    return result;
  }

  /** Uninitialized instances of SecureRandom must self-seed before their first use. */
  @Test
  public void testSeedUninitializedInstance() throws Exception {
    final int samples = 10;  // the number of samples per SecureRandom.
    // The size of the generated pseudorandom bytes. An output size of 8 bytes
    // means that the probability of false positives is about
    //   2^{-65}*(samples * (#secure random instances))^2.
    // Hence a random failure of this function is unlikely.
    final int outputsize = 8;
    Set<String> seen = new TreeSet<>();
    for (Provider.Service service : secureRandomServices()) {
      for (int i = 0; i < samples; i++) {
        SecureRandom random = SecureRandom.getInstance(service.getAlgorithm(),
            service.getProvider());
        byte[] bytes = new byte[outputsize];
        random.nextBytes(bytes);
        String hex = TestUtil.bytesToHex(bytes);
        assertFalse("Repeated output from " + service.getAlgorithm(), seen.contains(hex));
        seen.add(hex);
      }
    }
  }

  /**
   * Tests calling setSeed directly after constructing a SecureRandom instance.
   *
   * <p>If setSeed is called directly after constructing a new SecureRandom instance then its
   * behavior depends on the class of the instance. A SecureRandom instance may used this seed and
   * thus become deterministic and reproducable, the instance may mix the seed into its entropy
   * pool, or may ignore it and use independent seeding.
   *
   * <p>For example the provider "SUN" in jdk20 implements SecureRandom classes with the following
   * behavior:
   *
   * <pre>
   *   Seeding SHA1PRNG results in deterministic output.
   *   Seeding NativePRNG results in non-deterministic output.
   *   Seeding NativePRNGBlocking results in non-deterministic output.
   *   Seeding NativePRNGNonBlocking results in non-deterministic output.
   *   Seeding DRBG from SUN results in non-deterministic output.
   * </pre>
   *
   * Implementations should not depend on the behavior of a given class, since it is easily possible
   * that the observed behavior changes between versions or platforms.
   *
   * <p>jdk9 adds a class java.security.DrbgParameter, which allows to better specify the expected
   * behavior of SecureRandom instances. Tests with these parameters are not included here.
   */
  @Test
  public void testSetSeedAfterConstruction() throws Exception {
    final int samples = 10;  // the number of samples per SecureRandom.
    // The size of the generated pseudorandom bytes. An output size of 8 bytes
    // means that the probability of false positives is about
    //   2^{-65}*(samples * (#secure random instances))^2.
    // Hence a random failure of this function is unlikely.
    final int outputsize = 8;
    final byte[] seed = new byte[32];
    for (Provider.Service service : secureRandomServices()) {
      Provider provider = service.getProvider();
      Set<String> seen = new TreeSet<>();
      for (int i = 0; i < samples; i++) {
        SecureRandom random = SecureRandom.getInstance(service.getAlgorithm(), provider);
        random.setSeed(seed);
        byte[] bytes = new byte[outputsize];
        random.nextBytes(bytes);
        String hex = TestUtil.bytesToHex(bytes);
        seen.add(hex);
      }
      if (seen.size() == 1) {
        System.out.println("Seeding " + service.getAlgorithm() + " from " + provider.getName()
                            + " results in deterministic output.");
      } else {
        System.out.println("Seeding " + service.getAlgorithm() + " from " + provider.getName()
                            + " results in non-deterministic output.");
        // ... and if the implementation is non-determinstic, there should be no repetitions.
        assertEquals(samples, seen.size());
      }
    }
  }

  /**
   * Checks the default for SecureRandom.
   *
   * <p>The test checks the following pattern:
   *
   * <pre>{@code
   * SecureRandom rand = new SecureRandom(seed);
   * byte[] bytes = new byte[outputsize];
   * secureRandom.nextBytes(bytes);
   * }</pre>
   *
   * For example under jdk20 with the SUN provider installed at position 1, the code above uses
   * NativePRNG. This pseudorandom number generator is non-deterministic. If no provider with
   * pseudorandom number generators is installed then SHA1PRNG is being used. This pseudorandom
   * number generator can be seeded deterministially, and the code above has indeed deterministic
   * behavior.
   *
   * <p>Hence it is probably a good idea to avoid the pattern above and to consider it as having
   * undefined or implementation defined behavior. Using no seed (e.g. using new SecureRandom()) is
   * preferable.
   */
  @Test
  public void testDefaultSecureRandom() throws Exception {
    final int samples = 10; // the number of samples per SecureRandom.
    // The size of the generated pseudorandom bytes. An output size of 8 bytes
    // means that the probability of false positives is about
    //   2^{-65}*(samples * (#secure random instances))^2.
    // Hence a random failure of this function is unlikely.
    final int outputsize = 8;
    final byte[] seed = new byte[32];
    Set<String> seen = new TreeSet<>();
    for (int i = 0; i < samples; i++) {
      SecureRandom rand = new SecureRandom(seed);
      byte[] bytes = new byte[outputsize];
      rand.nextBytes(bytes);
      String hex = TestUtil.bytesToHex(bytes);
      seen.add(hex);
    }
    String algorithm = new SecureRandom(seed).getAlgorithm();
    if (seen.size() == 1) {
      System.out.println("Default SecureRandom " + algorithm + " results in deterministic output.");
    } else {
      System.out.println(
          "Default SecureRandom " + algorithm + " results in non-deterministic output.");
      // ... and if the implementation is non-determinstic, there should be no repetitions.
      assertEquals(samples, seen.size());
    }
  }

  /**
   * Calling setSeed after use adds the seed to the current state. It must never replace it.
   */
  @Test
  public void testSetSeedAfterUse() throws Exception {
    final int samples = 10;  // the number of samples per SecureRandom.
    // The size of the generated pseudorandom bytes. An output size of 8 bytes
    // means that the probability of false positives is about
    //   2^{-65}*(samples * (#secure random instances))^2.
    // Hence a random failure of this function is unlikely.
    final int outputsize = 8;
    Set<String> seen = new TreeSet<>();
    final byte[] seed = new byte[32];
    for (Provider.Service service : secureRandomServices()) {
      for (int i = 0; i < samples; i++) {
        SecureRandom random = SecureRandom.getInstance(service.getAlgorithm(),
            service.getProvider());
        // Calling nextBytes() self-seeds the instance.
        byte[] dummy = new byte[0];
        random.nextBytes(dummy);
        // Calling setSeed() adds the seed to the instance. It would be wrong to
        // replace the current state of the instance with the new seed.
        random.setSeed(seed);
        byte[] bytes = new byte[outputsize];
        // Hence it would be an error (or an unlikely false positive) if the generated
        // bytes are already known.
        random.nextBytes(bytes);
        String hex = TestUtil.bytesToHex(bytes);
        assertFalse("Repeated output from " + service.getAlgorithm(), seen.contains(hex));
        seen.add(hex);
      }
    }
  }
}
