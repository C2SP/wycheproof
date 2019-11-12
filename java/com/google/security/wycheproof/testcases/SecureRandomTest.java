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
 * The tests here are quite limited. They only test that instances are non-deterministic, when
 * required by the API. The tests do not attempt the determine whether the output is pseudorandom
 * and whether the seeds used are unpredictable.
 *
 * Any instance of SecureRandom must self-seed itself if no seed is provided: hence the following
 * code must never result in deterministic or predictable behaviour:
 * <pre>{@code
 *   // Safe use of SecureRandom
 *   SecureRandom secureRandom = SecureRandom.getInstance(ALGORITHM);
 *   byte[] randomOutput = new byte[SIZE];
 *   secureRandom.nextBytes(randomOutput);
 *   ...
 * }</pre>
 * An important point is that the constructur itself does not necessarily seed the SecureRandom
 * instance and that the self-seeding is only required if caller does not provide any seeds.
 * Thus the following code snippet can lead to deterministic and predictable behaviour:
 * <pre>{@code
 *   // Potentially deterministic and predictable outcome.
 *   SecureRandom secureRandom = SecureRandom.getInstance(ALGORITHM);
 *   secureRandom.setSeed(MY_SEED);
 *   byte[] randomOutput = new byte[SIZE];
 *   secureRandom.nextBytes(randomOutput);
 *   ...
 * }</pre>
 * For example "SHA1PRNG" has the property that calling setSeed after the construction gives
 * a SecureRandom instance with output that only depends on the caller provided seeds.
 *
 * Once a SecureRandom instance has been seeded, all further calls of setSeed must add additional
 * randomness. It is not acceptable setSeed overrides the current seed of an instance. Hence the
 * following code must always be non-deterministic.
 * <pre>{@code
 *   SecureRandom secureRandom = SecureRandom.getInstance(ALGORITHM);
 *   // The next line forces secureRandom to self-seed.
 *   secureRandom.nextBytes(new byte[1]);
 *   // Adding and additional seed. The instance remains properly seeded and unpredictable even if
 *   // MY_SEED is known or constant.
 *   secureRandom.setSeed(MY_SEED);
 *   byte[] randomOutput = new byte[SIZE];
 *   secureRandom.nextBytes(randomOutput);
 *   ...
 * }</pre>
 *
 */
@RunWith(JUnit4.class)
public class SecureRandomTest {

  /** Returns a list of all implemented services of SecureRandom. */
  Collection<Provider.Service> secureRandomServices() {
    // TODO(bleichen): Check if all instances of SecureRandom are actually
    //   listed as services. In particular the default SecureRandom() and
    //   SecureRandom.getInstanceStrong() may not not be registered.
    ArrayList<Provider.Service> result = new ArrayList<Provider.Service>();
    for (Provider p : Security.getProviders()) {
      for (Provider.Service service : p.getServices()) {
        if (service.getType().equals("SecureRandom")) {
          result.add(service);
        }
      }
    }
    return result;
  }

  /**
   * Uninitialized instances or SecureRandom must self-seed before
   * their first use.
   */
  @Test
  public void testSeedUninitializedInstance() throws Exception {
    final int samples = 10;  // the number of samples per SecureRandom.
    // The size of the generated pseudorandom bytes. An output size of 8 bytes
    // means that the probability of false positives is about
    //   2^{-65}*(samples * (#secure random instances))^2.
    // Hence a random failure of this function is unlikely.
    final int outputsize = 8;
    Set<String> seen = new TreeSet<String>();
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
   * Calling setSeed directly after the initialization may result in deterministic
   * results.
   *
   * The test expects that a SecureRandom instance is either completely deterministic if
   * seeded or non-deterministic and unpredictable (though the test is much too simple
   * to give any meaningful result).
   * 
   * For example the provider "SUN" has the following behaviour:
   * <pre>
   *   Seeding SHA1PRNG from SUN results in deterministic output.
   *   Seeding NativePRNG from SUN results in non-deterministic output.
   *   Seeding NativePRNGBlocking from SUN results in non-deterministic output.
   *   Seeding NativePRNGNonBlocking from SUN results in non-deterministic output.
   * </pre>
   *
   * jdk9 adds a class java.security.DrbgParameter, which allows to better specify the expected
   * behaviour of SecureRandom instances. Tests with these parameters are not included here.
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
      Set<String> seen = new TreeSet<String>();
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
    Set<String> seen = new TreeSet<String>();
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
