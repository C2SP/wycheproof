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

import static org.junit.Assert.assertArrayEquals;

import com.google.common.collect.ImmutableSet;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests the test utilities. */
@RunWith(JUnit4.class)
public final class TestUtilTest {

  private static List<String> getProviders() {
    List<String> providerNames = new ArrayList<>();
    for (Provider p : Security.getProviders()) {
      providerNames.add(p.getName());
    }
    return providerNames;
  }

  @Test
  public void removeProvidersExcept_keepsProvider() throws Exception {
    TestUtil.removeProvidersExcept(ImmutableSet.of(Security.getProvider("SUN")));

    assertArrayEquals(
        "Expected provider not present", getProviders().toArray(), new String[] {"SUN"});
  }

  @Test
  public void installOnlyOpenJDKProviders_correctOrder() throws Exception {
    TestUtil.installOnlyOpenJDKProviders();

    String[] expectedProviders = {"SUN", "SunJCE", "SunRsaSign", "SunEC"};
    assertArrayEquals(
        "Expected providers not present and/or not in order",
        getProviders().toArray(),
        expectedProviders);
  }
}
