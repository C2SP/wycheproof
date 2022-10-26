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

import java.security.Provider;
import java.security.Security;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Not a true test: reports information about the provider. */
@RunWith(JUnit4.class)
public class BasicTest {

  /**
   * List all algorithms known to the security manager.
   *
   * <p>Some links for additional information about providers are:
   * https://docs.oracle.com/en/java/javase/19/security/oracle-providers.html
   * https://github.com/google/conscrypt/blob/master/CAPABILITIES.md
   * https://www.bouncycastle.org/specifications.html
   */
  @Test
  public void testListAllAlgorithms() {
    for (Provider p : Security.getProviders()) {
      System.out.println();
      System.out.println("Provider: " + p.getName() + " " + p.getVersion());
      // Using a TreeSet here, because the elements are sorted.
      TreeSet<String> list = new TreeSet<String>();
      for (var entry : p.entrySet()) {
        String algorithm = (String) entry.getKey();
        Object value = entry.getValue();
        if (algorithm.startsWith("Alg.Alias")
            || algorithm.endsWith("ImplementedIn")
            || algorithm.endsWith("SupportedKeyClasses")) {
          continue;
        }
        if (algorithm.contains(" ")) {
          list.add(algorithm + " : " + value);
        } else {
          list.add(algorithm);
        }
      }
      for (String algorithm : list) {
        System.out.println(algorithm);
      }
    }
  }
}
