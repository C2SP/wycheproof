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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test BigInteger class.
 *
 * <p>This unit tests focuses on checking security relevant properties.
 */
@RunWith(JUnit4.class)
public class BigIntegerTest {

  /** Convenience method to get a BigInteger from a JsonObject */
  protected static BigInteger getBigInteger(JsonObject object, String name) throws Exception {
    return JsonUtil.asBigInteger(object.get(name));
  }

  /** Convenience method to get a byte array from a JsonObject */
  protected static byte[] getBytes(JsonObject object, String name) throws Exception {
    return JsonUtil.asByteArray(object.get(name));
  }

  @Test
  public void testIsProbablePrimeVectors() throws Exception {
    String filename = "primality_test.json";
    JsonObject test = JsonUtil.getTestVectors(filename);
    int errors = 0;
    int passedTests = 0;
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        int tcid = testcase.get("tcId").getAsInt();
        String tc = "tcId: " + tcid + " " + testcase.get("comment").getAsString();
        BigInteger value = getBigInteger(testcase, "value");
        // result is "valid" if the tested integer is prime, "invalid" if it is
        // composite or -1, 0, 1 and it is "acceptable" if it is the negative of
        // prime. BigInteger.isProbablyPrime() accepts the later as prime (as do
        // a number of other primality tests). Such a behaviour may be a pitfall
        // for cryptographic protocols. However, it can not be flagged as error. 
        String result = testcase.get("result").getAsString();

        // The probability that a non-prime passes should be at most 1-2^{-certainty}.
        int certainty = 80;
        boolean isProbablePrime = value.isProbablePrime(certainty);
        if (result.equals("invalid") && isProbablePrime) {
          System.out.println("Composite number passed as prime:" + tc);
          errors++;
        } else if (result.equals("valid") && !isProbablePrime) {
          System.out.println("Prime failed primality test:" + tc);
          errors++;
        } else {
          passedTests++;
        }
      }
    }
    assertEquals(0, errors);
    System.out.println("Passed primality tests:" + passedTests);
  }
}
