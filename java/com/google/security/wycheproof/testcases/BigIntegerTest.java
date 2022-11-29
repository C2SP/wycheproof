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

  private static void singleTest(JsonObject testcase, TestResult testResult) {
    int tcid = testcase.get("tcId").getAsInt();
    BigInteger value = JsonUtil.asBigInteger(testcase.get("value"));
    // result is "valid" if the tested integer is prime, "invalid" if it is
    // composite or -1, 0, 1 and it is "acceptable" if it is the negative of
    // prime. BigInteger.isProbablyPrime() accepts the later as prime (as do
    // a number of other primality tests). Such a behaviour may be a pitfall
    // for cryptographic protocols. However, it can not be flagged as error.
    String result = testcase.get("result").getAsString();

    // The probability that a non-prime passes should be at most 1-2^{-certainty}.
    int certainty = 80;
    boolean isProbablePrime;
    try {
      isProbablePrime = value.isProbablePrime(certainty);
    } catch (RuntimeException ex) {
      testResult.addResult(tcid, TestResult.Type.WRONG_EXCEPTION, ex.toString());
      return;
    }
    if (result.equals("invalid") && isProbablePrime) {
      testResult.addResult(tcid, TestResult.Type.WRONG_RESULT, "Composite number passed as prime.");
    } else if (result.equals("valid") && !isProbablePrime) {
      testResult.addResult(tcid, TestResult.Type.WRONG_RESULT, "Prime failed primality test.");
    } else {
      testResult.addResult(tcid, TestResult.Type.PASSED_VALID, "");
    }
  }

  public static TestResult probablePrimeTest(TestVectors testVectors) {
    var testResult = new TestResult(testVectors);
    JsonObject test = testVectors.getTest();
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      for (JsonElement t : group.getAsJsonArray("tests")) {
        singleTest(t.getAsJsonObject(), testResult);
      }
    }
    return testResult;
  }

  @Test
  public void testIsProbablePrimeVectors() throws Exception {
    String filename = "primality_test.json";
    JsonObject test = JsonUtil.getTestVectorsV1(filename);
    TestVectors testVectors = new TestVectors(test, filename);
    TestResult testResult = probablePrimeTest(testVectors);
    System.out.print(testResult.asString());
    assertEquals(0, testResult.errors());
  }
}
