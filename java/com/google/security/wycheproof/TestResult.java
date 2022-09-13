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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

class TestResult {
  /**
   * A type describing the result of a single test.
   *
   * <p>Some of the motivations for returning test results with a more detailed value than just
   * pass/fail are as follows:
   *
   * <p>The seriousness of a failure depends on the type of the failure. E.g., if an ECDH exchange
   * returns an incorrect result (WRONG_RESULT) then it is very plausible that an invalid curve
   * attack is possible, which leaks the private key. If it throws an unchecked exception
   * (WRONG_EXCEPTION) then this may in some cases lead to a denial of service attack.
   *
   * <p>If none of the valid test vectors in a file passes (i.e. returns PASSED_VALID, then it is
   * likely that the cryptographic primitive is not or not properly supported by the library. In
   * such situations we may mark the test as skipped.
   *
   * <p>Java provider are not consistent with algorithm names. Often the same cryptographic
   * primitive has multiple distinct algorithm names among distinct providers. Provider may treat
   * algorithm parameters differently or not support them. Hence it is helpful to determine if a
   * test vector was rejected because the cryptographic primitive could not be instantiated or if an
   * error occurred while evaluating the primitive.
   */
  public enum Type {
    // A valid test vector was verified.
    PASSED_VALID,
    // An invalid test vector with malformed input passed the
    // test with the expected result as a valid well-formed input.
    // A main example where this type is used is ECDH. If the ephemeral public key is
    // malformed but the compuation behaves like an equivalent correct public key then this
    // is less severe than if the result is wrong. In the later case an invalid curve attack
    // is likely.
    PASSED_MALFORMED,
    // A test vector with legacy behaviour was verified.
    PASSED_LEGACY,
    // A valid test vector was rejected.
    REJECTED_VALID,
    // An invalid test vector was correctly rejected.
    REJECTED_INVALID,
    // An invalid test vector was not rejected.
    NOT_REJECTED_INVALID,
    // The algorithm was rejected. This includes keys with unsupported
    // parameters (e.g. unknown curves, small key sizes etc.)
    // An invalid test vector incorrectly passed.
    REJECTED_ALGORITHM,
    // The test vector was skipped by the test.
    SKIPPED,
    // A valid test vector returned the wrong result.
    WRONG_RESULT,
    // A test vector threw an incorrect exception.
    // Throwing unchecked exceptions instead of checked exceptions such as
    // GeneralSecurityException is a bug and can lead to
    WRONG_EXCEPTION,
    // Something is wrong with the test itself.
    // Examples are unknown files, unsupported algorithms, missing files or
    // files with incorrect format.
    WRONG_SETUP,
    // Test vectors that should have indistinguishable behavior are
    // distinguishable,
    DISTINGUISHABLE,
  };

  // The source of the test result.
  private final TestVectors testVectors;
  // The type of the test result of a test vector.
  private final Map<Integer, Type> result;
  // Comments for each test vector
  private final Map<Integer, String> comment;
  // A count of the bug types
  private final Map<Type, Integer> count;
  // Failures not assigned to individual test vectors.
  private final Set<String> failures;
  // The number of performed tests.
  private int numTests;

  public TestResult(TestVectors testVectors) {
    this.testVectors = testVectors;
    result = new TreeMap<>();
    comment = new TreeMap<>();
    count = new HashMap<>();
    failures = new TreeSet<>();
    numTests = 0;
  }

  /**
   * Adds a failure that was not caused by a specific test vector.
   *
   * @param type the type of the bug. Typical values are REJECTED_ALGORITHM or WRONG_SETUP.
   * @param reason a description of the failure.
   */
  public void addFailure(Type type, String reason) {
    count.put(type, count.getOrDefault(type, 0) + 1);
    failures.add(reason);
  }

  /**
   * Adds a test result.
   *
   * @param tcId the identifier of the test vector.
   * @param type the type of the result
   * @param reason an additional comment that explains the result. A typical case is an exception.
   */
  public void addResult(int tcId, Type type, String reason) {
    numTests++;
    result.put(tcId, type);
    comment.put(tcId, reason);
    count.put(type, count.getOrDefault(type, 0) + 1);
  }

  /**
   * Counts the label for a given set of tcIds.
   *
   * @param tcIds a set of tcIds
   * @return a string containing the count.
   */
  public String countLabels(Set<Integer> tcIds) {
    Map<String, Integer> labels = new HashMap<>();
    for (int tcId : tcIds) {
      for (var label : testVectors.get(tcId).getAsJsonArray("flags")) {
        String flag = label.getAsString();
        labels.put(flag, labels.getOrDefault(flag, 0) + 1);
      }
    }
    var result = new StringBuilder();
    for (var count : labels.entrySet()) {
      result.append(count.getKey());
      result.append(":");
      result.append(count.getValue());
      result.append("\n");
    }
    return result.toString();
  }

  /**
   * Returns the number of performed tests. The count includes only test vector that were tested. It
   * excluded test vectors that were skipped, e.g., because the key could not be constructed.
   *
   * @return the number of performed tests
   */
  public int performedTests() {
    return numTests;
  }

  /**
   * Returns the count for a specific TestResult.Type.
   *
   * @param type the for which the count is returned.
   * @return the number of tests that had the type as result.
   */
  public int getCount(Type type) {
    return count.getOrDefault(type, 0);
  }

  /**
   * Returns the tcIds of the test vectors considered failed.
   *
   * <p>This set includes valid test vectors that failed under the assumption that at least some
   * other valid test vectors passed. If no valid test vectors passed the method assumes that the
   * primitive is not supported. A provider should behave properly even if a primitive is not
   * supported. If exceptions are thrown this should be check exceptions and not RunTimeExceptions,
   * since otherwise an attacker could try a denial of service attacks with unsupported primitives.
   *
   * @return a set of identifiers of failed test vectors.
   */
  public Set<Integer> failedTcIds() {
    Set<Integer> failed = new TreeSet<>();
    boolean hasValid = getCount(Type.PASSED_VALID) > 0;
    for (var entry : result.entrySet()) {
      switch (entry.getValue()) {
        case PASSED_VALID:
        case PASSED_LEGACY:
        case REJECTED_INVALID:
          break;
        case REJECTED_VALID:
          if (hasValid) {
            failed.add(entry.getKey());
          }
          break;
        case NOT_REJECTED_INVALID:
        case WRONG_RESULT:
        case WRONG_EXCEPTION:
        case PASSED_MALFORMED:
        case DISTINGUISHABLE:
          failed.add(entry.getKey());
          break;
        case SKIPPED:
        case WRONG_SETUP:
        case REJECTED_ALGORITHM:
          // The test was not performed.
          break;
      }
    }
    return failed;
  }

  /**
   * Returns the set of failing test vectors.
   */
  public TestVectors failingTests() {
    return testVectors.subSet(failedTcIds());
  }

  /**
   * Returns the number of errors.
   *
   * <p>This is the same as failedTcIds().size()
   *
   * @return the number of errors.
   */
  public int errors() {
    boolean hasValid = getCount(Type.PASSED_VALID) > 0;
    int countFailed = 0;
    if (hasValid) {
      countFailed += getCount(Type.REJECTED_VALID);
    }
    countFailed += getCount(Type.NOT_REJECTED_INVALID);
    countFailed += getCount(Type.WRONG_RESULT);
    countFailed += getCount(Type.WRONG_EXCEPTION);
    countFailed += getCount(Type.PASSED_MALFORMED);
    countFailed += getCount(Type.DISTINGUISHABLE);
    return countFailed;
  }

  /**
   * Returns True if there are no valid test results. The conclusion is that the algorithm is not
   * supported. Hence we probably should skip the test.
   *
   * @return True if the test should be skipped.
   */
  public boolean skipTest() {
    return (getCount(Type.PASSED_VALID) == 0 && errors() == 0);
  }

  public void checkIndistinguishableResult(String flag) {
    Set<Type> results = new TreeSet<Type>();
    Set<String> comments = new TreeSet<String>();
    for (int tcId : testVectors.withFlag(flag)) {
      results.add(result.get(tcId));
      comments.add(comment.get(tcId));
    }
    if (results.size() > 1 || comments.size() > 1) {
      for (int tcId : testVectors.withFlag(flag)) {
        // This line overrides previous test results.
        // This is done because distinguishable paddings are likely more
        // important that other errors.
        addResult(tcId, Type.DISTINGUISHABLE, comment.get(tcId));
      }
    }
  }

  /**
   * Converts the test result into a readable string.
   *
   * <p>This function is likely going to change a lot depending on actual use cases.
   *
   * <p>A typical example might look like this (but keep in mind that we have not worked on the
   * formatting yet and will improve this).
   *
   * <pre>
   * === Name : ecdsa_secp224r1_sha224_p1363_test.json ===
   * Performed tests: 203
   * valid test vectors: 131
   * PASSED_VALID:126
   * PASSED_INVALID:1
   * REJECTED_VALID:5
   * REJECTED_INVALID:71
   * Total number of failed tests: 6
   *  92: ; small r and s; EDGE_CASE
   *  94: ; small r and s; EDGE_CASE
   *  97: ; incorrect size of signature; SIGNATURE_MALLEABILITY EDGE_CASE
   * File : ecdsa_secp224r1_sha224_p1363_test.json
   * tcId : 97
   * test result: PASSED_INVALID
   * comment:
   * {
   *   "tcId": 97,
   *   "comment": "incorrect size of signature",
   *   "flags": [
   *     "SmallRandS",
   *     "ArithmeticError",
   *     "SignatureSize"
   *   ],
   *   "msg": "313233343030",
   *   "sig": "0304",
   *   "result": "invalid"
   * }
   * {
   *   "bugType": "EDGE_CASE",
   *   "description": "The test vectors contains a signature where both r and s are small ...",
   *   "effect": "While the signature in this test vector is constructed and similar ...",
   *   "cves": [
   *     "2020-13895"
   *   ]
   * }
   * {
   *   "bugType": "EDGE_CASE",
   *   "description": "Some implementations of ECDSA have arithmetic errors that occur ...",
   *   "cves": [
   *     "CVE-2017-18146"
   *   ]
   * }
   * {
   *   "bugType": "SIGNATURE_MALLEABILITY",
   *   "description": "The size of an IEEE P1363 encoded signature should always be ..."
   * }
   *  100: ; small r and s^-1; EDGE_CASE
   *  101: ; smallish r and s^-1; EDGE_CASE
   *  103: ; small r and 100 bit s^-1; EDGE_CASE
   * SmallRandS:3
   * ArithmeticError:6
   * SignatureSize:1
   * </pre>
   *
   * In this case there are 6 failed tests. In one case an incorrectly formatted signature is
   * accepted leading to problems in applications where signature malleability is a issue. 5 valid
   * edge case signatures are rejected. Edge case signatures are constructed signatures. Often an
   * analysis of the underlying cause is necessary to determine the severity of such failures.
   *
   * @return a printable string that summarizes the test result.
   */
  public String asString() {
    var out = new StringBuilder();
    out.append("\n=== Name : ").append(testVectors.getName()).append(" ===\n");
    out.append("Performed tests: ").append(performedTests()).append("\n");
    out.append("valid test vectors: ").append(testVectors.numValid()).append("\n");
    for (Type type : Type.values()) {
      int cnt = getCount(type);
      if (cnt > 0) {
        out.append(type.name()).append(":").append(cnt).append("\n");
      }
    }
    out.append("Total number of failed tests: ").append(errors()).append("\n");
    Set<Integer> failed = failedTcIds();
    if (!failed.isEmpty()) {
      out.append("--- Possible explanations (by labels) ---\n");
      out.append(countLabels(failed));
      out.append("--- Failing tests ---\n");
      for (int tcId : failed) {
        out.append(" ").append(tcId);
        out.append(" ").append(result.get(tcId).name());
        JsonObject testCase = testVectors.get(tcId);
        out.append(": ").append(comment.get(tcId)).append("; ");
        out.append(testCase.get("comment").getAsString()).append(";");
        for (String flag : testVectors.getFlags(tcId)) {
          out.append(" ").append(flag);
        }
        out.append("\n");
      }

      // Print test test failing test vectors, but only when there are not
      // too many.
      if (failed.size() <= 10) {
        out.append("--- Failing test vectors ---\n");
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        out.append(gson.toJson(failingTests().getTest()));
        out.append("\n");
      }
    }
    return out.toString();
  }

  /**
   * Returns the test result for a tcId.
   *
   * @param tcId the id of the test vector
   * @return a printable string that describes the test result for a given test vector.
   */
  public String getResult(int tcId) {
    var out = new StringBuilder();
    out.append("File : ").append(testVectors.getName()).append("\n");
    out.append("tcId : ").append(tcId).append("\n");
    if (!result.containsKey(tcId)) {
      out.append("Test vector was not tested");
    } else {
      Gson gson = new GsonBuilder().setPrettyPrinting().create();
      out.append("test result: ").append(result.get(tcId)).append("\n");
      out.append("comment: ").append(comment.get(tcId)).append("\n");
      JsonObject testCase = testVectors.get(tcId);
      String jsonOutput = gson.toJson(testCase);
      int maxSize = 2048;
      if (jsonOutput.length() > maxSize) {
        jsonOutput = jsonOutput.substring(0, maxSize) + " ...";
      }
      out.append(jsonOutput).append("\n");
      for (String flag : testVectors.getFlags(tcId)) {
        JsonObject note = testVectors.getNote(flag);
        out.append(gson.toJson(note)).append("\n");
      }
    }
    return out.toString();
  }
}
