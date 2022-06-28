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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * TestVectors is a wrapper around a JSON file with test vectors.
 *
 * <p>The test vectors share some information about themselves to save some space. A test vector
 * file is divided into a number of test groups, where each test group contains for example the keys
 * shared among all the test vectors in the group. The notes in the header of the file contains a
 * list of bug descriptions.
 *
 * <p>A main goal of this class is to allow easy access to all information for a given test vector
 * identified by a tcId. This allows to call tests individually.
 */
class TestVectors {
  // The JSON object that is wrapped.
  private final JsonObject test;
  // The name of the test vectors. The name is typically the name of the file
  // containing the test vectors.
  private final String name;
  // A lookup table for the test cases indexed by the tcId.
  private final Map<Integer, JsonObject> testcases;
  // A lookup map for the notes. Each test vector has a list of flags, where
  // a flag refers to notes[flag].
  private final Map<String, JsonObject> notes;
  // The group to which a test vector belongs. The group of a test vector
  // contains information shared with all test vectors from the same group.
  // For example keys are often shared.
  private final HashMap<Integer, JsonObject> groups;
  // A set of BugTypes that are considered to be legacy bugs. Sometimes a
  // crypto library intentially accepts some invalid input because of legacy
  // bugs. For example a library may accept some slightly invalid ASN
  // encodings. Test vectors with these bug types are considered acceptable.
  // All the bug types in this set must be benign. They also have to be
  // dominant, in the sense that they overrule other bug types.
  // Currently this set contains just the bug type "LEGACY".
  private final Set<String> legacyBugTypes;
  // The number of valid test vectors in the file.
  private int cntValid;
  // The number of invalid test vectors in the file.
  private int cntInvalid;

  public TestVectors(JsonObject test, String name) {
    this.test = test;
    this.name = name;
    testcases = new HashMap<>();
    groups = new HashMap<>();
    notes = new HashMap<>();
    legacyBugTypes = new HashSet<>();
    legacyBugTypes.add("LEGACY");
    cntValid = 0;
    cntInvalid = 0;
    JsonObject n = test.getAsJsonObject("notes");
    for (var entry : n.entrySet()) {
      JsonElement value = entry.getValue();
      JsonObject val = value.getAsJsonObject();
      notes.put(entry.getKey(), val);
    }

    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      for (JsonElement t : group.getAsJsonArray("tests")) {
        JsonObject testcase = t.getAsJsonObject();
        int tcId = testcase.get("tcId").getAsInt();
        testcases.put(tcId, testcase);
        groups.put(tcId, group);
        String result = testcase.get("result").getAsString();
        if (result.equals("valid")) {
          cntValid++;
        } else if (result.equals("invalid")) {
          cntInvalid++;
        }
      }
    }
  }

  /**
   * Returns the name of the test vectors. This is normally the name of the file containing the test
   * vectors.
   */
  String getName() {
    return name;
  }

  /** Returns the JSON Schema of the test vectors. */
  String getSchema() {
    return test.get("schema").getAsString();
  }

  /** Returns the number of tests in the file. */
  int numTests() {
    return test.get("numberOfTests").getAsInt();
  }

  /** Returns the number of valid test vectors in the file. */
  int numValid() {
    return cntValid;
  }

  /** Returns the number of invalid test vectors in the file. */
  int numInvalid() {
    return cntInvalid;
  }

  /** Returns the whole test */
  JsonObject getTest() {
    return test;
  }

  /** Returns the test vector with given tcId */
  JsonObject get(int tcId) {
    return testcases.get(tcId);
  }

  /** Returns the group containing the test vector with the given tcId. */
  JsonObject getGroup(int tcId) {
    return groups.get(tcId);
  }

  /** Returns a set of flags belonging to the test vector with given tcId. */
  Set<String> getFlags(int tcId) {
    Set<String> flags = new HashSet<>();
    for (var flag : get(tcId).getAsJsonArray("flags")) {
      flags.add(flag.getAsString());
    }
    return flags;
  }

  /**
   * Returns a JsonObject that describes a flag.
   *
   * <p>The JsonObject may contain a number of fields:
   *
   * <ul>
   *   <li>"bugType": the type of the bug
   *   <li>"description": a description of the bug
   *   <li>"effect": a description of the effect fo the bug
   *   <li>"links": a list of additional links describing the bug
   *   <li>"cves": a list of CVEs with similar bugs
   * </ul>
   *
   * @param flag the flag
   * @return the JsonObject
   */
  JsonObject getNote(String flag) {
    return notes.get(flag);
  }

  /** Returns a set of bugType associated with a given tcId. */
  Set<String> getBugTypes(int tcId) {
    Set<String> bugTypes = new HashSet<>();
    for (String flag : getFlags(tcId)) {
      JsonObject note = notes.get(flag);
      String bugType = note.get("bugType").getAsString();
      bugTypes.add(bugType);
    }
    return bugTypes;
  }

  /**
   * Returns True if tcId contains a legacy case.
   *
   * <p>A legacy case is a test vector containing some invalid input that may be accepted
   * nonetheless to support legacy behaviour. An example for such a legacy case are RSA PKCS#1
   * signatures where the encoding of the algorithm misses the NULL parameter. A number of libraries
   * accept such RSA signatures.
   *
   * <p>If a library accepts such legacy test cases, then this typically should not be flagged as an
   * error.
   *
   * @return True if one of the flags of the bug is marked as a legacy test case.
   */
  boolean isLegacy(int tcId) {
    for (var bugType : getBugTypes(tcId)) {
      if (legacyBugTypes.contains(bugType)) {
        return true;
      }
    }
    return false;
  }
}
