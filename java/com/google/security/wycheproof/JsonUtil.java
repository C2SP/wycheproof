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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.math.BigInteger;

/** Utilities for reading test vectors in JSON format */
public class JsonUtil {

  /**
   * Reads a set of test vectors from a file.
   * @param filename the name of the file, local to the directory with the
   *        the test vectors.
   * @return a JsonObject with a test
   * @throws IOException if the test vectors could not be read.
   * @throws JsonParseException if the file is not valid JSON.
   */
  public static JsonObject getTestVectors(String filename) throws 
      IOException {
    // The directory where the test vectors are.
    String testVectorsDir = "testvectors/";
    FileInputStream is = new FileInputStream(testVectorsDir + filename);
    JsonReader reader = new JsonReader(new InputStreamReader(is, UTF_8));
    JsonParser parser = new JsonParser();
    JsonElement elem = parser.parse(reader);
    return elem.getAsJsonObject();
  }

  /** 
   * Converts a JsonElement into a byte array.
   * @param element a JsonElement containing an encoded byte array. 
   *        Wycheproof represents byte arrays as hexadeciamal strings.
   * @throws ClassCastException if element is not a valid string value.
   * @throws IllegalStateException - if element contains an array.
   */
  public static byte[] asByteArray(JsonElement element) {
    String hex = element.getAsString();
    return TestUtil.hexToBytes(hex);
  }

  /**
   * Converts a JsonElement into a BigInteger.
   * @param element a JsonElement containing a BigInteger. 
   * Wycheproof represents BigIntegers as hexadecimal strings using
   * twos complement representation.
   * <p> E.g., 31 is represented as "1f", -1 is represented as "f", and
   * 255 is represented as "0ff".
   * @throws ClassCastException if element is not a valid string value.
   * @throws IllegalStateException if element contains an array.
   * @throws NumberFormatException if representation of the BigInteger is invalid.
   */ 
  public static BigInteger asBigInteger(JsonElement element) {
    String hex = element.getAsString();
    // TODO(bleichen): Consider to change the representation of BigIntegers in
    //   Wycheproof as hexadecimal string with a sign.
    if (hex.length() % 2 == 1) {
      if (hex.charAt(0) >= '0' && hex.charAt(0) <= '7') {
        hex = "0" + hex;
      } else {
        hex = "f" + hex;
      }
    }
    return new BigInteger(TestUtil.hexToBytes(hex));
  }
}
