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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import com.google.security.wycheproof.WycheproofRunner.SlowTest;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests ECDSA against invalid signatures.
 *
 * @author bleichen@google.com (Daniel Bleichenbacher)
 */
// Tested providers:
//   SunEC: accepts a few alternative encodings and throws run time exceptions.
//     The implementation does not protect against timing attacks.
//   BC: accepts alternative encoding, and additional arguments
//   AndroidOpenSSL: OK
// TODO(bleichen):
//   - CVE-2015-2730: Firefox failed to handle some signatures correctly because of incorrect
//     point multiplication. (I don't have enough information here.)
@RunWith(JUnit4.class)
public class EcdsaTest {
  // ECDSA-Key1
  static final String MESSAGE = "Hello";
  static final String CURVE = "secp256r1";
  static final BigInteger PubX =
      new BigInteger(
          "33903964965861532023650245008903090201819051686264021958530366090984128098564");
  static final BigInteger PubY =
      new BigInteger(
          "113542129898393725739068316260085522189065290079050903091108740065052129055287");

  // Valid signatures for MESSAGE
  static final String[] VALID_SIGNATURES = {
    "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
  };

  /**
   * The following test vectors contain a valid signature that use alternative BER encoding. Whether
   * such signatures are accepted as valid or rejected depends on the implementation. Allowing
   * alternative BER encodings is in many cases benign. However, there are cases where this kind of
   * signature malleability was a problem. See for example
   * https://en.bitcoin.it/wiki/Transaction_Malleability
   */
  // NOTE(bleichen): The following test vectors were generated with some python code.
  //   New test vectors should best be done by extending this code. Some of the signatures
  //   can be moved to INVALID_SIGNATURES, when b/31572415 is fixed.
  static final String[] MODIFIED_SIGNATURES = {
    // BER:long form encoding of length
    "308145022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d"
        + "491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e762"
        + "85cd59f43260ecce",
    "304602812100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d"
        + "491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e762"
        + "85cd59f43260ecce",
    "3046022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f028120747291dd2f3f44af7ace68ea33431d6f94e418c106a6e762"
        + "85cd59f43260ecce",
    // BER:length contains leading 0
    "30820045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a"
        + "3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e7"
        + "6285cd59f43260ecce",
    "30470282002100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a"
        + "3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e7"
        + "6285cd59f43260ecce",
    "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f02820020747291dd2f3f44af7ace68ea33431d6f94e418c106a6e7"
        + "6285cd59f43260ecce",
    // BER:prepending 0's to integer
    "30470223000000b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a"
        + "3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e7"
        + "6285cd59f43260ecce",
    "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f02220000747291dd2f3f44af7ace68ea33431d6f94e418c106a6e7"
        + "6285cd59f43260ecce",
    // NOTE (bleichen): belongs into INVALID_SIGNATURES. We only keep these
    //  sigantures here because of b/31572415.
    // length = 2**31 - 1
    "30847fffffff022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7"
        + "db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106"
        + "a6e76285cd59f43260ecce",
    "304902847fffffff00b7babae9332b54b8a3a05b7004579821a887a1b21465f7"
        + "db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106"
        + "a6e76285cd59f43260ecce",
    "3049022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f02847fffffff747291dd2f3f44af7ace68ea33431d6f94e418c106"
        + "a6e76285cd59f43260ecce",
  };

  /**
   * Test vectors with invalid signatures. The motivation for these test vectors are previously
   * broken implementations. E.g.
   *
   * <ul>
   *   <li>The implementation of DSA in gpg4browsers accepted signatures with r=1 and s=q as valid.
   *       Similar bugs in ECDSA are thinkable, hence the test vectors contain a number of tests
   *       with edge case integers.
   *   <li>CVE-2013-2944: strongSwan 5.0.4 accepts invalid ECDSA signatures when openssl is used.
   *       (Not sure if the following interpretation is correct, because of missing details).
   *       OpenSSLs error codes are easy to misinterpret. For many functions the result can be 0
   *       (verification failed), 1 (verification succeded) or -1 (invalid format). A simple <code>
   *       if (result) { ... }</code> will be incorrect in such situations. The test vectors below
   *       contain incorrectly encoded signatures.
   * </ul>
   *
   * <p>{@link java.security.Signature#verify(byte[])} should either return false or throw a
   * SignatureException. Other behaviour such as throwing a RuntimeException might allow a denial of
   * service attack:
   *
   * <ul>
   *   <li>CVE-2016-5546: OpenJDK8 throwed an OutOfmemoryError on some signatures.
   * </ul>
   *
   * Some of the test vectors were derived from a valid signature by corrupting the DER encoding. If
   * providers accepts such modified signatures for legacy purpose, then these signatures should be
   * moved to MODIFIED_SIGNATURES.
   */
  // NOTE(bleichen): The following test vectors were generated with some python code. New test
  // vectors should best be done by extending the python code.
  static final String[] INVALID_SIGNATURES = {
    // wrong length
    "3046022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3044022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3045022200b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3045022000b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0221747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f021f747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    // uint32 overflow in length
    "30850100000045022100b7babae9332b54b8a3a05b7004579821a887a1b21465"
        + "f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c1"
        + "06a6e76285cd59f43260ecce",
    "304a0285010000002100b7babae9332b54b8a3a05b7004579821a887a1b21465"
        + "f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c1"
        + "06a6e76285cd59f43260ecce",
    "304a022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f02850100000020747291dd2f3f44af7ace68ea33431d6f94e418c1"
        + "06a6e76285cd59f43260ecce",
    // uint64 overflow in length
    "3089010000000000000045022100b7babae9332b54b8a3a05b7004579821a887"
        + "a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f"
        + "94e418c106a6e76285cd59f43260ecce",
    "304e028901000000000000002100b7babae9332b54b8a3a05b7004579821a887"
        + "a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f"
        + "94e418c106a6e76285cd59f43260ecce",
    "304e022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0289010000000000000020747291dd2f3f44af7ace68ea33431d6f"
        + "94e418c106a6e76285cd59f43260ecce",
    // length = 2**32 - 1
    "3084ffffffff022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7"
        + "db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106"
        + "a6e76285cd59f43260ecce",
    "30490284ffffffff00b7babae9332b54b8a3a05b7004579821a887a1b21465f7"
        + "db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106"
        + "a6e76285cd59f43260ecce",
    "3049022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0284ffffffff747291dd2f3f44af7ace68ea33431d6f94e418c106"
        + "a6e76285cd59f43260ecce",
    // length = 2**64 - 1
    "3088ffffffffffffffff022100b7babae9332b54b8a3a05b7004579821a887a1"
        + "b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94"
        + "e418c106a6e76285cd59f43260ecce",
    "304d0288ffffffffffffffff00b7babae9332b54b8a3a05b7004579821a887a1"
        + "b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94"
        + "e418c106a6e76285cd59f43260ecce",
    "304d022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0288ffffffffffffffff747291dd2f3f44af7ace68ea33431d6f94"
        + "e418c106a6e76285cd59f43260ecce",
    // removing sequence
    "",
    // appending 0's to sequence
    "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce0000",
    // prepending 0's to sequence
    "30470000022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a"
        + "3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e7"
        + "6285cd59f43260ecce",
    // appending unused 0's
    "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce0000",
    "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f00000220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e7"
        + "6285cd59f43260ecce",
    // appending null value
    "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce0500",
    "3047022300b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f05000220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e7"
        + "6285cd59f43260ecce",
    "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0222747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce0500",
    // including garbage
    "304949803045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7"
        + "db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106"
        + "a6e76285cd59f43260ecce",
    "304925003045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7"
        + "db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106"
        + "a6e76285cd59f43260ecce",
    "30473045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a"
        + "3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e7"
        + "6285cd59f43260ecce0004deadbeef",
    "304922254980022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7"
        + "db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106"
        + "a6e76285cd59f43260ecce",
    "304922252500022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7"
        + "db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106"
        + "a6e76285cd59f43260ecce",
    "304d2223022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a"
        + "3d491b39fd2c3f0004deadbeef0220747291dd2f3f44af7ace68ea33431d6f94"
        + "e418c106a6e76285cd59f43260ecce",
    "3049022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f222449800220747291dd2f3f44af7ace68ea33431d6f94e418c106"
        + "a6e76285cd59f43260ecce",
    "3049022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f222425000220747291dd2f3f44af7ace68ea33431d6f94e418c106"
        + "a6e76285cd59f43260ecce",
    "304d022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f22220220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e7"
        + "6285cd59f43260ecce0004deadbeef",
    // including undefined tags
    "304daa00bb00cd003045022100b7babae9332b54b8a3a05b7004579821a887a1"
        + "b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94"
        + "e418c106a6e76285cd59f43260ecce",
    "304baa02aabb3045022100b7babae9332b54b8a3a05b7004579821a887a1b214"
        + "65f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418"
        + "c106a6e76285cd59f43260ecce",
    "304d2229aa00bb00cd00022100b7babae9332b54b8a3a05b7004579821a887a1"
        + "b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94"
        + "e418c106a6e76285cd59f43260ecce",
    "304b2227aa02aabb022100b7babae9332b54b8a3a05b7004579821a887a1b214"
        + "65f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418"
        + "c106a6e76285cd59f43260ecce",
    "304d022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f2228aa00bb00cd000220747291dd2f3f44af7ace68ea33431d6f94"
        + "e418c106a6e76285cd59f43260ecce",
    "304b022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f2226aa02aabb0220747291dd2f3f44af7ace68ea33431d6f94e418"
        + "c106a6e76285cd59f43260ecce",
    // changing tag value
    "2e45022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3245022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "ff45022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3045002100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3045042100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3045ff2100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0020747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0420747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3fff20747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    // dropping value of sequence
    "3000",
    // using composition
    "304930010230442100b7babae9332b54b8a3a05b7004579821a887a1b21465f7"
        + "db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106"
        + "a6e76285cd59f43260ecce",
    "304922250201000220b7babae9332b54b8a3a05b7004579821a887a1b21465f7"
        + "db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106"
        + "a6e76285cd59f43260ecce",
    "3049022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f2224020174021f7291dd2f3f44af7ace68ea33431d6f94e418c106"
        + "a6e76285cd59f43260ecce",
    // truncate sequence
    "3044022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ec",
    "30442100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b"
        + "39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd"
        + "59f43260ecce",
    // prepend empty sequence
    "30473000022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a"
        + "3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e7"
        + "6285cd59f43260ecce",
    // append empty sequence
    "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce3000",
    // sequence of sequence
    "30473045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a"
        + "3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e7"
        + "6285cd59f43260ecce",
    // truncated sequence
    "3023022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f",
    // repeat element in sequence
    "3067022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e7"
        + "6285cd59f43260ecce",
    // removing integer
    "30220220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
    // appending 0's to integer
    "3047022300b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f00000220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e7"
        + "6285cd59f43260ecce",
    "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0222747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce0000",
    // dropping value of integer
    "302402000220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
    "3025022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0200",
    // modify first byte of integer
    "3045022101b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220757291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    // modify last byte of integer
    "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3e0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260eccf",
    // truncate integer
    "3044022000b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd"
        + "59f43260ecce",
    "30440220b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b"
        + "39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd"
        + "59f43260ecce",
    "3044022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f021f747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ec",
    "3044022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f021f7291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd"
        + "59f43260ecce",
    // leading ff in integer
    "30460222ff00b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d"
        + "491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e762"
        + "85cd59f43260ecce",
    "3046022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f0221ff747291dd2f3f44af7ace68ea33431d6f94e418c106a6e762"
        + "85cd59f43260ecce",
    // infinity
    "30250901800220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
    "3026022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f090180",
    // Vectors where r or s have been modified e.g. by adding or subtracting the order of the
    // group or field and hence violate the range check for r and s required by ECDSA.
    "30450221ff48454516ccd4ab475c5fa48ffba867de57785e4deb9a082475c2b6"
        + "e4c602d3c10220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3045022101b7babae8332b54b9a3a05b7004579821656e9c5fbb7d96607df713"
        + "de366051900220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3044022048454515ccd4ab485c5fa48ffba867de145f58fb92b1a6a9697c81a7"
        + "c265f9120220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd"
        + "59f43260ecce",
    "3045022101b7babae8332b54b9a3a05b7004579821a887a1b31465f7db8a3d49"
        + "1b39fd2c3e0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
        + "cd59f43260ecce",
    "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f02208b8d6e22d0c0bb5085319715ccbce2906b1be73ef959189d7a"
        + "32a60bcd9f1332",
    "3046022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f022101747291dc2f3f44b07ace68ea33431d6f51cb136eadbe85e7"
        + "798724b72ec4121f",
    "3046022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
        + "1b39fd2c3f022101747291dc2f3f44b07ace68ea33431d6f94e418c206a6e762"
        + "85cd59f43260eccd",
    // Signatures with special case values for r and s (such as 0 and 1). Such values often
    // uncover implementation errors.
    "3006020100020100",
    "3006020100020101",
    "30060201000201ff",
    "3026020100022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "3026020100022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    "3026020100022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    "3026020100022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "3026020100022100ffffffff00000001000000000000000000000001000000000000000000000000",
    "3008020100090380fe01",
    "3006020101020100",
    "3006020101020101",
    "30060201010201ff",
    "3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    "3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    "3026020101022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "3026020101022100ffffffff00000001000000000000000000000001000000000000000000000000",
    "3008020101090380fe01",
    "30060201ff020100",
    "30060201ff020101",
    "30060201ff0201ff",
    "30260201ff022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "30260201ff022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    "30260201ff022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    "30260201ff022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "30260201ff022100ffffffff00000001000000000000000000000001000000000000000000000000",
    "30080201ff090380fe01",
    "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020100",
    "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101",
    "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325510201ff",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632551022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632551",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632551022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632550",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632551022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632552",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632551022100ffffffff00000001000000000000000000000000ffffffff"
        + "ffffffffffffffff",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632551022100ffffffff0000000100000000000000000000000100000000"
        + "0000000000000000",
    "3028022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca" + "c2fc632551090380fe01",
    "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550020100",
    "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550020101",
    "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325500201ff",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632550022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632551",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632550022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632550",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632550022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632552",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632550022100ffffffff00000001000000000000000000000000ffffffff"
        + "ffffffffffffffff",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632550022100ffffffff0000000100000000000000000000000100000000"
        + "0000000000000000",
    "3028022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca" + "c2fc632550090380fe01",
    "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552020100",
    "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552020101",
    "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325520201ff",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632552022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632551",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632552022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632550",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632552022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632552",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632552022100ffffffff00000001000000000000000000000000ffffffff"
        + "ffffffffffffffff",
    "3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca"
        + "c2fc632552022100ffffffff0000000100000000000000000000000100000000"
        + "0000000000000000",
    "3028022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9ca" + "c2fc632552090380fe01",
    "3026022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff020100",
    "3026022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff020101",
    "3026022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff0201ff",
    "3046022100ffffffff00000001000000000000000000000000ffffffffffffff"
        + "ffffffffff022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632551",
    "3046022100ffffffff00000001000000000000000000000000ffffffffffffff"
        + "ffffffffff022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632550",
    "3046022100ffffffff00000001000000000000000000000000ffffffffffffff"
        + "ffffffffff022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632552",
    "3046022100ffffffff00000001000000000000000000000000ffffffffffffff"
        + "ffffffffff022100ffffffff00000001000000000000000000000000ffffffff"
        + "ffffffffffffffff",
    "3046022100ffffffff00000001000000000000000000000000ffffffffffffff"
        + "ffffffffff022100ffffffff0000000100000000000000000000000100000000"
        + "0000000000000000",
    "3028022100ffffffff00000001000000000000000000000000ffffffffffffff" + "ffffffffff090380fe01",
    "3026022100ffffffff00000001000000000000000000000001000000000000000000000000020100",
    "3026022100ffffffff00000001000000000000000000000001000000000000000000000000020101",
    "3026022100ffffffff000000010000000000000000000000010000000000000000000000000201ff",
    "3046022100ffffffff0000000100000000000000000000000100000000000000"
        + "0000000000022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632551",
    "3046022100ffffffff0000000100000000000000000000000100000000000000"
        + "0000000000022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632550",
    "3046022100ffffffff0000000100000000000000000000000100000000000000"
        + "0000000000022100ffffffff00000000ffffffffffffffffbce6faada7179e84"
        + "f3b9cac2fc632552",
    "3046022100ffffffff0000000100000000000000000000000100000000000000"
        + "0000000000022100ffffffff00000001000000000000000000000000ffffffff"
        + "ffffffffffffffff",
    "3046022100ffffffff0000000100000000000000000000000100000000000000"
        + "0000000000022100ffffffff0000000100000000000000000000000100000000"
        + "0000000000000000",
    "3028022100ffffffff0000000100000000000000000000000100000000000000" + "0000000000090380fe01",
  };

  /**
   * Determines the Hash name from the ECDSA algorithm. There is a small inconsistency in the naming
   * of algorithms. The Oracle standard use no hyphen in SHA256WithECDSA but uses a hyphen in the
   * message digest, i.e., SHA-256.
   */
  private String getHashAlgorithm(String ecdsaAlgorithm) {
    ecdsaAlgorithm = ecdsaAlgorithm.toUpperCase();
    int idx = ecdsaAlgorithm.indexOf("WITH");
    if (idx > 0) {
      if (ecdsaAlgorithm.startsWith("SHA")) {
        return "SHA-" + ecdsaAlgorithm.substring(3, idx);
      } else {
        return ecdsaAlgorithm.substring(0, idx);
      }
    }
    return "";
  }

  /**
   * Extract the integer r from an ECDSA signature. This method implicitely assumes that the ECDSA
   * signature is DER encoded. and that the order of the curve is smaller than 2^1024.
   */
  BigInteger extractR(byte[] signature) throws Exception {
    int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
    int lengthR = signature[startR + 1];
    return new BigInteger(Arrays.copyOfRange(signature, startR + 2, startR + 2 + lengthR));
  }

  BigInteger extractS(byte[] signature) throws Exception {
    int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
    int lengthR = signature[startR + 1];
    int startS = startR + 2 + lengthR;
    int lengthS = signature[startS + 1];
    return new BigInteger(Arrays.copyOfRange(signature, startS + 2, startS + 2 + lengthS));
  }

  /** Extract the k that was used to sign the signature. */
  BigInteger extractK(byte[] signature, BigInteger h, ECPrivateKey priv) throws Exception {
    BigInteger x = priv.getS();
    BigInteger n = priv.getParams().getOrder();
    BigInteger r = extractR(signature);
    BigInteger s = extractS(signature);
    BigInteger k = x.multiply(r).add(h).multiply(s.modInverse(n)).mod(n);
    return k;
  }

  public ECPublicKeySpec publicKey1() throws Exception {
    ECParameterSpec params = EcUtil.getNistP256Params();
    ECPoint w = new ECPoint(PubX, PubY);
    return new ECPublicKeySpec(w, params);
  }

  public void testVectors(
      String[] signatures,
      ECPublicKeySpec pubSpec,
      String message,
      String algorithm,
      String signatureType,
      boolean isValidDER,
      boolean isValidBER)
      throws Exception {
    byte[] messageBytes = message.getBytes("UTF-8");
    Signature verifier = Signature.getInstance(algorithm);
    KeyFactory kf = KeyFactory.getInstance("EC");
    ECPublicKey pub = (ECPublicKey) kf.generatePublic(pubSpec);
    int errors = 0;
    for (String signature : signatures) {
      byte[] signatureBytes = TestUtil.hexToBytes(signature);
      verifier.initVerify(pub);
      verifier.update(messageBytes);
      boolean verified = false;
      try {
        verified = verifier.verify(signatureBytes);
      } catch (SignatureException ex) {
        // verify can throw SignatureExceptions if the signature is malformed.
        // We don't flag these cases and simply consider the signature as invalid.
        verified = false;
      }
      if (!verified && isValidDER) {
        System.out.println(signatureType + " was not verified:" + signature);
        errors++;
      }
      if (verified && !isValidBER) {
        System.out.println(signatureType + " was verified:" + signature);
        errors++;
      }
    }
    assertEquals(0, errors);
  }

  @Test
  public void testValidSignatures() throws Exception {
    testVectors(
        VALID_SIGNATURES,
        publicKey1(),
        "Hello",
        "SHA256WithECDSA",
        "Valid ECDSA signature",
        true,
        true);
  }

  @Test
  public void testModifiedSignatures() throws Exception {
    testVectors(
        MODIFIED_SIGNATURES,
        publicKey1(),
        "Hello",
        "SHA256WithECDSA",
        "Modified ECDSA signature",
        false,
        true);
  }

  @Test
  public void testInvalidSignatures() throws Exception {
    testVectors(
        INVALID_SIGNATURES,
        publicKey1(),
        "Hello",
        "SHA256WithECDSA",
        "Invalid ECDSA signature",
        false,
        false);
  }

  /**
   * This test checks the basic functionality of ECDSA. It can also be used to generate simple test
   * vectors.
   */
  @Test
  public void testBasic() throws Exception {
    String algorithm = "SHA256WithECDSA";
    String hashAlgorithm = "SHA-256";
    String message = "Hello";
    String curve = "secp256r1";

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
    keyGen.initialize(ecSpec);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

    byte[] messageBytes = message.getBytes("UTF-8");
    Signature signer = Signature.getInstance(algorithm);
    Signature verifier = Signature.getInstance(algorithm);
    signer.initSign(priv);
    signer.update(messageBytes);
    byte[] signature = signer.sign();
    verifier.initVerify(pub);
    verifier.update(messageBytes);
    assertTrue(verifier.verify(signature));

    // Extract some parameters.
    byte[] rawHash = MessageDigest.getInstance(hashAlgorithm).digest(messageBytes);
    ECParameterSpec params = priv.getParams();

    // Print keys and signature, so that it can be used to generate new test vectors.
    System.out.println("Message:" + message);
    System.out.println("Hash:" + TestUtil.bytesToHex(rawHash));
    System.out.println("Curve:" + curve);
    System.out.println("Order:" + params.getOrder().toString());
    System.out.println("Private key:");
    System.out.println("S:" + priv.getS().toString());
    System.out.println("encoded:" + TestUtil.bytesToHex(priv.getEncoded()));
    System.out.println("Public key:");
    ECPoint w = pub.getW();
    System.out.println("X:" + w.getAffineX().toString());
    System.out.println("Y:" + w.getAffineY().toString());
    System.out.println("encoded:" + TestUtil.bytesToHex(pub.getEncoded()));
    System.out.println("Signature:" + TestUtil.bytesToHex(signature));
    System.out.println("r:" + extractR(signature).toString());
    System.out.println("s:" + extractS(signature).toString());
  }

  /** Checks whether the one time key k in ECDSA is biased. */
  public void testBias(String algorithm, String curve, ECParameterSpec ecParams) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    try {
      keyGen.initialize(ecParams);
    } catch (InvalidAlgorithmParameterException ex) {
      System.out.println("This provider does not support curve:" + curve);
      return;
    }
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    // If we throw a fair coin tests times then the probability that
    // either heads or tails appears less than mincount is less than 2^{-32}.
    // Therefore the test below is not expected to fail unless the generation
    // of the one time keys is indeed biased.
    final int tests = 1024;
    final int mincount = 410;

    String hashAlgorithm = getHashAlgorithm(algorithm);
    String message = "Hello";
    byte[] messageBytes = message.getBytes("UTF-8");
    byte[] digest = MessageDigest.getInstance(hashAlgorithm).digest(messageBytes);

    // TODO(bleichen): Truncate the digest if the digest size is larger than the
    //   curve size.
    BigInteger h = new BigInteger(1, digest);
    BigInteger q = priv.getParams().getOrder();
    BigInteger qHalf = q.shiftRight(1);

    Signature signer = Signature.getInstance(algorithm);
    signer.initSign(priv);
    int countLsb = 0; // count the number of k's with msb set
    int countMsb = 0; // count the number of k's with lsb set
    for (int i = 0; i < tests; i++) {
      signer.update(messageBytes);
      byte[] signature = signer.sign();
      BigInteger k = extractK(signature, h, priv);
      if (k.testBit(0)) {
        countLsb++;
      }
      if (k.compareTo(qHalf) == 1) {
        countMsb++;
      }
    }
    System.out.println(
        signer.getProvider().getName()
            + " curve:"
            + curve
            + " countLsb:"
            + countLsb
            + " countMsb:"
            + countMsb);
    if (countLsb < mincount || countLsb > tests - mincount) {
      fail("Bias detected in the least significant bit of k:" + countLsb);
    }
    if (countMsb < mincount || countMsb > tests - mincount) {
      fail("Bias detected in the most significant bit of k:" + countMsb);
    }
  }

  @SlowTest(
    providers = {
      ProviderType.BOUNCY_CASTLE,
      ProviderType.CONSCRYPT,
      ProviderType.OPENJDK,
      ProviderType.SPONGY_CASTLE
    }
  )
  @Test
  public void testBiasAll() throws Exception {
    testBias("SHA256WithECDSA", "secp256r1", EcUtil.getNistP256Params());
    testBias("SHA224WithECDSA", "secp224r1", EcUtil.getNistP224Params());
    testBias("SHA384WithECDSA", "secp384r1", EcUtil.getNistP384Params());
    testBias("SHA512WithECDSA", "secp521r1", EcUtil.getNistP521Params());
    testBias("SHA256WithECDSA", "brainpoolP256r1", EcUtil.getBrainpoolP256r1Params());
  }

  /**
   * Tests for a potential timing attack. This test checks if there is a correlation between the
   * timing of signature generation and the size of the one-time key k. This is for example the case
   * if a double and add method is used for the point multiplication. The test fails if such a
   * correlation can be shown with high confidence. Further analysis will be necessary to determine
   * how easy it is to exploit the bias in a timing attack.
   */
  // TODO(bleichen): Determine if there are exploitable providers.
  //
  // SunEC currently fails this test. Since ECDSA typically is used with EC groups whose order
  // is 224 bits or larger, it is unclear whether the same attacks that apply to DSA are practical.
  //
  // The ECDSA implementation in BouncyCastle leaks information about k through timing too.
  // The test has not been optimized to detect this bias. It would require about 5'000'000 samples,
  // which is too much for a simple unit test.
  //
  // BouncyCastle uses FixedPointCombMultiplier for ECDSA. This is a method using
  // precomputation. The implementation is not constant time, since the precomputation table
  // contains the point at infinity and adding this point is faster than ordinary point additions.
  // The timing leak only has a small correlation to the size of k and at the moment it is is very
  // unclear if the can be exploited. (Randomizing the precomputation table by adding the same
  // random point to each element in the table and precomputing the necessary offset to undo the
  // precomputation seems much easier than analyzing this.)
  public void testTiming(String algorithm, String curve, ECParameterSpec ecParams)
      throws Exception {
    ThreadMXBean bean = ManagementFactory.getThreadMXBean();
    if (!bean.isCurrentThreadCpuTimeSupported()) {
      System.out.println("getCurrentThreadCpuTime is not supported. Skipping");
      return;
    }
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    try {
      keyGen.initialize(ecParams);
    } catch (InvalidAlgorithmParameterException ex) {
      System.out.println("This provider does not support curve:" + curve);
      return;
    }
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

    String message = "Hello";
    String hashAlgorithm = getHashAlgorithm(algorithm);
    byte[] messageBytes = message.getBytes("UTF-8");
    byte[] digest = MessageDigest.getInstance(hashAlgorithm).digest(messageBytes);
    BigInteger h = new BigInteger(1, digest);
    Signature signer = Signature.getInstance(algorithm);
    signer.initSign(priv);
    // The number of samples used for the test. This number is a bit low.
    // I.e. it just barely detects that SunEC leaks information about the size of k.
    int samples = 50000;
    long[] timing = new long[samples];
    BigInteger[] k = new BigInteger[samples];
    for (int i = 0; i < samples; i++) {
      long start = bean.getCurrentThreadCpuTime();
      signer.update(messageBytes);
      byte[] signature = signer.sign();
      timing[i] = bean.getCurrentThreadCpuTime() - start;
      k[i] = extractK(signature, h, priv);
    }
    long[] sorted = Arrays.copyOf(timing, timing.length);
    Arrays.sort(sorted);
    double n = priv.getParams().getOrder().doubleValue();
    double expectedAverage = n / 2;
    double maxSigma = 0;
    System.out.println("testTiming algorithm:" + algorithm);
    for (int idx = samples - 1; idx > 10; idx /= 2) {
      long cutoff = sorted[idx];
      int count = 0;
      BigInteger total = BigInteger.ZERO;
      for (int i = 0; i < samples; i++) {
        if (timing[i] <= cutoff) {
          total = total.add(k[i]);
          count += 1;
        }
      }
      double expectedStdDev = n / Math.sqrt(12 * count);
      double average = total.doubleValue() / count;
      // Number of standard deviations that the average is away from
      // the expected value:
      double sigmas = Math.abs(expectedAverage - average) / expectedStdDev;
      if (sigmas > maxSigma) {
        maxSigma = sigmas;
      }
      System.out.println(
          "count:"
              + count
              + " cutoff:"
              + cutoff
              + " relative average:"
              + (average / expectedAverage)
              + " sigmas:"
              + sigmas);
    }
    // Checks if the signatures with a small timing have a biased k.
    // We use 7 standard deviations, so that the probability of a false positive is smaller
    // than 10^{-10}.
    if (maxSigma >= 7) {
      fail("Signatures with short timing have a biased k");
    }
  }

  @SlowTest(
    providers = {
      ProviderType.BOUNCY_CASTLE,
      ProviderType.CONSCRYPT,
      ProviderType.OPENJDK,
      ProviderType.SPONGY_CASTLE
    }
  )
  @Test
  public void testTimingAll() throws Exception {
    testTiming("SHA256WithECDSA", "secp256r1", EcUtil.getNistP256Params());
    // TODO(bleichen): crypto libraries sometimes use optimized code for curves that are frequently
    //   used. Hence it would make sense to test distinct curves. But at the moment testing many
    //   curves is not practical since one test alone is already quite time consuming.
    // testTiming("SHA224WithECDSA", "secp224r1", EcUtil.getNistP224Params());
    // testTiming("SHA384WithECDSA", "secp384r1", EcUtil.getNistP384Params());
    // testTiming("SHA512WithECDSA", "secp521r1", EcUtil.getNistP521Params());
    // testTiming("SHA256WithECDSA", "brainpoolP256r1", EcUtil.getBrainpoolP256r1Params());
  }
}
