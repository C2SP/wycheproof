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

import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import com.google.security.wycheproof.WycheproofRunner.SlowTest;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Testing ECDH.
 *
 * <p><b>Defense in depth</b>: The tests for ECDH assume that a attacker has control over all
 * aspects of the public key in an exchange. That means that the attacker can potentially send weak
 * or invalid public keys. For example, invalid public keys can contain points not on the curve,
 * curves that have been deliberately chosen so that DLs are easy to compute as well as orders or
 * cofactors that are wrong. It is expected that implementations validate the inputs of a key
 * agreement and that in no case information about the private key is leaked.
 *
 * <p><b>References:</b> Ingrid Biehl, Bernd Meyer, Volker Müller, "Differential Fault Attacks on
 * Elliptic Curve Cryptosystems", Crypto '00, pp. 131-164
 *
 * <p>Adrian Antipa, Daniel Brown, Alfred Menezes, Rene Struik, and Scott Vanstone, "Validation of
 * Elliptic Curve Public Keys", PKC 2003, https://www.iacr.org/archive/pkc2003/25670211/25670211.pdf
 *
 * <p><b>Bugs:</b> CVE-2015-7940: BouncyCastle before 1.51 does not validate a point is on the
 * curve. BouncyCastle v.1.52 checks that the public key point is on the public key curve but does
 * not check whether public key and private key use the same curve. BouncyCastle v.1.53 is still
 * vulnerable to attacks with modified public keys. An attacker can change the order of the curve
 * used by the public key. ECDHC would then reduce the private key modulo this order, which can be
 * used to find the private key.
 *
 * <p>CVE-2015-6924: Utimaco HSMs vulnerable to invalid curve attacks, which made the private key
 * extraction possible.
 *
 * <p>CVE-2015-7940: Issue with elliptic curve addition in mixed Jacobian-affine coordinates
 *
 * @author bleichen@google.com (Daniel Bleichenbacher)
 */
// TODO(bleichen): Stuff we haven't implemented:
//   - timing attacks
// Stuff we are delaying because there are more important bugs:
//   - testWrongOrder using BouncyCastle with ECDHWithSHA1Kdf throws
//     java.lang.UnsupportedOperationException: KDF can only be used when algorithm is known
//     Not sure if that is expected or another bug.
// CVEs for ECDH we haven't used anywhere.
//   - CVE-2014-3470: OpenSSL anonymous ECDH denial of service: triggered by NULL value in
//     certificate.
//   - CVE-2014-3572: OpenSSL downgrades ECDHE to ECDH
//   - CVE-2011-3210: OpenSSL was not thread safe
@RunWith(JUnit4.class)
public class EcdhTest {

  static final String[] ECDH_VARIANTS = {
    // Raw ECDH. The shared secret is the x-coordinate of the ECDH computation.
    // The tests below assume that this variant is implemenented.
    "ECDH",
    // ECDHC is a variant described in P1363 7.2.2 ECSVDP-DHC.
    // BouncyCastle implements this variant.
    "ECDHC",
    // A variant with an explicit key derivation function.
    // This is implemented by BouncyCastle.
    "ECDHWITHSHA1KDF",
  };

  /** Test vectors */
  public static class EcPublicKeyTestVector {
    final String comment;
    final String encoded; // hexadecimal representation of the X509 encoding
    final BigInteger p; // characteristic of the field
    final BigInteger n; // order of the subgroup
    final BigInteger a; // parameter a of the Weierstrass representation
    final BigInteger b; // parameter b of the Weierstrass represnetation
    final BigInteger gx; // x-coordinate of the generator
    final BigInteger gy; // y-coordainat of the generator
    final Integer h; // cofactor: may be null
    final BigInteger pubx; // x-coordinate of the public point
    final BigInteger puby; // y-coordinate of the public point

    public EcPublicKeyTestVector(
        String comment,
        String encoded,
        BigInteger p,
        BigInteger n,
        BigInteger a,
        BigInteger b,
        BigInteger gx,
        BigInteger gy,
        Integer h,
        BigInteger pubx,
        BigInteger puby) {
      this.comment = comment;
      this.encoded = encoded;
      this.p = p;
      this.n = n;
      this.a = a;
      this.b = b;
      this.gx = gx;
      this.gy = gy;
      this.h = h;
      this.pubx = pubx;
      this.puby = puby;
    }

    /**
     * Returns this key as ECPublicKeySpec or null if the key cannot be represented as
     * ECPublicKeySpec. The later happens for example if the order of cofactor are not positive.
     */
    public ECPublicKeySpec getSpec() {
      try {
        ECFieldFp fp = new ECFieldFp(p);
        EllipticCurve curve = new EllipticCurve(fp, a, b);
        ECPoint g = new ECPoint(gx, gy);
        // ECParameterSpec requires that the cofactor h is specified.
        if (h == null) {
          return null;
        }
        ECParameterSpec params = new ECParameterSpec(curve, g, n, h);
        ECPoint pubPoint = new ECPoint(pubx, puby);
        ECPublicKeySpec pub = new ECPublicKeySpec(pubPoint, params);
        return pub;
      } catch (Exception ex) {
        System.out.println(comment + " throws " + ex.toString());
        return null;
      }
    }

    public X509EncodedKeySpec getX509EncodedKeySpec() {
      return new X509EncodedKeySpec(TestUtil.hexToBytes(encoded));
    }
  }

public static final EcPublicKeyTestVector EC_VALID_PUBLIC_KEY =
      new EcPublicKeyTestVector(
          "unmodified",
          "3059301306072a8648ce3d020106082a8648ce3d03010703420004cdeb39edd0"
              + "3e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b84"
              + "29598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8",
          new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
          new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
          new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
          new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
          new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
          new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
          1,
          new BigInteger("cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958", 16),
          new BigInteger("ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8", 16));

  public static final EcPublicKeyTestVector[] EC_MODIFIED_PUBLIC_KEYS = {
      // Modified keys
      new EcPublicKeyTestVector(
          "public point not on curve",
          "3059301306072a8648ce3d020106082a8648ce3d03010703420004cdeb39edd0"
              + "3e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b84"
              + "29598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebaca",
          new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
          new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
          new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
          new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
          new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
          new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
          1,
          new BigInteger("cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958", 16),
          new BigInteger("ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebaca", 16)),
      new EcPublicKeyTestVector(
          "public point = (0,0)",
          "3059301306072a8648ce3d020106082a8648ce3d030107034200040000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "000000000000000000000000000000000000000000000000000000",
          new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
          new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
          new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
          new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
          new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
          new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
          1,
          new BigInteger("0"),
          new BigInteger("0")),
      new EcPublicKeyTestVector(
          "order = 1",
          "308201133081cc06072a8648ce3d02013081c0020101302c06072a8648ce3d01"
              + "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
              + "ffffffff30440420ffffffff00000001000000000000000000000000ffffffff"
              + "fffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53"
              + "b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d"
              + "812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33"
              + "576b315ececbb6406837bf51f502010102010103420004cdeb39edd03e2b1a11"
              + "a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b"
              + "49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8",
          new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
          new BigInteger("01", 16),
          new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
          new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
          new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
          new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
          1,
          new BigInteger("cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958", 16),
          new BigInteger("ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8", 16)),
      new EcPublicKeyTestVector(
          "order = 26959946660873538060741835960514744168612397095220107664918121663170",
          "3082012f3081e806072a8648ce3d02013081dc020101302c06072a8648ce3d01"
              + "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
              + "ffffffff30440420ffffffff00000001000000000000000000000000ffffffff"
              + "fffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53"
              + "b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d"
              + "812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33"
              + "576b315ececbb6406837bf51f5021d00ffffffff00000000ffffffffffffffff"
              + "bce6faada7179e84f3b9cac202010103420004cdeb39edd03e2b1a11a5e134ec"
              + "99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b49bbb85c"
              + "3303ddb1553c3b761c2caacca71606ba9ebac8",
          new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
          new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2", 16),
          new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
          new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
          new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
          new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
          1,
          new BigInteger("cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958", 16),
          new BigInteger("ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8", 16)),
      new EcPublicKeyTestVector(
          "generator = (0,0)",
          "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
              + "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
              + "ffffffff30440420ffffffff00000001000000000000000000000000ffffffff"
              + "fffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53"
              + "b0f63bce3c3e27d2604b04410400000000000000000000000000000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "00000000000000000000000000022100ffffffff00000000ffffffffffffffff"
              + "bce6faada7179e84f3b9cac2fc63255102010103420004cdeb39edd03e2b1a11"
              + "a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b"
              + "49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8",
          new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
          new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
          new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
          new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
          new BigInteger("0"),
          new BigInteger("0"),
          1,
          new BigInteger("cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958", 16),
          new BigInteger("ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8", 16)),
      new EcPublicKeyTestVector(
          "generator not on curve",
          "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
              + "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
              + "ffffffff30440420ffffffff00000001000000000000000000000000ffffffff"
              + "fffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53"
              + "b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d"
              + "812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33"
              + "576b315ececbb6406837bf51f7022100ffffffff00000000ffffffffffffffff"
              + "bce6faada7179e84f3b9cac2fc63255102010103420004cdeb39edd03e2b1a11"
              + "a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b"
              + "49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8",
          new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
          new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
          new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
          new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
          new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
          new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f7", 16),
          1,
          new BigInteger("cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958", 16),
          new BigInteger("ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8", 16)),
      new EcPublicKeyTestVector(
          "cofactor = 2",
          "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
              + "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
              + "ffffffff30440420ffffffff00000001000000000000000000000000ffffffff"
              + "fffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53"
              + "b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d"
              + "812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33"
              + "576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffff"
              + "bce6faada7179e84f3b9cac2fc63255102010203420004cdeb39edd03e2b1a11"
              + "a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b"
              + "49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8",
          new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
          new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
          new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
          new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
          new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
          new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
          2,
          new BigInteger("cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958", 16),
          new BigInteger("ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8", 16)),
      new EcPublicKeyTestVector(
          "cofactor = None",
          "308201303081e906072a8648ce3d02013081dd020101302c06072a8648ce3d01"
              + "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
              + "ffffffff30440420ffffffff00000001000000000000000000000000ffffffff"
              + "fffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53"
              + "b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d"
              + "812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33"
              + "576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffff"
              + "bce6faada7179e84f3b9cac2fc63255103420004cdeb39edd03e2b1a11a5e134"
              + "ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b49bbb8"
              + "5c3303ddb1553c3b761c2caacca71606ba9ebac8",
          new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
          new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
          new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
          new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
          new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
          new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
          null,
          new BigInteger("cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958", 16),
          new BigInteger("ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8", 16)),
      new EcPublicKeyTestVector(
          "modified prime",
          "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
              + "01022100fd091059a6893635f900e9449d63f572b2aebc4cff7b4e5e33f1b200"
              + "e8bbc1453044042002f6efa55976c9cb06ff16bb629c0a8d4d5143b40084b1a1"
              + "cc0e4dff17443eb704205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53"
              + "b0f63bce3c3e27d2604b0441040000000000000000000006597fa94b1fd90000"
              + "000000000000000000000000021b8c7dd77f9a95627922eceefea73f028f1ec9"
              + "5ba9b8fa95a3ad24bdf9fff414022100ffffffff00000000ffffffffffffffff"
              + "bce6faada7179e84f3b9cac2fc63255102010103420004000000000000000000"
              + "0006597fa94b1fd90000000000000000000000000000021b8c7dd77f9a956279"
              + "22eceefea73f028f1ec95ba9b8fa95a3ad24bdf9fff414",
          new BigInteger("fd091059a6893635f900e9449d63f572b2aebc4cff7b4e5e33f1b200e8bbc145", 16),
          new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
          new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
          new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
          new BigInteger("06597fa94b1fd9000000000000000000000000000002", 16),
          new BigInteger("1b8c7dd77f9a95627922eceefea73f028f1ec95ba9b8fa95a3ad24bdf9fff414", 16),
          1,
          new BigInteger("06597fa94b1fd9000000000000000000000000000002", 16),
          new BigInteger("1b8c7dd77f9a95627922eceefea73f028f1ec95ba9b8fa95a3ad24bdf9fff414", 16)),
      new EcPublicKeyTestVector(
          "using secp224r1",
          "304e301006072a8648ce3d020106052b81040021033a0004074f56dc2ea648ef"
              + "89c3b72e23bbd2da36f60243e4d2067b70604af1c2165cec2f86603d60c8a611"
              + "d5b84ba3d91dfe1a480825bcc4af3bcf",
          new BigInteger("ffffffffffffffffffffffffffffffff000000000000000000000001", 16),
          new BigInteger("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", 16),
          new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffffffffffe", 16),
          new BigInteger("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16),
          new BigInteger("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 16),
          new BigInteger("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16),
          1,
          new BigInteger("074f56dc2ea648ef89c3b72e23bbd2da36f60243e4d2067b70604af1", 16),
          new BigInteger("c2165cec2f86603d60c8a611d5b84ba3d91dfe1a480825bcc4af3bcf", 16)),
      new EcPublicKeyTestVector(
          "a = 0",
          "308201143081cd06072a8648ce3d02013081c1020101302c06072a8648ce3d01"
              + "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
              + "ffffffff30250401000420f104880c3980129c7efa19b6b0cb04e547b8d0fc0b"
              + "95f4946496dd4ac4a7c440044104cdeb39edd03e2b1a11a5e134ec99d5f25f21"
              + "673d403f3ecb47bd1fa676638958ea58493b8429598c0b49bbb85c3303ddb155"
              + "3c3b761c2caacca71606ba9ebac8022100ffffffff00000000ffffffffffffff"
              + "ffbce6faada7179e84f3b9cac2fc63255102010103420004cdeb39edd03e2b1a"
              + "11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c"
              + "0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8",
          new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
          new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
          new BigInteger("0"),
          new BigInteger("f104880c3980129c7efa19b6b0cb04e547b8d0fc0b95f4946496dd4ac4a7c440", 16),
          new BigInteger("cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958", 16),
          new BigInteger("ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8", 16),
          1,
          new BigInteger("cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958", 16),
          new BigInteger("ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8", 16)),
      new EcPublicKeyTestVector(
          "new curve with generator of order 3 that is also on secp256r1",
          "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
              + "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
              + "ffffffff3044042046dc879a5c2995d0e6f682468ea95791b7bbd0225cfdb251"
              + "3fb10a737afece170420bea6c109251bfe4acf2eeda7c24c4ab70a1473335dec"
              + "28b244d4d823d15935e2044104701c05255026aa4630b78fc6b769e388059ab1"
              + "443cbdd1f8348bedc3be589dc34cfdab998ad27738ae382aa013986ade0f4859"
              + "2a9a1ae37ca61d25ec5356f1bd022100ffffffff00000000ffffffffffffffff"
              + "bce6faada7179e84f3b9cac2fc63255102010103420004701c05255026aa4630"
              + "b78fc6b769e388059ab1443cbdd1f8348bedc3be589dc3b3025465752d88c851"
              + "c7d55fec679521f0b7a6d665e51c8359e2da13aca90e42",
          new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
          new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
          new BigInteger("46dc879a5c2995d0e6f682468ea95791b7bbd0225cfdb2513fb10a737afece17", 16),
          new BigInteger("bea6c109251bfe4acf2eeda7c24c4ab70a1473335dec28b244d4d823d15935e2", 16),
          new BigInteger("701c05255026aa4630b78fc6b769e388059ab1443cbdd1f8348bedc3be589dc3", 16),
          new BigInteger("4cfdab998ad27738ae382aa013986ade0f48592a9a1ae37ca61d25ec5356f1bd", 16),
          1,
          new BigInteger("701c05255026aa4630b78fc6b769e388059ab1443cbdd1f8348bedc3be589dc3", 16),
          new BigInteger("b3025465752d88c851c7d55fec679521f0b7a6d665e51c8359e2da13aca90e42", 16)),
      // Invalid keys
      new EcPublicKeyTestVector(
          "order = -1157920892103562487626974469494075735299969552241357603"
              + "42422259061068512044369",
          "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
              + "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
              + "ffffffff30440420ffffffff00000001000000000000000000000000ffffffff"
              + "fffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53"
              + "b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d"
              + "812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33"
              + "576b315ececbb6406837bf51f50221ff00000000ffffffff0000000000000000"
              + "4319055258e8617b0c46353d039cdaaf02010103420004cdeb39edd03e2b1a11"
              + "a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b"
              + "49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8",
          new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
          new BigInteger(
              "-115792089210356248762697446949407573529996955224135760342422259061068512044369"),
          new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
          new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
          new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
          new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
          1,
          new BigInteger("cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958", 16),
          new BigInteger("ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8", 16)),
      new EcPublicKeyTestVector(
          "order = 0",
          "308201133081cc06072a8648ce3d02013081c0020101302c06072a8648ce3d01"
              + "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
              + "ffffffff30440420ffffffff00000001000000000000000000000000ffffffff"
              + "fffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53"
              + "b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d"
              + "812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33"
              + "576b315ececbb6406837bf51f502010002010103420004cdeb39edd03e2b1a11"
              + "a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b"
              + "49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8",
          new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
          new BigInteger("0"),
          new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
          new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
          new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
          new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
          1,
          new BigInteger("cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958", 16),
          new BigInteger("ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8", 16)),
      new EcPublicKeyTestVector(
          "cofactor = -1",
          "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
              + "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
              + "ffffffff30440420ffffffff00000001000000000000000000000000ffffffff"
              + "fffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53"
              + "b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d"
              + "812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33"
              + "576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffff"
              + "bce6faada7179e84f3b9cac2fc6325510201ff03420004cdeb39edd03e2b1a11"
              + "a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b"
              + "49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8",
          new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
          new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
          new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
          new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
          new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
          new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
          -1,
          new BigInteger("cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958", 16),
          new BigInteger("ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8", 16)),
      new EcPublicKeyTestVector(
          "cofactor = 0",
          "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
              + "01022100ffffffff00000001000000000000000000000000ffffffffffffffff"
              + "ffffffff30440420ffffffff00000001000000000000000000000000ffffffff"
              + "fffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53"
              + "b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d"
              + "812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33"
              + "576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffff"
              + "bce6faada7179e84f3b9cac2fc63255102010003420004cdeb39edd03e2b1a11"
              + "a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b"
              + "49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8",
          new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
          new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
          new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
          new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
          new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
          new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
          0,
          new BigInteger("cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958", 16),
          new BigInteger("ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebac8", 16)),
  };

  /** Checks that key agreement using ECDH works. */
  @Test
  public void testBasic() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
    keyGen.initialize(ecSpec);
    KeyPair keyPairA = keyGen.generateKeyPair();
    KeyPair keyPairB = keyGen.generateKeyPair();

    KeyAgreement kaA = KeyAgreement.getInstance("ECDH");
    KeyAgreement kaB = KeyAgreement.getInstance("ECDH");
    kaA.init(keyPairA.getPrivate());
    kaB.init(keyPairB.getPrivate());
    kaA.doPhase(keyPairB.getPublic(), true);
    kaB.doPhase(keyPairA.getPublic(), true);
    byte[] kAB = kaA.generateSecret();
    byte[] kBA = kaB.generateSecret();
    assertEquals(TestUtil.bytesToHex(kAB), TestUtil.bytesToHex(kBA));
  }

  @NoPresubmitTest(
    providers = {ProviderType.BOUNCY_CASTLE},
    bugs = {"BouncyCastle uses long encoding. Is this a bug?"}
  )
  @Test
  public void testEncode() throws Exception {
    KeyFactory kf = KeyFactory.getInstance("EC");
    ECPublicKey valid = (ECPublicKey) kf.generatePublic(EC_VALID_PUBLIC_KEY.getSpec());
    assertEquals(TestUtil.bytesToHex(valid.getEncoded()), EC_VALID_PUBLIC_KEY.encoded);
  }

  @Test
  public void testDecode() throws Exception {
    KeyFactory kf = KeyFactory.getInstance("EC");
    ECPublicKey key1 = (ECPublicKey) kf.generatePublic(EC_VALID_PUBLIC_KEY.getSpec());
    ECPublicKey key2 = (ECPublicKey) kf.generatePublic(EC_VALID_PUBLIC_KEY.getX509EncodedKeySpec());
    ECParameterSpec params1 = key1.getParams();
    ECParameterSpec params2 = key2.getParams();
    assertEquals(params1.getCofactor(), params2.getCofactor());
    assertEquals(params1.getCurve(), params2.getCurve());
    assertEquals(params1.getGenerator(), params2.getGenerator());
    assertEquals(params1.getOrder(), params2.getOrder());
    assertEquals(key1.getW(), key2.getW());
  }

  /**
   * This test modifies the order of group in the public key. A severe bug would be an
   * implementation that leaks information whether the private key is larger than the order given in
   * the public key. Also a severe bug would be to reduce the private key modulo the order given in
   * the public key parameters.
   */
  @SuppressWarnings("InsecureCryptoUsage")
  public void testModifiedPublic(String algorithm) throws Exception {
    KeyAgreement ka;
    try {
      ka = KeyAgreement.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("testWrongOrder: " + algorithm + " not supported");
      return;
    }
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(EcUtil.getNistP256Params());
    ECPrivateKey priv = (ECPrivateKey) keyGen.generateKeyPair().getPrivate();
    KeyFactory kf = KeyFactory.getInstance("EC");
    ECPublicKey validKey = (ECPublicKey) kf.generatePublic(EC_VALID_PUBLIC_KEY.getSpec());
    ka.init(priv);
    ka.doPhase(validKey, true);
    String expected = TestUtil.bytesToHex(ka.generateSecret());
    for (EcPublicKeyTestVector test : EC_MODIFIED_PUBLIC_KEYS) {
      try {
        X509EncodedKeySpec spec = test.getX509EncodedKeySpec();
        ECPublicKey modifiedKey = (ECPublicKey) kf.generatePublic(spec);
        ka.init(priv);
        ka.doPhase(modifiedKey, true);
        String shared = TestUtil.bytesToHex(ka.generateSecret());
        // The implementation did not notice that the public key was modified.
        // This is not nice, but at the moment we only fail the test if the
        // modification was essential for computing the shared secret.
        //
        // BouncyCastle v.1.53 fails this test, for ECDHC with modified order.
        // This implementation reduces the product s*h modulo the order given
        // in the public key. An attacker who can modify the order of the public key
        // and who can learn whether such a modification changes the shared secret is
        // able to learn the private key with a simple binary search.
        assertEquals("algorithm:" + algorithm + " test:" + test.comment, expected, shared);
      } catch (GeneralSecurityException ex) {
        // OK, since the public keys have been modified.
        System.out.println("testModifiedPublic:" + test.comment + " throws " + ex.toString());
      }
    }
  }

  /**
   * This is a similar test as testModifiedPublic. However, this test uses test vectors
   * ECPublicKeySpec
   */
  @SuppressWarnings("InsecureCryptoUsage")
  public void testModifiedPublicSpec(String algorithm) throws Exception {
    KeyAgreement ka;
    try {
      ka = KeyAgreement.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("testWrongOrder: " + algorithm + " not supported");
      return;
    }
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(EcUtil.getNistP256Params());
    ECPrivateKey priv = (ECPrivateKey) keyGen.generateKeyPair().getPrivate();
    KeyFactory kf = KeyFactory.getInstance("EC");
    ECPublicKey validKey = (ECPublicKey) kf.generatePublic(EC_VALID_PUBLIC_KEY.getSpec());
    ka.init(priv);
    ka.doPhase(validKey, true);
    String expected = TestUtil.bytesToHex(ka.generateSecret());
    for (EcPublicKeyTestVector test : EC_MODIFIED_PUBLIC_KEYS) {
      ECPublicKeySpec spec = test.getSpec();
      if (spec == null) {
        // The constructor of EcPublicKeySpec performs some very minor validity checks.
        // spec == null if one of these validity checks fails. Of course such a failure is OK.
        continue;
      }
      try {
        ECPublicKey modifiedKey = (ECPublicKey) kf.generatePublic(spec);
        ka.init(priv);
        ka.doPhase(modifiedKey, true);
        String shared = TestUtil.bytesToHex(ka.generateSecret());
        // The implementation did not notice that the public key was modified.
        // This is not nice, but at the moment we only fail the test if the
        // modification was essential for computing the shared secret.
        //
        // BouncyCastle v.1.53 fails this test, for ECDHC with modified order.
        // This implementation reduces the product s*h modulo the order given
        // in the public key. An attacker who can modify the order of the public key
        // and who can learn whether such a modification changes the shared secret is
        // able to learn the private key with a simple binary search.
        assertEquals("algorithm:" + algorithm + " test:" + test.comment, expected, shared);
      } catch (GeneralSecurityException ex) {
        // OK, since the public keys have been modified.
        System.out.println("testModifiedPublic:" + test.comment + " throws " + ex.toString());
      }
    }
  }

  @Test
  public void testModifiedPublic() throws Exception {
    testModifiedPublic("ECDH");
    testModifiedPublic("ECDHC");
  }

  @Test
  public void testModifiedPublicSpec() throws Exception {
    testModifiedPublicSpec("ECDH");
    testModifiedPublicSpec("ECDHC");
  }

  @SuppressWarnings("InsecureCryptoUsage")
  public void testDistinctCurves(String algorithm, ECPrivateKey priv, ECPublicKey pub)
      throws Exception {
    KeyAgreement kaA;
    try {
      kaA = KeyAgreement.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("Algorithm not supported: " + algorithm);
      return;
    }
    byte[] shared;
    try {
      kaA.init(priv);
      kaA.doPhase(pub, true);
      shared = kaA.generateSecret();
    } catch (InvalidKeyException ex) {
      // This is expected.
      return;
    }
    // Printing some information to determine what might have gone wrong:
    // E.g., if the generated secret is the same as the x-coordinate of the public key
    // then it is likely that the ECDH computation was using a fake group with small order.
    // Such a situation is probably exploitable.
    // This probably is exploitable. If the curve of the private key was used for the ECDH
    // then the generated secret and the x-coordinate of the public key are likely
    // distinct.
    EllipticCurve pubCurve = pub.getParams().getCurve();
    EllipticCurve privCurve = priv.getParams().getCurve();
    ECPoint pubW = pub.getW();
    System.out.println("testDistinctCurves: algorithm=" + algorithm);
    System.out.println(
        "Private key: a="
            + privCurve.getA()
            + " b="
            + privCurve.getB()
            + " p"
            + EcUtil.getModulus(privCurve));
    System.out.println("        s =" + priv.getS());
    System.out.println(
        "Public key: a="
            + pubCurve.getA()
            + " b="
            + pubCurve.getB()
            + " p"
            + EcUtil.getModulus(pubCurve));
    System.out.println("        w = (" + pubW.getAffineX() + ", " + pubW.getAffineY() + ")");
    System.out.println(
        "          = ("
            + pubW.getAffineX().toString(16)
            + ", "
            + pubW.getAffineY().toString(16)
            + ")");
    System.out.println("generated shared secret:" + TestUtil.bytesToHex(shared));
    fail("Generated secret with distinct Curves using " + algorithm);
  }

  /**
   * This test modifies the order of group in the public key. A severe bug would be an
   * implementation that leaks information whether the private key is larger than the order given in
   * the public key. Also a severe bug would be to reduce the private key modulo the order given in
   * the public key parameters.
   */
  // TODO(bleichen): This can be merged with testModifiedPublic once this is fixed.
  @SuppressWarnings("InsecureCryptoUsage")
  public void testWrongOrder(String algorithm, ECParameterSpec spec) throws Exception {
    KeyAgreement ka;
    try {
      ka = KeyAgreement.getInstance(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      System.out.println("testWrongOrder: " + algorithm + " not supported");
      return;
    }
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    ECPrivateKey priv;
    ECPublicKey pub;
    try {
      keyGen.initialize(spec);
      priv = (ECPrivateKey) keyGen.generateKeyPair().getPrivate();
      pub = (ECPublicKey) keyGen.generateKeyPair().getPublic();
    } catch (GeneralSecurityException ex) {
      // This is OK, since not all provider support Brainpool curves
      System.out.println("testWrongOrder: could not generate keys for curve");
      return;
    }
    // Get the shared secret for the unmodified keys.
    ka.init(priv);
    ka.doPhase(pub, true);
    byte[] shared = ka.generateSecret();
    // Generate a modified public key.
    ECParameterSpec modifiedParams =
        new ECParameterSpec(
            spec.getCurve(), spec.getGenerator(), spec.getOrder().shiftRight(16), 1);
    ECPublicKeySpec modifiedPubSpec = new ECPublicKeySpec(pub.getW(), modifiedParams);
    KeyFactory kf = KeyFactory.getInstance("EC");
    ECPublicKey modifiedPub;
    try {
      modifiedPub = (ECPublicKey) kf.generatePublic(modifiedPubSpec);
    } catch (GeneralSecurityException ex) {
      // The provider does not support non-standard curves or did a validity check.
      // Both would be correct.
      System.out.println("testWrongOrder: can't modify order.");
      return;
    }
    byte[] shared2;
    try {
      ka.init(priv);
      ka.doPhase(modifiedPub, true);
      shared2 = ka.generateSecret();
    } catch (GeneralSecurityException ex) {
      // This is the expected behavior
      System.out.println("testWrongOrder:" + ex.toString());
      return;
    }
    // TODO(bleichen): Getting here is already a bug and we might flag this later.
    // At the moment we are only interested in really bad behavior of a library, that potentially
    // leaks the secret key. This is the case when the shared secrets are different, since this
    // suggests that the implementation reduces the multiplier modulo the given order of the curve
    // or some other behaviour that is dependent on the private key.
    // An attacker who can check whether a DH computation was done correctly or incorrectly because
    // of modular reduction, can determine the private key, either by a binary search or by trying
    // to guess the private key modulo some small "order".
    // BouncyCastle v.1.53 fails this test, and leaks the private key.
    System.out.println(
        "Generated shared secret with a modified order:"
            + algorithm
            + "\n"
            + "expected:"
            + TestUtil.bytesToHex(shared)
            + " computed:"
            + TestUtil.bytesToHex(shared2));
    assertEquals(
        "Algorithm:" + algorithm, TestUtil.bytesToHex(shared), TestUtil.bytesToHex(shared2));
  }

  @Test
  public void testWrongOrderEcdh() throws Exception {
    testWrongOrder("ECDH", EcUtil.getNistP256Params());
    testWrongOrder("ECDH", EcUtil.getBrainpoolP256r1Params());
  }

  @Test
  public void testWrongOrderEcdhc() throws Exception {
    testWrongOrder("ECDHC", EcUtil.getNistP256Params());
    testWrongOrder("ECDHC", EcUtil.getBrainpoolP256r1Params());
  }

  /**
   * Tests for the problem detected by CVE-2017-10176. 
   *
   * <p>Some libraries do not compute P + (-P) correctly and return 2 * P or throw exceptions. When
   * the library uses addition-subtraction chains for the point multiplication then such cases can
   * occur for example when the private key is close to the order of the curve.
   */
  private void testLargePrivateKey(ECParameterSpec spec) throws Exception {
    BigInteger order = spec.getOrder();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    ECPublicKey pub;
    try {
      keyGen.initialize(spec);
      pub = (ECPublicKey) keyGen.generateKeyPair().getPublic();
    } catch (GeneralSecurityException ex) {
      // curve is not supported
      return;
    }
    KeyFactory kf = KeyFactory.getInstance("EC");
    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    for (int i = 1; i <= 64; i++) {
      BigInteger p1 = BigInteger.valueOf(i);
      ECPrivateKeySpec spec1 = new ECPrivateKeySpec(p1, spec);
      ECPrivateKeySpec spec2 = new ECPrivateKeySpec(order.subtract(p1), spec);
      ka.init(kf.generatePrivate(spec1));
      ka.doPhase(pub, true);
      byte[] shared1 = ka.generateSecret();
      ka.init(kf.generatePrivate(spec2));
      ka.doPhase(pub, true);
      byte[] shared2 = ka.generateSecret();
      // The private keys p1 and p2 are equivalent, since only the x-coordinate of the
      // shared point is used to generate the shared secret.
      assertEquals(TestUtil.bytesToHex(shared1), TestUtil.bytesToHex(shared2));
    }
  }

  @Test
  public void testLargePrivateKey() throws Exception {
    testLargePrivateKey(EcUtil.getNistP224Params());
    testLargePrivateKey(EcUtil.getNistP256Params());
    testLargePrivateKey(EcUtil.getNistP384Params());
    // This test failed before CVE-2017-10176 was fixed.
    testLargePrivateKey(EcUtil.getNistP521Params());
    testLargePrivateKey(EcUtil.getBrainpoolP256r1Params());
  }

  /**
   * This test tries to determine whether point multipliplication using two distinct
   * points leads to distinguishable timings.
   *
   * The main goal here is to determine if the attack by Toru Akishita and Tsuyoshi Takagi
   * in https://www-old.cdc.informatik.tu-darmstadt.de/reports/TR/TI-03-01.zvp.pdf
   * might be applicable. I.e. one of the points contains a zero value when multiplied
   * by mul, the other one does not.
   *
   * In its current form the test here is quite weak for a number of reasons:
   * (1) The timing is often noisy, because the test is run as a unit test.
   * (2) The test is executed with only a small number of input points.
   * (3) The number of samples is rather low. Running this test with a larger sample
   *     size would detect more timing differences. Unfortunately
   * (4) The test does not determine if a variable run time is exploitable. For example
   *     if the tested provider uses windowed exponentiation and the special point is
   *     in the precomputation table then timing differences are easy to spot, but more
   *     difficult to exploit and hence additional experiments would be necessary.
   *
   * @param spec the specification of the curve
   * @param p0 This is a special point. I.e. multiplying this point by mul
   *           may lead to a zero value that may be observable.
   * @param p1 a random point on the curve
   * @param mul an integer, such that multiplying p0 with this value may lead to a timing
   *        difference
   * @param privKeySize the size of the private key in bits
   * @param comment describes the test case
   */
  private void testTiming(ECParameterSpec spec, ECPoint p0, ECPoint p1,
                          BigInteger mul, int privKeySize, String comment) throws Exception {
    ThreadMXBean bean = ManagementFactory.getThreadMXBean();
    if (!bean.isCurrentThreadCpuTimeSupported()) {
      System.out.println("getCurrentThreadCpuTime is not supported. Skipping");
      return;
    }
    SecureRandom random = new SecureRandom();
    int fixedSize = mul.bitLength();
    int missingBits = privKeySize - 2 * fixedSize;
    assertTrue(missingBits > 0);
    // possible values for tests, minCount:
    //   1024,  410
    //   2048,  880
    //   4096, 1845
    //  10000, 4682
    // I.e. these are values, such that doing 'tests' coin flips results in <= minCount heads or
    // tails with a probability smaller than 2^-32.
    //
    // def min_count(n, b=33):
    //   res, sum, k = 1,1,0
    //   bnd = 2**(n-b)
    //   while sum < bnd:
    //     res *= n - k
    //     res //= 1 + k
    //     k += 1
    //     sum += res
    //   return k - 1
    final int tests = 2048;
    final int minCount = 880;
    // the number of measurements done with each point
    final int repetitions = 8;
    // the number of warmup experiments that are ignored
    final int warmup = 8;
    final int sampleSize = warmup + tests;
    KeyFactory kf = KeyFactory.getInstance("EC");
    PublicKey[] publicKeys = new PublicKey[2];
    try {
      publicKeys[0] = kf.generatePublic(new ECPublicKeySpec(p0, spec));
      publicKeys[1] = kf.generatePublic(new ECPublicKeySpec(p1, spec));
    } catch (InvalidKeySpecException ex) {
      // unsupported curve
      return;
    }
    PrivateKey[] privKeys = new PrivateKey[sampleSize];
    for (int i = 0; i < sampleSize; i++) {
      BigInteger m = new BigInteger(missingBits, random);
      m = mul.shiftLeft(missingBits).add(m);
      m = m.shiftLeft(fixedSize).add(mul);
      ECPrivateKeySpec privSpec = new ECPrivateKeySpec(m, spec);
      privKeys[i] = kf.generatePrivate(privSpec);
    }
    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    long[][] timings = new long[2][sampleSize];
    for (int i = 0; i < sampleSize; i++) {
      for (int j = 0; j < 2 * repetitions; j++) {
        // idx determines which key to use.
        int idx = (j ^ i) & 1;
        ka.init(privKeys[i]);
        long start = bean.getCurrentThreadCpuTime();
        ka.doPhase(publicKeys[idx], true);
        byte[] unused = ka.generateSecret();
        long time = bean.getCurrentThreadCpuTime() - start;
        timings[idx][i] += time;
      }
    }
    for (int i = 0; i < sampleSize; i++) {
      for (int j = 0; j < 2; j++) {
        timings[j][i] /= repetitions;
      }
    }
 
    // Performs some statistics.
    boolean noisy = false;  // Set to true, if the timings have a large variance.
    System.out.println("ECDH timing test:" + comment);
    double[] avg = new double[2];
    double[] var = new double[2];
    for (int i = 0; i < 2; i++) {
      double sum = 0.0;
      double sumSqr = 0.0;
      for (int j = warmup; j < sampleSize; j++) {
        double val = (double) timings[i][j];
        sum += val;
        sumSqr += val * val;
      }
      avg[i] = sum / tests;
      var[i] = (sumSqr - avg[i] * sum) / (tests - 1);
      double stdDev = Math.sqrt(var[i]);
      double cv = stdDev / avg[i]; 
      System.out.println("Timing for point " + i + " avg: " + avg[i] + " std dev: " + stdDev
                         + " cv:" + cv);
      // The ratio 0.05 below is a somewhat arbitrary value that tries to determine if the noise
      // is too big to detect even larger timing differences.
      if (cv > 0.05) {
        noisy = true;
      }
    }
    // Paired Z-test:
    // The outcome of this value can be significantly influenced by extreme outliers, such
    // as slow timings because of things like a garbage collection.
    double sigmas = Math.abs(avg[0] - avg[1]) / Math.sqrt((var[0] + var[1]) / tests);
    System.out.println("Sigmas: " + sigmas);

    // Pairwise comparison:
    // this comparison has the property that it compares timings done with the same
    // private key, hence timing differences from using different addition chain sizes
    // are ignored. Extreme outliers should not influence the result a lot, as long as the
    // number of outliers is small.
    int point0Faster = 0;
    int equal = 0;
    for (int i = 0; i < sampleSize; i++) {
      if (timings[0][i] < timings[1][i]) {
        point0Faster += 1;
      } else if (timings[0][i] < timings[1][i]) {
        equal += 1;
      }
    }
    point0Faster += equal / 2;
    System.out.println("Point 0 multiplication is faster: " + point0Faster);
    if (point0Faster < minCount || point0Faster > sampleSize - minCount) {
      fail("Timing differences in ECDH computation detected");
    } else if (noisy) {
      System.out.println("Timing was too noisy to expect results.");
    }
  }

  @SlowTest(providers = 
      {ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE, ProviderType.OPENJDK})
  @Test
  public void testTimingSecp256r1() throws Exception {
    // edge case for projective coordinates
    BigInteger x1 =
        new BigInteger("81bfb55b010b1bdf08b8d9d8590087aa278e28febff3b05632eeff09011c5579", 16);
    BigInteger y1 =
        new BigInteger("732d0e65267ea28b7af8cfcb148936c2af8664cbb4f04e188148a1457400c2a7", 16);
    ECPoint p1 = new ECPoint(x1, y1);
    // random point
    BigInteger x2 =
        new BigInteger("8608e36a91f1fba12e4074972af446176b5608c9c58dc318bd0742754c3dcee7", 16);
    BigInteger y2 =
        new BigInteger("bc2c9ecd44af916ca58d9e3ef1257f698d350ef486eb86137fe69a7375bcc191", 16);
    ECPoint p2 = new ECPoint(x2, y2);
    testTiming(EcUtil.getNistP256Params(), p1, p2, new BigInteger("2"), 256, "secp256r1");
  }

  @SlowTest(providers = 
      {ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE, ProviderType.OPENJDK})
  @Test
  public void testTimingSecp384r1() throws Exception {
    // edge case for projective coordinates
    BigInteger x1 =
        new BigInteger("7a6fadfee03eb09554f2a04fe08300aca88bb3a46e8f6347bace672cfe427698"
                       + "8541cef8dc10536a84580215f5f90a3b", 16);
    BigInteger y1 =
        new BigInteger("6d243d5d9de1cdddd04cbeabdc7a0f6c244391f7cb2d5738fe13c334add4b458"
                       + "5fef61ffd446db33b39402278713ae78", 16);
    ECPoint p1 = new ECPoint(x1, y1);
    // random point
    BigInteger x2 =
        new BigInteger("71f3c57d6a879889e582af2c7c5444b0eb6ba95d88365b21ca9549475273ecdd"
                       + "3930aa0bebbd1cf084e4049667278602", 16);
    BigInteger y2 =
        new BigInteger("9dcbc4d843af8944eb4ba018d369b351a9ea0f7b9e3561df2ee218d54e198f7c"
                       + "837a3abaa41dffd2d2cb771a7599ed9e", 16);
    ECPoint p2 = new ECPoint(x2, y2);
    testTiming(EcUtil.getNistP384Params(), p1, p2, new BigInteger("2"), 384, "secp384r1");
  }

  @SlowTest(providers = 
      {ProviderType.BOUNCY_CASTLE, ProviderType.SPONGY_CASTLE, ProviderType.OPENJDK})
  @Test
  public void testTimingBrainpoolP256r1() throws Exception {
    // edge case for Jacobian and projective coordinates
    BigInteger x1 =
        new BigInteger("79838c22d2b8dc9af2e6cf56f8826dc3dfe10fcb17b6aaaf551ee52bef12f826", 16);
    BigInteger y1 =
        new BigInteger("1e2ed3d453088c8552c6feecf898667bc1e15905002edec6b269feb7bea09d5b", 16);
    ECPoint p1 = new ECPoint(x1, y1);

    // random point
    BigInteger x2 =
        new BigInteger("2720b2e821b2ac8209b573bca755a68821e1e09deb580666702570dd527dd4c1", 16);
    BigInteger y2 =
        new BigInteger("25cdd610243c7e693fad7bd69b43ae3e63e94317c4c6b717d9c8bc3be8c996fb", 16);
    ECPoint p2 = new ECPoint(x2, y2);
    testTiming(EcUtil.getBrainpoolP256r1Params(), p1, p2, new BigInteger("2"), 255,
               "brainpoolP256r1");
  }
}

