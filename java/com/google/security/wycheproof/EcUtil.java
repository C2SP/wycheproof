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

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

/**
 * Some utilities for testing Elliptic curve crypto. This code is for testing only and hasn't been
 * reviewed for production.
 */
public class EcUtil {
  /**
   * Returns the ECParameterSpec for a named curve. Not every provider implements the
   * AlgorithmParameters. For such providers this function constructs the parameter specs for the
   * most popular curves.
   */
  public static ECParameterSpec getCurveSpec(String name)
      throws NoSuchAlgorithmException, InvalidParameterSpecException {
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec(name));
    return parameters.getParameterSpec(ECParameterSpec.class);
  }

  /**
   * Returns a constructed ECParameterSpec for a named curve.
   *
   * <p>If the curve is not known then an ECParameterSpec is constructed for some curves. The
   * selection of the curves that are implemented using explicit parameters is somewhat arbitrary
   * and does not reflect their popularity. Rather the selection was done to achieve somewhat decent
   * test coverage. secp256r1, secp384r1 and secp521r1 were added becuase they are implemented by
   * most providers. secp224r1 has recently been removed from jdk. brainpoolP224r1 and
   * brainpoolP256r1 are curves, where the order is not close to a power of two, hence a bias in the
   * generation of k might be detectable. secp256k1 may have a special case implementation, because
   * this curve is used by bitcoin with modified ECDSA signatures. prime239v1 is the default curve
   * used by BouncyCastle. FRP256v1 has been added simply because it is not popular and hence is one
   * of the curves that likely uses general formulas for the EC computation (assuming it is
   * supported).
   */
  public static ECParameterSpec getCurveSpecConstructed(String name)
      throws NoSuchAlgorithmException, InvalidParameterSpecException {
    try {
      AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
      parameters.init(new ECGenParameterSpec(name));
      return parameters.getParameterSpec(ECParameterSpec.class);
    } catch (NoSuchAlgorithmException | InvalidParameterSpecException ex) {
      // The provider does not support algorithm parameters.
      // Hence the backup parameters are used below.
    }
    switch (name) {
      case "secp224r1":
        return getNistP224Params();
      case "secp256r1":
        return getNistP256Params();
      case "secp384r1":
        return getNistP384Params();
      case "secp521r1":
        return getNistP521Params();
      case "secp256k1":
        return getSecp256k1Params();
      case "brainpoolP224r1":
        return getBrainpoolP224r1Params();
      case "brainpoolP256r1":
        return getBrainpoolP256r1Params();
      case "X9.62 prime239v1":
        return getPrime239v1Params();
      case "FRP256v1":
        return getFRP256v1Params();
      default:
        throw new NoSuchAlgorithmException("Curve not implemented:" + name);
    }
  }

  public static void printParameters(ECParameterSpec spec) {
    System.out.println("cofactor:" + spec.getCofactor());
    EllipticCurve curve = spec.getCurve();
    System.out.println("A:" + curve.getA());
    System.out.println("B:" + curve.getB());
    ECField field = curve.getField();
    System.out.println("field size:" + field.getFieldSize());
    if (field instanceof ECFieldFp) {
      ECFieldFp fp = (ECFieldFp) field;
      System.out.println("P:" + fp.getP());
    }
    ECPoint generator = spec.getGenerator();
    System.out.println("Gx:" + generator.getAffineX());
    System.out.println("Gy:" + generator.getAffineY());
    System.out.println("order:" + spec.getOrder());
  }

  public static ECParameterSpec getNistCurveSpec(
      String decimalP, String decimalN, String hexB, String hexGX, String hexGY) {
    final BigInteger p = new BigInteger(decimalP);
    final BigInteger n = new BigInteger(decimalN);
    final BigInteger three = new BigInteger("3");
    final BigInteger a = p.subtract(three);
    final BigInteger b = new BigInteger(hexB, 16);
    final BigInteger gx = new BigInteger(hexGX, 16);
    final BigInteger gy = new BigInteger(hexGY, 16);
    final int h = 1;
    ECFieldFp fp = new ECFieldFp(p);
    java.security.spec.EllipticCurve curveSpec = new java.security.spec.EllipticCurve(fp, a, b);
    ECPoint g = new ECPoint(gx, gy);
    ECParameterSpec ecSpec = new ECParameterSpec(curveSpec, g, n, h);
    return ecSpec;
  }

  public static ECParameterSpec getNistP224Params() {
    return getNistCurveSpec(
        "26959946667150639794667015087019630673557916260026308143510066298881",
        "26959946667150639794667015087019625940457807714424391721682722368061",
        "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
        "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
        "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34");
  }

  public static ECParameterSpec getNistP256Params() {
    return getNistCurveSpec(
        "115792089210356248762697446949407573530086143415290314195533631308867097853951",
        "115792089210356248762697446949407573529996955224135760342422259061068512044369",
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
  }

  public static ECParameterSpec getNistP384Params() {
    return getNistCurveSpec(
        "3940200619639447921227904010014361380507973927046544666794829340"
            + "4245721771496870329047266088258938001861606973112319",
        "3940200619639447921227904010014361380507973927046544666794690527"
            + "9627659399113263569398956308152294913554433653942643",
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
            + "c656398d8a2ed19d2a85c8edd3ec2aef",
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
            + "5502f25dbf55296c3a545e3872760ab7",
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
            + "0a60b1ce1d7e819d7a431d7c90ea0e5f");
  }

  public static ECParameterSpec getNistP521Params() {
    return getNistCurveSpec(
        "6864797660130609714981900799081393217269435300143305409394463459"
            + "18554318339765605212255964066145455497729631139148085803712198"
            + "7999716643812574028291115057151",
        "6864797660130609714981900799081393217269435300143305409394463459"
            + "18554318339765539424505774633321719753296399637136332111386476"
            + "8612440380340372808892707005449",
        "051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef10"
            + "9e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
        "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3d"
            + "baa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
        "11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e6"
            + "62c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650");
  }

  public static ECParameterSpec getBrainpoolP224r1Params() {
    // name = "brainpoolP224r1",
    // oid = '2b2403030208010105',
    // ref = "RFC 5639",
    BigInteger p = new BigInteger("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF", 16);
    BigInteger a = new BigInteger("68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43", 16);
    BigInteger b = new BigInteger("2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B", 16);
    BigInteger x = new BigInteger("0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D", 16);
    BigInteger y = new BigInteger("58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD", 16);
    BigInteger n = new BigInteger("D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F", 16);
    final int h = 1;
    ECFieldFp fp = new ECFieldFp(p);
    EllipticCurve curve = new EllipticCurve(fp, a, b);
    ECPoint g = new ECPoint(x, y);
    return new ECParameterSpec(curve, g, n, h);
  }

  public static ECParameterSpec getBrainpoolP256r1Params() {
    BigInteger p =
        new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16);
    BigInteger a =
        new BigInteger("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16);
    BigInteger b =
        new BigInteger("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16);
    BigInteger x =
        new BigInteger("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16);
    BigInteger y =
        new BigInteger("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16);
    BigInteger n =
        new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16);
    final int h = 1;
    ECFieldFp fp = new ECFieldFp(p);
    EllipticCurve curve = new EllipticCurve(fp, a, b);
    ECPoint g = new ECPoint(x, y);
    return new ECParameterSpec(curve, g, n, h);
  }

  public static ECParameterSpec getSecp256k1Params() {
    BigInteger p =
        new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    BigInteger a = BigInteger.ZERO;
    BigInteger b = new BigInteger("7", 16);
    BigInteger x =
        new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    BigInteger y =
        new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    BigInteger n =
        new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    final int h = 1;
    ECFieldFp fp = new ECFieldFp(p);
    EllipticCurve curve = new EllipticCurve(fp, a, b);
    ECPoint g = new ECPoint(x, y);
    return new ECParameterSpec(curve, g, n, h);
  }

  /**
   * The curve prime239v1 is defined in X9.62. This curve is used as a default by BouncyCastle in
   * the EC key generation if no curve has been specified. The KeyPairGenerator implemented in
   * org/bouncycastle/jcajce/provider/asymmetric/ec/KeyPairGeneratorSpi.java uses the strength of
   * 239 unless this value is explicitely set.
   */
  public static ECParameterSpec getPrime239v1Params() {
    BigInteger p =
        new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff", 16);
    BigInteger n =
        new BigInteger("7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b", 16);
    BigInteger a =
        new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16);
    BigInteger b =
        new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16);
    BigInteger x =
        new BigInteger("ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf", 16);
    BigInteger y =
        new BigInteger("7debe8e4e90a5dae6e4054ca530ba04654b36818ce226b39fccb7b02f1ae", 16);
    final int h = 1;
    ECFieldFp fp = new ECFieldFp(p);
    EllipticCurve curve = new EllipticCurve(fp, a, b);
    ECPoint g = new ECPoint(x, y);
    return new ECParameterSpec(curve, g, n, h);
  }

  /**
   * FRP256v1 is a rather unknown curve defined in
   * https://www.legifrance.gouv.fr/jorf/id/JORFTEXT000024668816 The curve was added because
   * implementations of this curve have a large chance to use generic EC code, rather than optimized
   * special case code.
   */
  public static ECParameterSpec getFRP256v1Params() {
    BigInteger p =
        new BigInteger("F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03", 16);
    BigInteger a =
        new BigInteger("F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C00", 16);
    BigInteger b =
        new BigInteger("EE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F", 16);
    BigInteger n =
        new BigInteger("F1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1", 16);
    final int h = 1;
    BigInteger x =
        new BigInteger("B6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF", 16);
    BigInteger y =
        new BigInteger("6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB", 16);
    ECFieldFp fp = new ECFieldFp(p);
    EllipticCurve curve = new EllipticCurve(fp, a, b);
    ECPoint g = new ECPoint(x, y);
    return new ECParameterSpec(curve, g, n, h);
  }

  /**
   * Compute the Legendre symbol of x mod p. This implementation is slow. Faster would be the
   * computation for the Jacobi symbol.
   *
   * @param x an integer
   * @param p a prime modulus
   * @returns 1 if x is a quadratic residue, -1 if x is a non-quadratic residue and 0 if x and p are
   *     not coprime.
   * @throws GeneralSecurityException when the computation shows that p is not prime.
   */
  public static int legendre(BigInteger x, BigInteger p) throws GeneralSecurityException {
    BigInteger q = p.subtract(BigInteger.ONE).shiftRight(1);
    BigInteger t = x.modPow(q, p);
    if (t.equals(BigInteger.ONE)) {
      return 1;
    } else if (t.equals(BigInteger.ZERO)) {
      return 0;
    } else if (t.add(BigInteger.ONE).equals(p)) {
      return -1;
    } else {
      throw new GeneralSecurityException("p is not prime");
    }
  }

  /**
   * Computes a modular square root. Timing and exceptions can leak information about the inputs.
   * Therefore this method must only be used in tests.
   *
   * @param x the square
   * @param p the prime modulus
   * @returns a value s such that s^2 mod p == x mod p
   * @throws GeneralSecurityException if the square root could not be found.
   */
  public static BigInteger modSqrt(BigInteger x, BigInteger p) throws GeneralSecurityException {
    if (p.signum() != 1) {
      throw new GeneralSecurityException("p must be positive");
    }
    x = x.mod(p);
    BigInteger squareRoot = null;
    // Special case for x == 0.
    // This check is necessary for Cipolla's algorithm.
    if (x.equals(BigInteger.ZERO)) {
      return x;
    }
    if (p.testBit(0) && p.testBit(1)) {
      // Case p % 4 == 3
      // q = (p + 1) / 4
      BigInteger q = p.add(BigInteger.ONE).shiftRight(2);
      squareRoot = x.modPow(q, p);
    } else if (p.testBit(0) && !p.testBit(1)) {
      // Case p % 4 == 1
      // For this case we use Cipolla's algorithm.
      // This alogorithm is preferrable to Tonelli-Shanks for primes p where p-1 is divisible by
      // a large power of 2, which is a frequent choice since it simplifies modular reduction.
      BigInteger a = BigInteger.ONE;
      BigInteger d = null;
      while (true) {
        d = a.multiply(a).subtract(x).mod(p);
        // Computes the Legendre symbol. Using the Jacobi symbol would be a faster. Using Legendre
        // has the advantage, that it detects a non prime p with high probability.
        // On the other hand if p = q^2 then the Jacobi (d/p)==1 for almost all d's and thus
        // using the Jacobi symbol here can result in an endless loop with invalid inputs.
        int t = legendre(d, p);
        if (t == -1) {
          break;
        } else {
          a = a.add(BigInteger.ONE);
        }
      }
      // Since d = a^2 - n is a non-residue modulo p, we have
      //   a - sqrt(d) == (a+sqrt(d))^p (mod p),
      // and hence
      //   n == (a + sqrt(d))(a - sqrt(d) == (a+sqrt(d))^(p+1) (mod p).
      // Thus if n is square then (a+sqrt(d))^((p+1)/2) (mod p) is a square root of n.
      BigInteger q = p.add(BigInteger.ONE).shiftRight(1);
      BigInteger u = a;
      BigInteger v = BigInteger.ONE;
      for (int bit = q.bitLength() - 2; bit >= 0; bit--) {
        // Compute (u + v sqrt(d))^2
        BigInteger tmp = u.multiply(v);
        u = u.multiply(u).add(v.multiply(v).mod(p).multiply(d)).mod(p);
        v = tmp.add(tmp).mod(p);
        if (q.testBit(bit)) {
          tmp = u.multiply(a).add(v.multiply(d)).mod(p);
          v = a.multiply(v).add(u).mod(p);
          u = tmp;
        }
      }
      squareRoot = u;
    }
    // The methods used to compute the square root only guarantee a correct result if the
    // preconditions (i.e. p prime and x is a square) are satisfied. Otherwise the value is
    // undefined. Hence, it is important to verify that squareRoot is indeed a square root.
    if (squareRoot != null && squareRoot.multiply(squareRoot).mod(p).compareTo(x) != 0) {
      throw new GeneralSecurityException("Could not find square root");
    }
    return squareRoot;
  }

  /**
   * Returns the modulus of the field used by the curve specified in ecParams.
   *
   * @param curve must be a prime order elliptic curve
   * @return the order of the finite field over which curve is defined.
   */
  public static BigInteger getModulus(EllipticCurve curve) throws GeneralSecurityException {
    java.security.spec.ECField field = curve.getField();
    if (field instanceof java.security.spec.ECFieldFp) {
      return ((java.security.spec.ECFieldFp) field).getP();
    } else {
      throw new GeneralSecurityException("Only curves over prime order fields are supported");
    }
  }

  /**
   * Returns the size of an element of the field over which the curve is defined.
   *
   * @param curve must be a prime order elliptic curve
   * @return the size of an element in bits
   */
  public static int fieldSizeInBits(EllipticCurve curve) {
    return curve.getField().getFieldSize();
  }

  /**
   * Returns the size of an element of the field over which the curve is defined.
   *
   * @param curve must be a prime order elliptic curve
   * @return the size of an element in bytes.
   */
  public static int fieldSizeInBytes(EllipticCurve curve) {
    return (fieldSizeInBits(curve) + 7) / 8;
  }

  /**
   * Checks that a point is on a given elliptic curve. This method implements the partial public key
   * validation routine from Section 5.6.2.6 of NIST SP 800-56A
   * http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf A partial
   * public key validation is sufficient for curves with cofactor 1. See Section B.3 of
   * http://www.nsa.gov/ia/_files/SuiteB_Implementer_G-113808.pdf The point validations above are
   * taken from recommendations for ECDH, because parameter checks in ECDH are much more important
   * than for the case of ECDSA. Performing this test for ECDSA keys is mainly a sanity check.
   *
   * @param point the point that needs verification
   * @param ec the elliptic curve. This must be a curve over a prime order field.
   * @throws GeneralSecurityException if the field is binary or if the point is not on the curve.
   */
  public static void checkPointOnCurve(ECPoint point, EllipticCurve ec)
      throws GeneralSecurityException {
    BigInteger p = getModulus(ec);
    BigInteger x = point.getAffineX();
    BigInteger y = point.getAffineY();
    if (x == null || y == null) {
      throw new GeneralSecurityException("point is at infinity");
    }
    // Check 0 <= x < p and 0 <= y < p.
    if (x.signum() == -1 || x.compareTo(p) >= 0) {
      throw new GeneralSecurityException("x is out of range");
    }
    if (y.signum() == -1 || y.compareTo(p) >= 0) {
      throw new GeneralSecurityException("y is out of range");
    }
    // Check y^2 == x^3 + a x + b (mod p)
    BigInteger lhs = y.multiply(y).mod(p);
    BigInteger rhs = x.multiply(x).add(ec.getA()).multiply(x).add(ec.getB()).mod(p);
    if (!lhs.equals(rhs)) {
      throw new GeneralSecurityException("Point is not on curve");
    }
  }

  /**
   * Checks a public key. I.e. this checks that the point defining the public key is on the curve.
   *
   * @param key must be a key defined over a curve using a prime order field.
   * @throws GeneralSecurityException if the key is not valid.
   */
  public static void checkPublicKey(ECPublicKey key) throws GeneralSecurityException {
    checkPointOnCurve(key.getW(), key.getParams().getCurve());
  }

  /**
   * Decompress a point
   *
   * @param x The x-coordinate of the point
   * @param bit0 true if the least significant bit of y is set.
   * @param ecParams contains the curve of the point. This must be over a prime order field.
   */
  public static ECPoint getPoint(BigInteger x, boolean bit0, ECParameterSpec ecParams)
      throws GeneralSecurityException {
    EllipticCurve ec = ecParams.getCurve();
    ECField field = ec.getField();
    if (!(field instanceof ECFieldFp)) {
      throw new GeneralSecurityException("Only curves over prime order fields are supported");
    }
    BigInteger p = ((java.security.spec.ECFieldFp) field).getP();
    if (x.signum() <= 0 || x.compareTo(p) >= 0) {
      throw new GeneralSecurityException("x is out of range");
    }
    // Compute rhs == x^3 + a x + b (mod p)
    BigInteger rhs = x.multiply(x).add(ec.getA()).multiply(x).add(ec.getB()).mod(p);
    BigInteger y = modSqrt(rhs, p);
    if (bit0 != y.testBit(0)) {
      y = p.subtract(y).mod(p);
    }
    return new ECPoint(x, y);
  }

  /**
   * Decompress a point on an elliptic curve.
   *
   * @param bytes The compressed point. Its representation is z || x where z is 2+lsb(y) and x is
   *     using a unsigned fixed length big-endian representation.
   * @param ecParams the specification of the curve. Only Weierstrass curves over prime order fields
   *     are implemented.
   */
  public static ECPoint decompressPoint(byte[] bytes, ECParameterSpec ecParams)
      throws GeneralSecurityException {
    EllipticCurve ec = ecParams.getCurve();
    ECField field = ec.getField();
    if (!(field instanceof ECFieldFp)) {
      throw new GeneralSecurityException("Only curves over prime order fields are supported");
    }
    BigInteger p = ((java.security.spec.ECFieldFp) field).getP();
    int expectedLength = 1 + (p.bitLength() + 7) / 8;
    if (bytes.length != expectedLength) {
      throw new GeneralSecurityException("compressed point has wrong length");
    }
    boolean lsb;
    switch (bytes[0]) {
      case 2:
        lsb = false;
        break;
      case 3:
        lsb = true;
        break;
      default:
        throw new GeneralSecurityException("Invalid format");
    }
    BigInteger x = new BigInteger(1, Arrays.copyOfRange(bytes, 1, bytes.length));
    if (x.signum() <= 0 || x.compareTo(p) >= 0) {
      throw new GeneralSecurityException("x is out of range");
    }
    // Compute rhs == x^3 + a x + b (mod p)
    BigInteger rhs = x.multiply(x).add(ec.getA()).multiply(x).add(ec.getB()).mod(p);
    BigInteger y = modSqrt(rhs, p);
    if (lsb != y.testBit(0)) {
      y = p.subtract(y).mod(p);
    }
    return new ECPoint(x, y);
  }

  /**
   * Returns a weak public key of order 3 such that the public key point is on the curve specified
   * in ecParams. This method is used to check ECC implementations for missing step in the
   * verification of the public key. E.g. implementations of ECDH must verify that the public key
   * contains a point on the curve as well as public and secret key are using the same curve.
   *
   * @param ecParams the parameters of the key to attack. This must be a curve in Weierstrass form
   *     over a prime order field.
   * @return a weak EC group with a genrator of order 3.
   */
  public static ECPublicKeySpec getWeakPublicKey(ECParameterSpec ecParams)
      throws GeneralSecurityException {
    EllipticCurve curve = ecParams.getCurve();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    BigInteger p = getModulus(curve);
    BigInteger three = new BigInteger("3");
    while (true) {
      // Generate a point on the original curve
      KeyPair keyPair = keyGen.generateKeyPair();
      ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
      ECPoint w = pub.getW();
      BigInteger x = w.getAffineX();
      BigInteger y = w.getAffineY();
      // Find the curve parameters a,b such that 3*w = infinity.
      // This is the case if the following equations are satisfied:
      //    3x == l^2 (mod p)
      //    l == (3x^2 + a) / 2*y (mod p)
      //    y^2 == x^3 + ax + b (mod p)
      BigInteger l;
      try {
        l = modSqrt(x.multiply(three), p);
      } catch (GeneralSecurityException ex) {
        continue;
      }
      BigInteger xSqr = x.multiply(x).mod(p);
      BigInteger a = l.multiply(y.add(y)).subtract(xSqr.multiply(three)).mod(p);
      BigInteger b = y.multiply(y).subtract(x.multiply(xSqr.add(a))).mod(p);
      EllipticCurve newCurve = new EllipticCurve(curve.getField(), a, b);
      // Just a sanity check.
      checkPointOnCurve(w, newCurve);
      // Cofactor and order are of course wrong.
      ECParameterSpec spec = new ECParameterSpec(newCurve, w, p, 1);
      return new ECPublicKeySpec(w, spec);
    }
  }
}
