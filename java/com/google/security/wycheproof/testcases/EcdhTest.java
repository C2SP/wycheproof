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
import static org.junit.Assert.fail;

import com.google.security.wycheproof.WycheproofRunner.NoPresubmitTest;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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

  /** ECDH test vectors */
  public static class EcdhTestVector {
    final String curvename;
    final String pub; // hexadecimal representation of the X509 encoding
    final BigInteger s; // private key
    final String shared; // hexadecimal representation of the shared secret

    public EcdhTestVector(String curvename, String pub, BigInteger s, String shared) {
      this.curvename = curvename;
      this.pub = pub;
      this.s = s;
      this.shared = shared;
    }

    public ECPublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
      KeyFactory kf = KeyFactory.getInstance("EC");
      byte[] encoded = TestUtil.hexToBytes(pub);
      return (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));
    }

    public ECPrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
      KeyFactory kf = KeyFactory.getInstance("EC");
      ECPrivateKeySpec spec = new ECPrivateKeySpec(s, EcUtil.getCurveSpecRef(curvename));
      return (ECPrivateKey) kf.generatePrivate(spec);
    }
  }

public static final EcdhTestVector[] ECDH_TEST_VECTORS = {
      // normal case
      new EcdhTestVector(
          "secp224r1",
          "304e301006072a8648ce3d020106052b81040021033a0004ede01a8a47b08cfa"
              + "b5f09382a44d09ff41e1ea10398a05b06f135024a9a68b71bfa0d258aeacec39"
              + "295ffc0700963da427d5239bc8d729a7",
          new BigInteger("66129e5f5f0020ef0b73a71a842807e25ae78609ea4bb46d365ed0df", 16),
          "b08501b65b3abfe01d98ee9336ca161957c7a25d7ff4e5666db3d6fb"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d0301070342000437bafd59f3"
              + "981a01d0a65ffb344ffdad6241e0df7ea6e0a0ba7df2dd2132f755b5c25e8a79"
              + "5aba52fd8302f3e39eed094cc676a28f29289ef6ab8493d454c03e",
          new BigInteger("5456fee42720eacbd17c1180d7bd6a089214166772181601451304512756b23b", 16),
          "edd951357c507199907847e1ba8d8f88a235e9818665b11feb3d4ae9a9a8e031"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b81040022036200042350c589ce86d99e"
              + "6de2692526f22bc1907cec4823cf114c6b8aa1c03e436430cfbe38a517816cc7"
              + "e1a98e032ea724a3b2e4ddff894f09cab9d396a853f82d4ddccb854f2ae3dc73"
              + "fb09934a3c65c18595e415654a70f7d00e8d8299e28fa169",
          new BigInteger("0c36c4fa76e4c93da419bc21656f972de470f4b1c028e0d5d068b6326f16b484"
                  + "e248fb722c06c8ca3badd1aee201ae5bd", 16),
          "4f6a59053a5ddc77d01fef51eb35bbb7194e89761b9c2e741b6d872b753feb58"
              + "3caa35eb444469082153fd21ba607c2b"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000400a4c85dc9bf"
              + "91c738450cc7a1c45ad544019cb92d13d010789fd682678b49b9f896d9138905"
              + "e1e28e6e7331ef3ca96a5724adbc6d290359e7e11300f707becf7c0c00bf0bd0"
              + "4da7e423fcd767f72d86983e0de5b93df1f037d7b5f53e69a696cab9c07e1a7c"
              + "6890d357951f88b90e811022962cb863b1c9cc7d9e9263c1f3d61d84d53d",
          new BigInteger("78bed2e5d1045588f2e254987b04c804d2cd43fe5ce09df34749e3b6825a1433"
                  + "38b30e8a8622e16edf22c54820f822722014d52fdf81349d4d5d4904311b893e"
                  + "f2", 16),
          "0134ef7a412c1edc9fa2b887427fe1e228252519acab9513c0bf2899ad26cbf6"
              + "7e62abff411d5b8aafc2da6cb4c7f2fbb83276e03749c39d6f6182634a0dfa64"
              + "dd36"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b2403030208010107034200048c8546bb"
              + "344a1b7dc42958e1d5fba13fe154ba1e1478871f99e7b4ac7aaac8b310425744"
              + "70f9096cd2d8f0eea4d0a7359a289ec3af86c221c3147d40dc84a0e0",
          new BigInteger("6f17d95bf371d6b10ebe652a1bbf91226be7425864964d18596bb1962acaa3a2", 16),
          "7a3ad1cc9d56410f7330a7e29364fad0a56ccbd3eb7e24683b32ea3fed8065bf"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b24030302080101090352000474a94a38"
              + "65c91135dd5f7de1d81feeeecc8844084ed3d7869ec32454a90ef4c94ba7c264"
              + "21faf81167e316a02b6d7e1ea1ace06cf7dab874300f8ea1cc8a8942402121d0"
              + "032809d02c932345e54981a5",
          new BigInteger("09e82121ce67a569641cda1208f58af4299d0da2a8f4e7d34ad82a6f8d657af5"
                  + "7aa6fa14117a1426", 16),
          "39088f92717317452e7b3b9fbb4c6fd9376b8708a710ede7f39fda81b64d5b7a"
              + "5ee5b9ef418600e1"),
      new EcdhTestVector(
          "brainpoolP384r1",
          "307a301406072a8648ce3d020106092b240303020801010b03620004477991ce"
              + "713b03bdaaf884bac354f46824feb76464eb4192af0a30938f62ec3e7740a448"
              + "e835dbd31980068f2d65b2a803531c3e2dd56d23987ff181e10d758d6ab18658"
              + "79ee4f9ecab7613bbe89089bb4cf9c812a98fa86c53fbcda879e9952",
          new BigInteger("3f633364b9d90bd70df187a48f054267ab6f511d4211a4ab927d5a13fc642553"
                  + "04a282e81a059b59b13da7e6681367bb", 16),
          "3db41a0846b8c1e87f5a7d1b6dd4ba0e5eeba354c4dd4d3ccfcf83263d4ed225"
              + "898f7d26016c184db04bff69a47d4e7e"),
      new EcdhTestVector(
          "brainpoolP512r1",
          "30819b301406072a8648ce3d020106092b240303020801010d038182000492be"
              + "ce2a6b584fd7d605608dd48c0cee71a9126755e9fd997c79b5cfb2ce3893941d"
              + "f056ddcdbfc377ef878f6e4985890c87271e93834fffc539684d2d4ad7ab223d"
              + "15ba7f2c77831cb027f1b91a05bceceec54ffad09b48b7aaab4934b2aec296b9"
              + "6672ece4aa26ae84d77dfc75d037ae66c803fa0f385b8ea5891dcd8beb64",
          new BigInteger("0dd055dcb0716072b3770afea2558aaf7604ad4cd46309d4773112eb07971bbe"
                  + "2f52a4c7dcd77ba459da2e3e1b81de7d275d8471c4576a4fad8d39d497427cf2", 16),
          "56befa424107477a441d9f220bc201b0922aa690319e0352403b41f93693632f"
              + "0a42c22695084e34a22258fb82405707d77fbc7a65d69fc3b2f0ff7964b88e11"),
      // edge cases for shared secret
      new EcdhTestVector(
          "secp224r1",
          "304e301006072a8648ce3d020106052b81040021033a000481580f0e1948c6cb"
              + "0d783aef31f7aa1453127fd5e9015787c21dc6e7b05823679cdf1f5f27fbb35a"
              + "1316f90c6ee6f1a830aff4cc079d7147",
          new BigInteger("0ef75a840917c5d6588481f54f72651d5ab682a27ed5e089dabcfeb4b", 16),
          "0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff"),
      new EcdhTestVector(
          "secp224r1",
          "304e301006072a8648ce3d020106052b81040021033a0004fbb1895eb32d264d"
              + "02fdd8ff69660c3b2d92ead2d73f83f0b822c3a7e3921eaff67f3885ff3a9e1f"
              + "599f88a905f3332ea265168b8e3959ee",
          new BigInteger("767410316e2bfaf819eaba53d9afc6389af3b3980aaeb6084d2cb42a", 16),
          "0003fffffff00000003fffffff00000003fffffff000000040000000"),
      new EcdhTestVector(
          "secp224r1",
          "304e301006072a8648ce3d020106052b81040021033a00044afaf873c68305e8"
              + "c59ae2bb35fcddf52445409e3de3e89ac5b4a85f3b19d5d2413d0ed6bbfb8a29"
              + "94e45233e9ccfbe6d19ae0fbd3fefecb",
          new BigInteger("08c082c5c024a049c638c0063056a9de4f1705a043d8903b21cc3fa57", 16),
          "01fffffffc00000007fffffff00000001fffffffc000000080000001"),
      new EcdhTestVector(
          "secp224r1",
          "304e301006072a8648ce3d020106052b81040021033a0004592cfacda94e179d"
              + "2fef452840fd9089c2635a2828d795c5e5e654db8b3235e150c7332614724505"
              + "732b3d43fdb24df59441f3a63324221c",
          new BigInteger("0df67dafb58c8bbea8cd3d6f101fd8d63e37b2d27f47378b23b79e8f1", 16),
          "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
      new EcdhTestVector(
          "secp224r1",
          "304e301006072a8648ce3d020106052b81040021033a00043ac084145783884d"
              + "6e6183b3024fc224ec0acceea314c1632876481c1cdf50dc03c360876df00bb6"
              + "e9798925548bbd6b9ee03903e4a856ba",
          new BigInteger("0b50ce76e695c37b2007edc24a2b284b327d39c48d891de7e40d481ec", 16),
          "fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0008001"),
      new EcdhTestVector(
          "secp224r1",
          "304e301006072a8648ce3d020106052b81040021033a0004aac5583c79a61c57"
              + "677497c7e69cd0a5a0e4649ec5eb7548ed12e08f4ca2e89e3a9a01ba7465cdd0"
              + "1eecf863b205a325d20c7c6326ee710f",
          new BigInteger("4d5d5810d1256528e330b6f8d2b2a934acf67b1c26b4588632078ea1", 16),
          "ffffffff00000000ffffffff00000000ffffffff00000000ffffffff"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d03010703420004fc933db19a"
              + "709f7428659e5fd92a44f6ca74b02f354c1524cd31eb02c0c3978f6c06947a10"
              + "48fde5d5ae530cec3af2425c95be31beb716f316c8742947305257",
          new BigInteger("408c07f785e05bc95675d0c67f82dbdf6b1cdd70cf69c29663d8ed1d2ecc7766", 16),
          "0000000000000000000000000000000000000000000000000000000000000000"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d030107034200042d8af9b4bf"
              + "95f23eef7d6a58ae122667c743c587ef0a83d1bd6429c228a6d360093def5202"
              + "28caba718f4507bd17b67786f112b9e849be71df86197ae63d4656",
          new BigInteger("3da0fcb37ce9cb90b8ecc283be909e4e26a546933f59f37a0172d4c0143b1023", 16),
          "00000000ffffffff00000000ffffffff00000000ffffffff0000000100000000"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d03010703420004a5d41b1161"
              + "5645ffccd3e70cabc57d2171ffbb9a6191e257689ebe44ef3b674db01ddd1bd1"
              + "60ece0c2d4420169099a403f273953ab494e59733b4e96b100404a",
          new BigInteger("7821d977e4b7b91a6a41b37819968c5185b0e10c5f02816b0fd9ae93981e88d7", 16),
          "0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff00010001"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d030107034200042e367b7d01"
              + "67214506d5b0e345b9df44cc9ac2c12374fffa146659815c562345c4162ffebc"
              + "91c7b9251b8e9f081cdd2f07a813f707b9f39e52b9a90dff94367e",
          new BigInteger("0cf80de9a104c55e263c105757248942f276bbc6e3f901f49191bfc7c10996dd1", 16),
          "7fff0001fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0007fff"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d03010703420004ce160aa0f5"
              + "b30945ff110aed4bb1db01fa2a13850db9e7d4b7e03d290680c061fd3edf4e12"
              + "2bec0147238822e11fbf1c22ebe05a914efc2e6f1f45705a034f8d",
          new BigInteger("655717199b5287de8e281ed157edba8e23a7416dd0317981aedfbb0c6dc0485c", 16),
          "8000000000000000000000000000000000000000000000000000000000000004"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d030107034200048e84800f8b"
              + "c418ed64cee6d1d73221386a6335491403f0b7244fbfef7274e111e39834c716"
              + "5de65e9f3dc32722bd8c5fa9e15aa35fe791022b4217038dddb67e",
          new BigInteger("466cc6d79dd089a44aee650739265d25c123f5a3ec840f6894f1b555e336df6e", 16),
          "ff00000001fffffffc00000007fffffff00000001fffffffc00000007fffffff"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d0301070342000413608e8b53"
              + "7a24815cbab85e6f3c9cc150985fc02b0c11e7b8d10969c7ec75ed7ba696ebfa"
              + "90f72c0183ebf5addf7924107d418ecd2d823d35a792e440354030",
          new BigInteger("2b1541701e9e1f76c841942fe131b19a7ec84117249a8223fe77c50e706ebfd5", 16),
          "ffff00000003fffffff00000003fffffff00000003fffffff00000003fffffff"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b8104002203620004c4cea9aa62a401b3"
              + "770e1ce475ef975430d579fc69b576074d4af6feec995ae7ef01ab3c231e37e3"
              + "9a3a490d6f6d9fc019ecd273860cf81f57ef2a8cc2d12af404bd5e4228a77556"
              + "ea3a327bdb46abcd315143d0d859640d8e1b55f9b5e33237",
          new BigInteger("0a6d86fea4069bf28161c0b1f6e0f542ee3f5347a2fdf702c58bd770bc727776"
                  + "5b5713b4f2c67a73e7731188dfb277c6d", 16),
          "0000000000000000000000000000000000000000000000000000000000000000"
              + "00000000000000000000000000000000"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b81040022036200046150defd7ece8903"
              + "07a16a4bf2fe004c065ffb7bad5accb620346f39d3a2ab7b6c872580dcd4860c"
              + "80ab9b16a05cfb6e6f9990cf74183dc8533f067c572633a231b4cc34ddde3f1d"
              + "ab01855b819a9969b6d286961449a81f2c5ffe0799f8f4d5",
          new BigInteger("0e2103cec6ffb44963a8588b02e9204579c70fc5bee437f00f146709a535306c"
                  + "5d21978677d26216cc32520c487ac8444", 16),
          "0000000000000000000000000000000000000000000000000000000000000000"
              + "00000000000000000000000000000002"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b8104002203620004730ee9b91512458a"
              + "a27e6b79fc44e3fc5ae0f4d1cfa19bb457a92f0a0dd6112faa5bbb8a94b96e97"
              + "7882e92e40487819901f5d9049fb413dbf55ba03b3a179098e1888f306f4c91d"
              + "4e63d2c51db983e8a15dd55c2556a7641a6ab6df54dd4cc4",
          new BigInteger("7688859c38fda9a4426a34b3383617a83604926c6af1134d8c08c6c6bf4a4b1b"
                  + "900ffb0c48163f2fc025291a3b77ccbe", 16),
          "00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff"
              + "00000000ffffffff00000000ffffffff"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b8104002203620004f9693073900322e5"
              + "1eaf56dafdb91485a673401247dfcba87f7eb740f908d7d05bd7a2b78882c4c6"
              + "9a2b33053f4704b1adf20cceaddf13d5cf42d084c4f2aea276f9d96e09eb57c4"
              + "adc5af6e348874bba825f0ead0e77137edc82825b7c02aec",
          new BigInteger("08e75f011ddf5df3720a16ee94098e1718f76c4a7fa80d6148bf4637918edc96"
                  + "7cbcf77a5523ad0823793ed3598ad716e", 16),
          "0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff"
              + "0000ffff0000ffff0000ffff0000ffff"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b81040022036200044418efb8a34156d8"
              + "9ade5833f9718aadebf107aee933eaf5aec3a67e68626ce3200beae2c45c9647"
              + "064be66b16201e39cf408605782eb1ed11353545da2c0fcadc3973bb1afeee89"
              + "faf1f17fb3804281f704aab4785281e48810b719723a4ebd",
          new BigInteger("0e01e507817ff8639a928ef97a2f4ddf99aeae4d84797ffc1ee915cd497af6c5"
                  + "103cd222eaa3f73957156ab3e90a8edd8", 16),
          "007fff0001fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0007f"
              + "ff0001fffc0007fff0001fffc0008000"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b8104002203620004c78a77b0b1f2efde"
              + "36cb77ddf01404c9c899f861ef407e793467dc1369efdc552a004244929afcff"
              + "5a2142119b2f74e29d61ff9175be46e98612b805062a1d9d93beeb0090518f7a"
              + "3a3bf9581c0aea1a85dbbbe1a088eb12fdad401cfe323736",
          new BigInteger("43f7f19cf19c357c4f13ce5dec61621f60483f86f6c0e7710801a76c61d59ab9"
                  + "2670af388685c54670a44455d978936d", 16),
          "8000000000000000000000000000000000000000000000000000000000000000"
              + "00000000000000000000000000000002"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b8104002203620004c92457e87b8cfbfb"
              + "f171461c9377618099a4654d59e46c5ae057fa974c9f82867484520a69832676"
              + "f030d3c16617cc864c2a5c94bfff52d16192a971a867a7dbd8005d42788440a3"
              + "0b0132006d14e3590d2b6c00c58ded46582d34dd7697eea4",
          new BigInteger("7f827b6a7d3e6f86dedd4c97b0306d0b3707fe0126ad54a03a7ba2b907feb2a9"
                  + "ce36ad2baa3eb6a7f88f157abd85ab9e", 16),
          "fff00000001fffffffc00000007fffffff00000001fffffffc00000007ffffff"
              + "f00000001fffffffc00000007fffffff"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b8104002203620004b475c6e55a4544a5"
              + "77b67eec7d442cfdad0f286768dbe0e83200c5b50c33be24890133ea054c8fb7"
              + "6ef46f4a1970a910e70251faf7b2678f57a455da24ef14d3c59131359acb90ce"
              + "14752746259a930dac1c3387061d7778ba78a89a58c0dd8f",
          new BigInteger("567d19cf1ec2cbf168d6a22532d61627623f216dab27f1869f94041ac86367c4"
                  + "fc34ab50fa950d092d2df20ed797cbfa", 16),
          "ffffff00000003fffffff00000003fffffff00000003fffffff00000003fffff"
              + "ff00000003fffffff00000003fffffff"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b810400220362000407f1d0e85c26e4b3"
              + "d96b0aa26a75eac049cd15f5c8aebb0e68c553edd41b28183e577bb716cdf68d"
              + "fb4f1c4c9e4bca9423306f54fce15401b587d0a78a74691df1f9f99fa3fbf049"
              + "10405ec2daa5189c9f5ea5dfc7dabaf19e229bdc184ef053",
          new BigInteger("0fb8ca434327c081c30cca21f6e623eccadf5f9ef78f461731cf7d05bf10dfd0"
                  + "97f8bb87d9db2b03a7af7e8a452ddfe77", 16),
          "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
              + "ffffffff0000000000000000fffffffe"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b810400230381860004015e99e4275e"
              + "7fb1e61aa735edf2a9cb11894a0d59a6beea4978a45cbd03950a0fd280d70e6c"
              + "ff3c3ba679a787bdb5fd8796aaf3bc9ac64d4752b04ebce1d115b92d01ae1c7b"
              + "b514014978c2ef7b7f337dbcabea7be6e577e1a9a1162f5c18c742b28d152d7c"
              + "fd6f5d37ac1205b14bfa7363b35f01d82c3764859a9279397ca58e2c6645",
          new BigInteger("0b452ff8f582b40ce7e63903a7a68dbefe489cfbff912465bc3c4844332e089c"
                  + "fa730f80eb5013a273f576d1656e973c2d0190dc76b4f3eefeaa3fa2236a184b"
                  + "ff8", 16),
          "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b810400230381860004017d2f35bf67"
              + "1967e026c27fa91d970c95491d541683fcf4b784292a27a6c9b504b7cd5d231a"
              + "7ec1775436a3591bea76bb089e16f9d83be29abdc4494702ae0a0a91010ce15f"
              + "f38dffa5b5fba0a1a5a1865d72524d9e6a93bb21a215f3c438722246d8132ba8"
              + "856969587541e593380ae1a477dcfc19b2a519df2e71a45b0f48d00f6502",
          new BigInteger("13c36dccb60ec1bd7a26a42ea57b9ef17619450d8e27f117fd4c56d73e2304f2"
                  + "0d44bd658a3f5d9c4bf0c6ad2e06c26b1e2f54ff88484df7d312495791f098ec"
                  + "367", 16),
          "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "0001"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000400a6887b6967"
              + "ba24669436d6e9c64a436389e7b306a107b213e658dc2392a8d76c418f653f1c"
              + "ceff4035c08bab5eb59064f458e4603b7ffe3cbb67d4e853bc44878500dd076e"
              + "e41c9f43f76d5fc6132b9132ceaeab9ed6d13dfe93ba11690f284ca30740c20e"
              + "864c846a36ddcbc6a0ef0546809f2e2ac95d93824e69a137e398b0132846",
          new BigInteger("16a6259942027c122855042467bca1146ed5adfcb62f80a1cac9c57e2d76a580"
                  + "175aa1d93491f0a6243c5ad84d247bdd42a1dd876db72fbaa0722ee769127ea7"
                  + "591", 16),
          "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "0002"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b8104002303818600040001efcda938"
              + "de5b0141c52a90cd14a15518b1f2a44867a867b8c833b9e8b368c2dcb9a0bd01"
              + "4133313b6b06be2152e7c1a8769468828a716b344b2702c328fd7f1701de36c1"
              + "d49a94a1c7a60e38af4e1fb2098c3f9b92e99ae935ee1f9cec6fbedaac2d2227"
              + "1c77796852e42dca2f601a26cd27bfa7c616cda8837b44933d6287ed2fbc",
          new BigInteger("1d03ece086a531f82916d29cc40cbbca8be84b181c24bbde942b1092f352f6db"
                  + "aca1991dca14ead801d1c5cc6348be5f8ca7d5d901b8bbea29e1abdd2b470cbf"
                  + "515", 16),
          "00003fffffff00000003fffffff00000003fffffff00000003fffffff0000000"
              + "3fffffff00000003fffffff00000003fffffff00000003fffffff00000003fff"
              + "ffff"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000400b6c397a25b"
              + "670e2c0ee1ef2a6298f35beec330e097fa3b8590d97aa99dd968a22395360c4e"
              + "0bb0813450a4771cf3a8eed54a124119eb154c53216042f2709770c201299201"
              + "ec5c5cbf768fd9cf0f2bda2c353a2439739b96c75b13dfa2036f6eaec20d65c8"
              + "139c009fc455f545ca269acd02e2745d5e086c860b2637f75144cb7d044e",
          new BigInteger("1eb34a1fa19633b82c3fe7c9f17cc583a6e602515cbd1aebfc62c5aa7d31b84b"
                  + "3ed3bf6013d50434157143ae086fd377ee28440d72cf5053e518ba1bbb9d491f"
                  + "c0", 16),
          "0100000000000000000000000000000000000000000000000000000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000400aa40d5df13"
              + "1a2bcb032fbabaa3c29a917d160fe812e5db9e2330796f0470af0e21aaa03871"
              + "a053dc9f71c51d3f7fa16ac02953692ff1b7f334f163c3331ea333ca00d2fc91"
              + "97ffa6696ed286cabc0dd51b3d16ce82e1fb7f04c01b5801485aa34a29a999a2"
              + "713be5570f80cd3c7153b1c0d16d93b7d89eba86818fa622622873a19f36",
          new BigInteger("1777f42a4677dc68864b6d606c3b7738dc5539853d79290364f4340ce50b8ba1"
                  + "7f7286e7f2778d992102f1e2eb3a3c11f89b335e15cb39f23193381c19a1d34c"
                  + "de2", 16),
          "01ff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffff"
              + "ffff00000000ffffffff00000000ffffffff00000000ffffffff00000000ffff"
              + "ffff"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b810400230381860004002149666876"
              + "9fdce5a2a1e703b3f8fc5f75b4f8fe90fb65acf2d24f40060b2b7d3f7f01f3f4"
              + "8131278a33358c4697d78478e0e71bb2cf3c98cf7b9600b39807315600ad0d17"
              + "01d62f4c51d363ef0da8327ee0e0446071066ecc3187c6fcf7f3e4901f8d1370"
              + "81d6036e93e51d1862e744dfeff9e3590351b0bb6cc200803c802cceb3f0",
          new BigInteger("0cfe4a5076b9b4d3375fe5d1887e4dfffa0985f86c96dadd50ffc1615787c35c"
                  + "a631b3ca041e6179648acb236035a68471a3fdd2989e6dacaa95bd91e0b84c73"
                  + "e1c", 16),
          "01ff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000"
              + "ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0001"
              + "0000"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b8104002303818600040067c03a18a9"
              + "f861651c7d1f0d1d562a1a61ff73c2fb51242009bac64ffbabdb0b209cb979ff"
              + "f57bf2204e1dd511ce4ea72d9d065144fe274b32e1555d952773e7cd01cc6e46"
              + "6f3add113f6d819f2b83f9909eaa68b288b0f2087c3dc781edbabbd4bad03572"
              + "944e995db00efa2f322a554434f811120e5de9dcdb8e04792cc7562ed676",
          new BigInteger("188cb47d2210832bd6850c9f7af49a3e9e89377a96ee1d2a73529fb6a8a7a903"
                  + "929d88bfb4918c9c457a9a2f47febaf12921d0a1d047f4d1f7717613ef3df43d"
                  + "728", 16),
          "01ffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0007fff0001fff"
              + "c0007fff0001fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc000"
              + "7fff"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000400e68a351c0c"
              + "a122ae9ddcdc67792a6602dfb8058467adb53099292048d04e91d43779c1c429"
              + "47cd1907b902b1d242b3277a241040fd60a3b14a28f4b9c5e59de7bc017e12ec"
              + "1118a2f198e139e1a2ac18e6fc8136b429c40115e3523e0d2bbefa4639bc3e5b"
              + "0188d5ae508c190c6922806eca74edf02b056db1074ae867af5b5f874c68",
          new BigInteger("1f76b4d9b4a5703233bc779a3464475b7d48a1db0a06bc7b8d016218c0e0dd67"
                  + "ceaa272fd3d6ba65d403fb708b101d0de805ccaeef55714a0fd94eca273e8735"
                  + "58f", 16),
          "01ffffff00000001fffffffc00000007fffffff00000001fffffffc00000007f"
              + "ffffff00000001fffffffc00000007fffffff00000001fffffffc00000008000"
              + "0002"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b810400230381860004015832b4f6df"
              + "b22031046358ad93c843cd45f430b2aeb9cc42053e83b99316ac1e8db4ea11af"
              + "68e33abc85ae928e7fbc0a533314ccb4f9a850d4a17b14917c9da08c0069312d"
              + "f170b806669fc4b6fb9cdf79b2edbcbea9692b9ff43eb605f841375bdcaffafe"
              + "a9c5ea459d3828fb7ca64b0ea4ff191655308db22a4967f297e01f7cc5b6",
          new BigInteger("0e2edaa38ef056b78262509d2a08d27ca3abb926e4ac98aa4704347e7a1b5c24"
                  + "fffa9d1bd00f37fefb193034c6bcca32c4f1bef05895cdb31bcf0ac4291c0aed"
                  + "9f0", 16),
          "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "fffd"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b810400230381860004006837a89b34"
              + "7bce215ba0bcebfbdf3fcb46c6744d0819439adb6d2e34ac8788affb4b5ec1a0"
              + "90fdef58643029409a2cad98f8277ee0be7ef966556ec08a4fc97e8f006e0491"
              + "e7be6ce05b98309d22a3a01dfacf694b5b5b99c3350f470b655193e470eb9b4d"
              + "dc0001bd806f217137cce6205c3f443d2b5978e952229dfc2d1cf0de3673",
          new BigInteger("6f0c42dd71e52c455b6e6571e4c2950c6fb6a82a91bcb08a6de7f647f644b058"
                  + "15d3e7de07fb92f6c5c98b25072c84e40ededd366815a29f64cdc8e46a33bb09"
                  + "81", 16),
          "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "fffe"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b2403030208010107034200048ddfe6cb"
              + "ac3dd65f815e7374d721b1bc03b2d007e50b93b2f7434293cf0579a696907f4e"
              + "b68418ad3d955987e01d34380b2be76623e291679c37a7d19f3cb098",
          new BigInteger("66ebb3d73d9e82279fa2f80c7470ddbe48d90eb45246c4fb19f38974876c5ee3", 16),
          "0000000000000000000000000000000000000000000000000000000000000001"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b2403030208010107034200040930bb2d"
              + "80d33db4071a34fcc77004ee0c6b0be7686c66b0f13a0ba89f957df78c522da7"
              + "9b0bfeae34b49ef86c3f500ac83677b24afb31eb818ede33da4d17d5",
          new BigInteger("5fa1e4693e18046c5d7540cc503f69444c6465737ab94b1575857d266749d805", 16),
          "0000000000000000000000000000000000000000000000000000000000000002"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b2403030208010107034200040e3fa34c"
              + "015fe23682710712014d34437c75650557c3a0e274028bb69e5d10945f51a4c1"
              + "8b1a5592fc883ae0c35f7b83e5a5c3fce46bd95757188e0aa9a3b91b",
          new BigInteger("1662eb3c7e09def21474a1d1748c13354451e73e2bf6df94fb3c283ac8425b1b", 16),
          "00000000ffffffff00000000ffffffff00000000ffffffff0000000100000001"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b2403030208010107034200041692e8ec"
              + "72b11baed89139ac7c3de1032e931b6b39fb3bac834958e12c50bfd5a7c68cac"
              + "11ae6bc9cc2fa88de30d4d7a582873d4e70032e4fbf33e5ae1fff528",
          new BigInteger("29de4f7362be7cf8fc025f7a322e6a495d042fcea541b98ea72808fe1f2eadb5", 16),
          "0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b2403030208010107034200041d92ac08"
              + "6206308f692b954e638784049e4d8359cb298ceffc69b0e7e020b6f7477ca259"
              + "e0c573c1222b6a11a4c0b2076bd98a3edf00afdead7c9fff6bf8fcf4",
          new BigInteger("08550b9b3db058bdf6b49d774e8b88abfaeab829e56550538a913ee480d736e6a", 16),
          "7f00000001fffffffc00000007fffffff00000001fffffffc000000080000002"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b2403030208010107034200040d939884"
              + "5132475dfd9d5d19cba3e3513ee97d88494dd8c96c5f9f5287f005349507a345"
              + "c2ce16fd720390034e7f0ada3676802d2cd9562eefa1e84af8e389be",
          new BigInteger("275327fdc7aa4d64423caee21b125a491663071af1d6d5151a6bde7fa79eb7f8", 16),
          "7fff00000003fffffff00000003fffffff00000003fffffff00000003fffffff"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b24030302080101070342000471435f10"
              + "b4a9f711564c385bd52018008a2769a6f2abef3eb2abc3665e84c5018a7669fd"
              + "adf9f154f15524068103e7bfe6d407955ba425389f649fe967849b48",
          new BigInteger("40e767db1c3251640bec8435f9dc34ab5b582f28dde8ad89bc89eb9b1d99d7f5", 16),
          "7fff0001fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0008000"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b240303020801010703420004434f8fd1"
              + "3025debf0f3ef2b1d8f8149e6c3b54ed23ced882fadfa423b20ec34d7eb8a099"
              + "6c6a4b23b6fb66c00b616946a4ba1671cceb25ca153aa8b60568b992",
          new BigInteger("691af60da82e8f696f57c624291103f28349d0253f580927cbc786b593b1f93e", 16),
          "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b2403030208010107034200049f796d43"
              + "32f9762fe83f7503852ba9ca04ff7e70183a64a783a92a7942c04c0738c87e04"
              + "fa81e60d401373556b7ebbd825f29ee5dc3c0bda5b173af7f9bb5723",
          new BigInteger("53425ad188c525cb80c4e90c06fc650b3fc3a544dfaa86fe8e2a59753c09ba6f", 16),
          "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5376"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b2403030208010109035200041b3a403e"
              + "0acbadc4166d63269caea16cd571dbd706bcd8ce9905d4ec69b90f7e8fd93f0b"
              + "e53c7779a3f7a414bd7f822f0ed1417ea1656ecb6c5a7cd3caefd348ed65d0ba"
              + "6abe6764b51ff05395178c20",
          new BigInteger("09c301783c077a95a6c781960daf10d445011d9fe227ce17a64103c7e94b7a09"
                  + "a7acc8e20dfb948", 16),
          "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000000000000001"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b24030302080101090352000406ea533b"
              + "98f3a3d423dd95382a0ba86175b3f7eebde63d0b2355eeaab43bd26cd714e9ba"
              + "0b01bf90896959c543e792f1d2b1bc446f9c6b9113e2b54a17f02870047a1c39"
              + "10ed7a4d1ffb274ddf19acc3",
          new BigInteger("62c2816fac0b517baeb3c3186f8451fc645bdaa62ce9fcff2a201b4b934092a6"
                  + "c38355828dd5f0d3", 16),
          "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000000000000002"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b240303020801010903520004785051db"
              + "8bcf7a0e42a4f9d02c0e6c52c67a7c9551993b1e582834871a492133b0c3f639"
              + "2c9b6a28b97dcd634b007d6a775d94f11846440152b61ae3f4eb5c0592d1ad8b"
              + "ce6d72624d09cd3d20d94068",
          new BigInteger("405b3e3504ebbcdb44e5c94b74a3680b547fa8819bbedc681fa1e7b660de526f"
                  + "6e3805624b485426", 16),
          "00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff"
              + "0000000100000006"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b240303020801010903520004a4e00b06"
              + "cddef03e47e2ca7d6e94d175547b1b4df454ae5167ee0584a9c3814d2ff2fe7c"
              + "d23c30e1cdad451ae9a8d5a90288ec347587f554d1fd34bdfdc043e0bf182447"
              + "082fe17313101288e84e1c0f",
          new BigInteger("30dcca12636be87de3d2ba185353cd70ebca05f0d978b31065299b774477639b"
                  + "753a42d57b658e5a", 16),
          "0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff"
              + "0000ffff0000ffff"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b24030302080101090352000496776d7f"
              + "4a79209d5a2dc7f9105b46d5b46d3414827b07b53261aff5d9de5e914bd69a25"
              + "faa3419d366c6fab70349933c86904bb0964abf3173d0a6e741848b6ad6d344c"
              + "84a30bed93b3622401bf4a7c",
          new BigInteger("7a51aee663ee3993ed0a8d698321368c9dd37c3db15dff61056d51d3eba70366"
                  + "3102b1b55a5b3f7a", 16),
          "07fff0001fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0007ff"
              + "f0001fffc0007fff"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b24030302080101090352000431398cc5"
              + "84098847a74e48416314b6abcef452e6bb55ec2ff3e705ce99be2f00e808d430"
              + "4f91ff00335b7bafdc07159ff40fdd7a1cd19842387247f67d6ebf47d608cdec"
              + "93c6ee2831e8a71d81059088",
          new BigInteger("4426c6448d59ea003ab7a6b8188c165f8d5a0ed3321fd6abed073e892d4526ea"
                  + "8437fe88abf2fa1", 16),
          "7fc00000007fffffff00000001fffffffc00000007fffffff00000001fffffff"
              + "c000000080000001"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b240303020801010903520004786f0230"
              + "9b5eff2bdb6b58b2206f8ccfa202baf9154354d4ee4c954f0592b5c812b4d067"
              + "fc900e268b58f9600aedb1762f6241cdebef54eaebfae0c37bdd9b9ab928dab2"
              + "4fdf5a7a0e5bca063dbc0ec9",
          new BigInteger("0932e2074de451ee3978676016cdbc8e315a755ca6bc9e2ad9787217b397dd4f"
                  + "a870e3074c13ed5ef", 16),
          "7ffff00000003fffffff00000003fffffff00000003fffffff00000003ffffff"
              + "f000000040000001"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b24030302080101090352000416f0ec7e"
              + "986884c41edba40f510f1988cd93d5509246274cd9c080235dcf92e4bb6247e5"
              + "0b7974b5211455a09ca2a22f8897b7c336b184ff77a3174af9f2c7a171616074"
              + "82048e745771fad4b477b18c",
          new BigInteger("66988febf58b1a503b71534608cd98d489aa6b060eaca2303d5c513b5e0c9b6f"
                  + "f9dbe9c99fa3a98e", 16),
          "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "ffffffffffffffff"),
      new EcdhTestVector(
          "brainpoolP384r1",
          "307a301406072a8648ce3d020106092b240303020801010b03620004841a020c"
              + "b95c15d31e3ce4a6bc66793060af461b2c464c450e1d55359551baffb243eb0f"
              + "929a8ec5eea893d0e3d3ca0f5f3aeca01aa93ed3d7a2f7d7385d03102e5961f8"
              + "c288a1f511e9ebdd99942b73113829042b40abbad533b8b88a5cf515",
          new BigInteger("60c7f5de5ae3a6dad85eed30b511b06b5b7164835ee97578c3faf02b8777158e"
                  + "4cb4b57ea4a0e5e45897e66277030edf", 16),
          "0000000000000000000000000000000000000000000000000000000000000000"
              + "00000000000000000000000000000001"),
      new EcdhTestVector(
          "brainpoolP384r1",
          "307a301406072a8648ce3d020106092b240303020801010b0362000433d6c62c"
              + "e69159b083dc29d9bc9d3b8655e0142ef0659e62b6d92ea97fcd543970a9feb3"
              + "ca6437dcf3506a76096bfa6b59d5e44760223485a322dcc0e2dadbed71ff1b34"
              + "8ddd478a5dd3facaaafb4523c9d0a89f90ebe07944a389b31c0bdd3b",
          new BigInteger("2b010b9a913072036aaad7e14a45703f37a801d87bfaf307bfd49aa6e80ca543"
                  + "7cea3688a5532ec343ba15ff38a4e5c", 16),
          "00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff"
              + "00000000ffffffff00000000ffffffff"),
      new EcdhTestVector(
          "brainpoolP384r1",
          "307a301406072a8648ce3d020106092b240303020801010b036200048b68fad8"
              + "1b2c0dad9f6b2bae291d7b9a9d9aae04334703a6d4bde3ad93b914edc88dd734"
              + "c09d582b8888fa9ffc913fb481ce6f9b31855f7b113bcad6d92599cc248e0bfb"
              + "f9278f98bc72f0680252992270a60843fba5d4c7370853c761e6908c",
          new BigInteger("1f877d710097a6d75a556e74f3a8c89d19fee8240eb2921bd5afdf11abb1e19f"
                  + "c9c44912f079ed003933ed20e1e41116", 16),
          "0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff"
              + "0000ffff0000ffff0000ffff00010000"),
      new EcdhTestVector(
          "brainpoolP384r1",
          "307a301406072a8648ce3d020106092b240303020801010b036200040742b702"
              + "fd04283d3cce6eb3f84a740ded05a92f9cf8051b607d002d20cd321d105d5edb"
              + "7c041735935764713e48d26d2110e79099ed49d37e1fe57e4b31b974b1c532e4"
              + "bcb104c034f819d534e61c914a6daf789c07ebee9e2b565d33504833",
          new BigInteger("579520d7f69d0f598d1330f336e59a2f1265a04240d3f0d620bd435e10146a3d"
                  + "eb6ba731956dc684f53fefc4ecbdac78", 16),
          "007fff0001fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0007f"
              + "ff0001fffc0007fff0001fffc0008002"),
      new EcdhTestVector(
          "brainpoolP384r1",
          "307a301406072a8648ce3d020106092b240303020801010b03620004451054d0"
              + "80f1bb7b88c1ab1af597c792790e8902a46c307a9206a5421da81076ccf473f4"
              + "ce81456986b5ed0adce6d62913e2671119645f6650e95975bca51def4f64fb43"
              + "a76c14cc91bfb8c749b04d5751df753ae3976d74825aefd69eb78c59",
          new BigInteger("14c807d4b2bfde38b275ba56b5a54893cbf2fa760b00a6c1373f150b0a882f42"
                  + "99455cae80f54ba37881c8e39965c0e3", 16),
          "7ff00000001fffffffc00000007fffffff00000001fffffffc00000007ffffff"
              + "f00000001fffffffc00000007fffffff"),
      new EcdhTestVector(
          "brainpoolP384r1",
          "307a301406072a8648ce3d020106092b240303020801010b0362000450a70abb"
              + "c1817f9244242a2924d9b2b168a238d3b7f3c02faef9eaf7aac8c5409146be56"
              + "bd16d32c69ccfe696bdb162054977658e0033bc5ae7c6dd3202686078fb8e541"
              + "210d410a40948abafbb3acb048ca2cd14a75eb8725d9b55efcd8fc35",
          new BigInteger("4ae2028a9fc676602f8ce2f2a21ad8325556a0d597cc7e9688b6680ab36a9aac"
                  + "d1354d2ebaa252281e6b381cdeaeb888", 16),
          "7fffff00000003fffffff00000003fffffff00000003fffffff00000003fffff"
              + "ff00000003fffffff00000003fffffff"),
      new EcdhTestVector(
          "brainpoolP384r1",
          "307a301406072a8648ce3d020106092b240303020801010b036200046bf6e66f"
              + "309d34cab5020a5a9a5987ec708dbbe79d594d5ee93d0fb40f98e605e110b2b9"
              + "ab1830d630afb71c17ee21874d191c0cf34519af953634478bc6cb66296e4296"
              + "943db1d9bc8a6e77092879ed7bd7c22c1791c96dc5dd5d5df6d4a1e8",
          new BigInteger("70772a60b189cd8fa77c99d99f9596298125dd6de21fb14dc9a96035e635d711"
                  + "950a494d4e6353215aeeb081476c5937", 16),
          "8000000000000000000000000000000000000000000000000000000000000000"
              + "00000000000000000000000000000001"),
      new EcdhTestVector(
          "brainpoolP512r1",
          "30819b301406072a8648ce3d020106092b240303020801010d0381820004a0e5"
              + "0388c314d81a56b1dbe64c39694b8f6fc372f84304e986b77453c3a4572e4f6f"
              + "cb4823da9ea02c5b39d88ec460e70aff41d311f02e5d4c9f2f2702ece872a162"
              + "d0ffafe40a5f4cff44574e7ee175cddb26bec4027c29cd3e0fab48748256f9ad"
              + "b7d9cddaa3560305c5f49a42ffb5ea987b550b4e8751e5f3a88a5ca8c52e",
          new BigInteger("526e3007987a84a8a453fc2ca3a2dd7a15f4ba00968423ce50b320096ba2b721"
                  + "6a97df334ba19f4d4bd6c672386c4dc3753a1be601a4f396d1b97bf7ab47a0a4", 16),
          "00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff"
              + "00000000ffffffff00000000ffffffff00000000ffffffff0000000100000000"),
      new EcdhTestVector(
          "brainpoolP512r1",
          "30819b301406072a8648ce3d020106092b240303020801010d03818200048ad4"
              + "0d9e1b649ee8f42755ec543de673ac92766e8d237ce331724fa06c3409ec2ca9"
              + "bc3b64d4d921512311fe0eba4bb5d176a7c9f78ca836624bfe80795d8f3e0ccd"
              + "f70077d5b61f4b75d69a6173f0feda41a324522732ea41fe7efd0a1ed09cf934"
              + "f001ca18669d30b635c2fb76c108b0a3a656bfc782dcd0055880d44753a4",
          new BigInteger("31dfade358b35f93be45243507fa431bb15bb0529c0deef68beda87d88d3841a"
                  + "77cb1772b8e75f6440415213c33f77aef92d971750687ba22a184d9fafaed6a4", 16),
          "0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff"
              + "0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff"),
      new EcdhTestVector(
          "brainpoolP512r1",
          "30819b301406072a8648ce3d020106092b240303020801010d03818200049ddb"
              + "6585b6e38b2eb5eb76ea6e5386d3d1eda219ebedd24c5b783fecec0108ae99d7"
              + "c4fcaacda8f9a4c9d142dff72fe95773dc3d5de8412e62f39ffd38b78eec0e0a"
              + "d99c6bde21944f42f00b3c941ce8739825e03e591f6436d8e2641976bc706575"
              + "500f4504a063a3debc7d74dd47f979e7398921e8bda6d1a7950fdc5e0443",
          new BigInteger("0be4dfd93a8d1ede4252275e8b45aebe39663ba9be1e27950b1551f338202812"
                  + "0fa425585f2622149970fde98b78cbf3195303475a2f955e0bb9d32ae58d532b", 16),
          "3fffffff00000003fffffff00000003fffffff00000003fffffff00000003fff"
              + "ffff00000003fffffff00000003fffffff00000003fffffff00000003fffffff"),
      new EcdhTestVector(
          "brainpoolP512r1",
          "30819b301406072a8648ce3d020106092b240303020801010d038182000437aa"
              + "c1b7f20d6076d4291774fd5601025fdd85c7ae887b6217b1ef2b238e10ac45e3"
              + "acf2a9e2b0091b7ae1b24e830d5d3cc2f4dc3c68efa885fbf18d9ced5d6300dd"
              + "2a056df71df75483a3c11e434aaf9c2e06e36bf405e1f610f39cd1e179c51794"
              + "7d499742b8b4412a6dc54d66b0323e6276a59edf1675acee19b0c7f2e210",
          new BigInteger("140072e85c614c0b76783774e2202ee34bc06c7ed1d55cf6598177c42f07804a"
                  + "447a08b1bd11529dc0640479c4f387634fc63d933bce49adecdea2972d49d677", 16),
          "40007fff0001fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc000"
              + "7fff0001fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0008000"),
      new EcdhTestVector(
          "brainpoolP512r1",
          "30819b301406072a8648ce3d020106092b240303020801010d038182000477fc"
              + "d103fc32d41854d7509b3b64c6e1c9c1138a2081f0073dd51fffdcd46580b0d9"
              + "3b78d77d50a29b52e3ce3f3cab3a91c90cbcf832a1b88bd4137cce1f11ba3c5a"
              + "6d66ac49e0d2f9d65e1b754d8b48ae279cbb1a482db930df3ab45f733f410588"
              + "ffc40f22407ff6641a5fffd9ee85d7668ab7aa9b301aca603f0a06869efe",
          new BigInteger("5ffb3afb78b5c6aaa33c48e243807efad9ad2859a19f2d6dbde42e479873a99b"
                  + "38cfc511b016c513f402df9f5c05e23dbffc2bc9d862fcd7c86d9ba24cf63a4e", 16),
          "7fff00000001fffffffc00000007fffffff00000001fffffffc00000007fffff"
              + "ff00000001fffffffc00000007fffffff00000001fffffffc00000007fffffff"),
      new EcdhTestVector(
          "brainpoolP512r1",
          "30819b301406072a8648ce3d020106092b240303020801010d03818200048fcf"
              + "4f5847a479ed11f23cb76c95abbae93cca882e6cd17df1590480c0787342e724"
              + "417474d799758561371060ffc432a054e71d4befc7a84a04efda080f5b1e4817"
              + "c7c1c79841a660b17261ff75aab3801fb99a73b19c81bc97427b07c4d60d4a13"
              + "3fdce51d71b288d995e2a6cbdfff4d06f4dd1393882df08f67d3c7af9f9e",
          new BigInteger("19060f4194710cbb5681dfeac22ff15a75669ae0de35345b4b69e4b2862c95ad"
                  + "09de2453ff22bda9a8f9d88ae81b23385dcdae44d1624529d7c4475e186b70a", 16),
          "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
      new EcdhTestVector(
          "brainpoolP512r1",
          "30819b301406072a8648ce3d020106092b240303020801010d03818200041fcc"
              + "447621fee28c9b13d3b7b174d8f7dd7866916b243987b2f92a89c9e2be69cbd7"
              + "246bf147d51ad4ea7bdbb3c92d990d4b50c5626f91e5b21241dcdea952060f62"
              + "9e1abf25ec94d3b0c10e6c5d5280b16dd19e7abef8fe7c0fd415654c08698b00"
              + "94960c2ae73f2e5fd0d7aeb8b473981fcb1affd85c0c7e2c214bb3f3bf7c",
          new BigInteger("37b1580be70bf5da673278dbe707b059ec150e0b427a075a63c7dd2e2538bad1"
                  + "ac1ca86ec275a031944996fac57c1bd49bdb370806716c4ea4f751074418d427", 16),
          "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330871"
              + "7d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f2"),
      // edge cases for ephemeral key
      new EcdhTestVector(
          "secp224r1",
          "304e301006072a8648ce3d020106052b81040021033a00040000ffff0000ffff"
              + "0000ffff0000ffff0000ffff0000ffff0000ffff77c5cfa4e2c384938d48bd8d"
              + "d98f54c86b279f1df8c0a1f6692439c9",
          new BigInteger("0afa12d5cca25a6f029a3ba2b837e4f98aa6a0c1d8fc6d300f861f409", 16),
          "fb94008911b788d442d5e3458acf3558f39f1ebb2a2e51344a0c68a5"),
      new EcdhTestVector(
          "secp224r1",
          "304e301006072a8648ce3d020106052b81040021033a00040003fffffff00000"
              + "003fffffff00000003fffffff00000004000000001f0828136016bb97445461b"
              + "c59f2175d8d23557d6b9381f26136e3d",
          new BigInteger("767c6da34f3a6108303e376998032bda8e362da1289f51ba0665ffb8", 16),
          "41ab29168bc19b1fb7c2d755ed649e36a0bcd0001d73facc429512fb"),
      new EcdhTestVector(
          "secp224r1",
          "304e301006072a8648ce3d020106052b81040021033a000401fffffffc000000"
              + "07fffffff00000001fffffffc0000000800000012d8acca6f199d4a94b933ba1"
              + "aa713a7debde8ac57b928f596ae66a66",
          new BigInteger("0d94b6440fd923c76bdd8cd08e6af7ba57d0cadda14959f1331e2d64d", 16),
          "e12f928cd6d6bd319dbf97240b8de6352fd014439e279a3954279e32"),
      new EcdhTestVector(
          "secp224r1",
          "304e301006072a8648ce3d020106052b81040021033a00047fffffffffffffff"
              + "ffffffffffffffffffffffffffffffffffffffff7d8dbca36c56bcaae92e3475"
              + "f799294f30768038e816a7d5f7f07d77",
          new BigInteger("6536c872294d58ee3308729be6e531f3207abe9cd7f912ef36f54870", 16),
          "2e52327991e925526574ced51bbf32f1617098983446b848029fc81c"),
      new EcdhTestVector(
          "secp224r1",
          "304e301006072a8648ce3d020106052b81040021033a0004fffc0007fff0001f"
              + "ffc0007fff0001fffc0007fff0001fffc000800174f1ff5ea7fbc72b92f61e06"
              + "556c26bab84c0b082dd6400ca1c1eb6d",
          new BigInteger("0fc93809800ccf0d14ba6e4baf1106135fb84a6edd0babf4303b1a38", 16),
          "919b8ba25f19028217d8c1074d0316321f587ccd555ac50c2557ef83"),
      new EcdhTestVector(
          "secp224r1",
          "304e301006072a8648ce3d020106052b81040021033a0004ffffffff00000000"
              + "ffffffff00000000ffffffff00000000ffffffff1c05ac2d4f10b69877c3243d"
              + "51f887277b7bf735c326ab2f0d70da8c",
          new BigInteger("6c49d434ceb307ee6a1a56edafaea3007bf86b2e650f6ef5801e6d0e", 16),
          "3a3baaef6bebb6fcf0e90a78230977454fa173a42595238c4042cb00"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d030107034200040000000000"
              + "00000000000000000000000000000000000000000000000000000066485c780e"
              + "2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4",
          new BigInteger("088c03a5a38304948da54216863307c67dfd1b6bfea1a95e941b9b40a0babdedd", 16),
          "f7072666bb3f5c5c46d812fa7a4166f783fbc577758759deee593d230d617db3"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d0301070342000400000000ff"
              + "ffffff00000000ffffffff00000000ffffffff0000000100000000462c0466e4"
              + "1802238d6c925ecbefc747cfe505ea196af9a2d11b62850fce946e",
          new BigInteger("0e531218f3e5347d113f2e2d9effcfd001d616e795b0d9fcfe5d57947659847a9", 16),
          "6cd9959abc051eeb81142dca2644f873c0b19e4b4b7e9298d483de48071854f0"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d030107034200040000ffff00"
              + "00ffff0000ffff0000ffff0000ffff0000ffff0000ffff00010001684c8a9586"
              + "ed6f9cbe447058a7da2108bab1e5e0a60d1f73e4e2e713f0a3dfe0",
          new BigInteger("0fe37420c91cdb1a6c8fc90c362aff517883fcd61e4d63516a10b3d5df7b46460", 16),
          "b60b7058285df03f1273352007e3f55447c62d403a9a902fe844898babfd142f"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d030107034200047fff0001ff"
              + "fc0007fff0001fffc0007fff0001fffc0007fff0001fffc0007fff2e2213caf0"
              + "3033e0fd0f7951154f6e6c3a9244a72faca65e9ce9eeb5c8e1cea9",
          new BigInteger("119bbcc59126f03853d109153e15f4b6ffaa999ba66f0fd9db1252d41731484f", 16),
          "48bd6becf17899a585e049f0ae7b22fdbe8a4977ccbb08b5f78ecd1871196cf3"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d030107034200048000000000"
              + "0000000000000000000000000000000000000000000000000000042be8789db8"
              + "1bb4870a9e60c5c18c80c83de464277281f1af1e640843a1a3148e",
          new BigInteger("6c1c2bec81db9deda4a145dba835b6013bc678afd6b563a39a52216678c28485", 16),
          "c932433b77db3da1c5732db24997cbb63ed30bd763b56c1ab561a03e69a8dfe5"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d03010703420004ff00000001"
              + "fffffffc00000007fffffff00000001fffffffc00000007fffffff5df80fc6ca"
              + "e26b6c1952fbd00ed174ee1209d069335f5b48588e29e80b9191ad",
          new BigInteger("095ee174620feedc08456ca1240058b287f0e535ec4345507586112d65bb3cc46", 16),
          "f9f1837a64cadf5cb37e859ad33d11da7e53f25eda41de478dfa82b4b88a318c"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d03010703420004ffff000000"
              + "03fffffff00000003fffffff00000003fffffff00000003fffffff2c63650e6a"
              + "5d332e2987dd09a79008e8faabbd37e49cb016bfb92c8cd0f5da77",
          new BigInteger("0c5bc3ee5d8ff36e4aa75691eab877cfe86b44c322173e88ecde059d1291f336f", 16),
          "5403bb179d758de79685b5fadd1c65fab2a6ea22ca9a2e958663dbfb135685de"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b81040022036200040000000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "00000000000000003cf99ef04f51a5ea630ba3f9f960dd593a14c9be39fd2bd2"
              + "15d3b4b08aaaf86bbf927f2c46e52ab06fb742b8850e521e",
          new BigInteger("0e9e989964d7fce7ea5f99695569a16807f8ff1f92023a48d8be1193cad9552c"
                  + "264fab6c4c9802da9c3f70d41033324d7", 16),
          "50e5d5952e908169f0da06ad0727cb88976c39bc77fb32b48612c7050de4b075"
              + "e851099933f4c522ff094829e55fe95d"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b81040022036200040000000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000000000000002732152442fb6ee5c3e6ce1d920c059bc623563814d79042b"
              + "903ce60f1d4487fccd450a86da03f3e6ed525d02017bfdb3",
          new BigInteger("287533ac7f3bdf4dcbe62bdf3c34785bec0a57807ca76d60bb254c393ae64a32"
                  + "71f3e6e114d4d51ffa39361034d43cb2", 16),
          "777516826d15cb7063c08b0e54c668d32e0d932221c719e879835aec0827b173"
              + "5c0874ae2701127abb69d1fa87391a13"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b810400220362000400000000ffffffff"
              + "00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff"
              + "00000000ffffffff70370385413d3eff6fa3407ba24f682c2b01b51445dbdf5e"
              + "f7b0dd0979f17e713e09081571f1e94dfb66bf282002f39f",
          new BigInteger("2482eb480bb42f8a4e5b40364001f4854125d7470cbe6a07f97c7064f4092cf3"
                  + "7fb5fecafb8541fb53815b8f3b5d47ad", 16),
          "1503e27812b71fb80b90ffa5a65fda25cc7e1b7766f0250577217db4f257029e"
              + "a6a5ea1fd2adb6351239f1813b49522b"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b81040022036200040000ffff0000ffff"
              + "0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff"
              + "0000ffff0000ffff112e191f1f78bbc54b6cc4f0b1e59ae8c6ff1a07f5128e41"
              + "dfa2828e1b6538d4fa2ca2394c6aab3449dcb3fc4eb44c09",
          new BigInteger("17c1564cd256692fe14c519f1749dae5a4639b27f32da167382562111c633dfb"
                  + "a51494b7368ac6b7c4d23cef6aa87c5a", 16),
          "f355c3b3a50aa985713f6ad40fb8a964ed31255ee542d660d8d82dbec2026656"
              + "626c6e22c6f6041c0a890ee2b0fe7b54"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b8104002203620004007fff0001fffc00"
              + "07fff0001fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0007ff"
              + "f0001fffc0008000028a4c8da5a05112fe6025ef41908969de20d05d9668e5c8"
              + "52ef2d492172ddc2a0a622fc488164fcc1a076b872942af2",
          new BigInteger("0c4f3982377d1a1d32c66d4acbbc69f221def10d17512853a4d3929ffb83193f"
                  + "e13127fc85cf82d510b9bf4f2922e7ea3", 16),
          "78ef5d865034c6dcee65fbe91f6ff76d2adc5f519ced309418c92e3d54f6521c"
              + "1c5feffa5843e705fb72962d4fe2351b"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b81040022036200048000000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "00000000000000020797da4c0751ced16de80d16ab7c654a5dc27d092626d086"
              + "5a192a1c5ea7c1b88c9fcab057946741e41cc28c80ec0b9a",
          new BigInteger("67e616281ef5fd345887cd66f4911f4455e5192d550d5058a4a10264d7eebd5b"
                  + "37a9ead23a9c59905f1554b549755ed", 16),
          "def5376fbbea1605cd07ff5ab8954d02c3827ff1576464ddee135b94f1ddd794"
              + "9d279d87a9eb01da8d9ba62314996b69"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b8104002203620004fff00000001fffff"
              + "ffc00000007fffffff00000001fffffffc00000007fffffff00000001fffffff"
              + "c00000007fffffff6c70898ae6fb31fa2f086562af2d10486ba4c6fd5e41dfe4"
              + "aa61598b4707a3bc276a62feb1b98557e3b17c025f7adf4e",
          new BigInteger("0c30831e3b31bf5cdfc106c4c8c381f58df9ad0e0da755c3347c1029e3f3aecf"
                  + "babaa1ba9679905ea27f7140dc32587a3", 16),
          "38913fa0674226922590537345bcedbdeb77a44ab776158da5cabbd0b36c1e89"
              + "4f90a6119896f6418db97ee51011fd1a"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b8104002203620004ffffff00000003ff"
              + "fffff00000003fffffff00000003fffffff00000003fffffff00000003ffffff"
              + "f00000003fffffff4987abae412809c2fa48fd23b1bdf9e622f5a606c4411721"
              + "5ffa61b18ef46e54a7fbbf11f9a6ba59c991b4ae501fedce",
          new BigInteger("0ca13630aef56b21ac260f68ba5e05c76b27c64a106f5ae8b71bad965d2795ea"
                  + "bdf4afca1c6971a3c0b5d224ba6c20013", 16),
          "0d503d9bc44129ae7b6a9df1debef79fef1bbe5948c5965bd80394b809968802"
              + "4524be203587c890bb5ffce30c25fdb8"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b8104002203620004ffffffffffffffff"
              + "fffffffffffffffffffffffffffffffffffffffffffffffeffffffff00000000"
              + "00000000fffffffe732152442fb6ee5c3e6ce1d920c059bc623563814d79042b"
              + "903ce60f1d4487fccd450a86da03f3e6ed525d02017bfdb3",
          new BigInteger("6df60ed78fb26471f873f83d254563e7740c70a3cb61b03382a9ee185a1104f4"
                  + "f72252a86be3f236e0934464a238beb2", 16),
          "364de15a7408e63d66c71c77a187ab358918af731445a1f777a5d661cbe69db8"
              + "99d4d46790279f42335052c7bfa75be1"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b810400230381860004000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000000000000000000000000000000000000000000000000000000000d20ec9"
              + "fea6b577c10d26ca1bb446f40b299e648b1ad508aad068896fee3f8e614bc630"
              + "54d5772bf01a65d412e0bcaa8e965d2f5d332d7f39f846d440ae001f4f87",
          new BigInteger("1aee1144e72c5492ca3182d7ba0445abd6f449aa5bb866f166a03c023f600786"
                  + "c7353ae8b00e1605e1a5209faa07617430dc2230fbdff570c016aa543fe2c619"
                  + "e15", 16),
          "01cf8eb7e4dcc424ae67ca0a54549e9a8a12426818d3a4c3850cc9b7c8702d55"
              + "b921a4efba011930f8584e81a873b9e5731d9501b882513f757e70b45113b003"
              + "b0b4"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b810400230381860004000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "000000000000000000000000000000000000000000000000000000010010e59b"
              + "e93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03df47849bf550ec6"
              + "36ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c832e843564",
          new BigInteger("0c5ba19a01fd621161553a9b75c40c4e0eb7bf9500ed187bf6edefe6b4229a2e"
                  + "198815b1f8b0f6b1ed452d0f80a51d6949dc0fd2d2d457c0c0f04ac41b2e7357"
                  + "ab3", 16),
          "01ab7a23162cbe7d36021a5a8095df8e7f7c1085ffdda1c59663d0884ab2b760"
              + "8c5a299e0d1f874db73203e46fc219689eff4b2bf10187fde8b692cddb570a97"
              + "4956"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b810400230381860004000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000000000000000000000000000000000000000000000000000000200d9254f"
              + "df800496acb33790b103c5ee9fac12832fe546c632225b0f7fce3da4574b1a87"
              + "9b623d722fa8fc34d5fc2a8731aad691a9a8bb8b554c95a051d6aa505acf",
          new BigInteger("1073a9a2eb11c580316e13925b3278966ec17ab90faa972c71fa1f4e139619b7"
                  + "d72832623c0a919dbce55b414308c91909842cb6574535cd9f37e58c9a59793f"
                  + "9c3", 16),
          "00a093ed6a932ba8caf978ea66a07a8421af9ae7331206e33ae7505d5e510e0b"
              + "cf514c20cd5e4a3053241b154ff5b64e294bb9f2950fad499d12da88c5dbe12a"
              + "19c4"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000400003fffffff"
              + "00000003fffffff00000003fffffff00000003fffffff00000003fffffff0000"
              + "0003fffffff00000003fffffff00000003fffffff00000003fffffff00cd2839"
              + "d857b4699f5c8e8a0194786e26a862f086b4ba80746ae5225ed3aa68f96b7aae"
              + "c55225830bb98f52d75221141897ba49d7a31ebbf0b6d7d31352e5266190",
          new BigInteger("08d3378cc64dff0de5a02f2a680e43aa302ede5364a755eebaec055fc9b1f6f2"
                  + "30c7c1dfb3fec80893e75b5975bdab2a53cf0fc72919f0326e8d856da20fba40"
                  + "e4c", 16),
          "01adba7713d8c8e0138eeb888009a3f1272be952849500b48a76a24ca6fb0a8d"
              + "c58f320cf4e4f768f20ba0b5f8a4e7d62364a810c25a70d9af13bb9ed1949fbe"
              + "1a5b"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b810400230381860004010000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "00000000000000000000000000000000000000000000000000000000000813d9"
              + "829119f42ffa95fea8ba9e81e4cd6a6ca97fb0778e12e5f5dfe35201dd4cca8e"
              + "ca0d2e395555997041381e6ac1f18ddf4c74e0b6e9041cfdca1d1c103091",
          new BigInteger("148774fe4f66954161c0e3180e4d2e590ca6c8f34668e08d1e7952d42161ea8f"
                  + "5c7498f4670565f291696989c7be90ce2a7c641ae80c55485cf91d6bbad92d46"
                  + "316", 16),
          "005129d355f994fa8897bb8e625483b000750e255a2cb222418ea03d77915bba"
              + "310541ea3f6014ffaaf297aae275f21a406dcdf2e0b79bb107d58773a89ab945"
              + "b41d"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000401ff00000000"
              + "ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000"
              + "ffffffff00000000ffffffff00000000ffffffff00000000ffffffff001fe800"
              + "c50e54012b75a33e4be7d07c8d60f29680a395e951a6a31c5096b0ea928fc2cb"
              + "f327dd784dc0a7ca46ea73992b758b5641364b4aba39e93798a4d925a008",
          new BigInteger("1b380248801aefb199d7b3416d333ac3b8edcb2d2c0fea06dbbbe0748a006f72"
                  + "c2dac18036207c4cb9fb08795a8662c02fcea3d0749c5c5473fbcdde1d246365"
                  + "d95", 16),
          "00d86f087287ccc7dd06b2aa8f76f08d8926c0c1c8fbb2aff29984519269c37a"
              + "83b96cb3e97325af4af284d4c0ad03b7f539a427209128eb0b2455a2fbf766b8"
              + "da01"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000401ff0000ffff"
              + "0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff"
              + "0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff00010000008dd18a"
              + "1f5e482140be79bb65a21ad60c8987e532c84345f0135affd46ec71ef02b1ca3"
              + "ad56f301d955fa306c122d441d6fedcf8b855ef256350bf69d23a7207ad9",
          new BigInteger("143b1583f68dfe2e0e6e32404deacef632bb356f21d2ee75d2bf1f48d0a85b9a"
                  + "8c5d386786318c019ade7ae6137a2dd0090c746dcce04b9768302ff2778809cf"
                  + "5b", 16),
          "012e91e4a6ddc4559550a00e832192d9964ab4b86c0fecbc0171f49c4dad413d"
              + "6b8f34121eaf2a040277d2462ce0e72b783eb59330798bb6407c7ad3f3828ec2"
              + "0e14"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000401ffc0007fff"
              + "0001fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0007fff0001"
              + "fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0007fff00b11c66"
              + "8fbd549f36889f7b63434051da26f15705839136b1b14a09152d7a182ea7806c"
              + "35478a32d3aa3c9c1627a61519ebec71b36fa77449025b8829e27f307834",
          new BigInteger("138b150200366a3c51feaaf2d48fd641c84a50513521d4c793f11e264cfe7adb"
                  + "9e342b8ea4682f306317138588655d2144c47e1e98e6e13ebf4859273f89e466"
                  + "a49", 16),
          "0194c232d2018768c2b65420453b81fbc91e11d8116acafd9ad1ae40efaa5fe7"
              + "f00c3a0101846deb90f4e9a1de3f45cfba8b87ba5119b504175aca87cf10c4ba"
              + "ee8f"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000401ffffff0000"
              + "0001fffffffc00000007fffffff00000001fffffffc00000007fffffff000000"
              + "01fffffffc00000007fffffff00000001fffffffc00000008000000200aa75ef"
              + "c0a8daac1d73f32c9c552414bccf44af8e74331b47439e7dcc49a135b3ee61e9"
              + "f69717d89b4bba3567a195aeda13fbec634bf2984b5ec6b6f80f5978ed5a",
          new BigInteger("1a1c37ab9e059a76000e61c9f9bb34e315a28b3c2beb2f28666584cec2da967c"
                  + "3f46dba3954f997f2d56cf5a62ff7f5fe28996ffa58b58149ec4b28ff0def4f6"
                  + "f6f", 16),
          "00b14c9b7c144f72ef4cdaf4d01f3cdc1e1e90059ba0fa88590153fd911d78fc"
              + "2e9db89dfd5f016a43ff41c8177c3fdc20cb4562e77114a608d221c6333cdce9"
              + "6913"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000401ffffffffff"
              + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "fffffffffffffffffffffffffffffffffffffffffffffffffffffffd0010e59b"
              + "e93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03df47849bf550ec6"
              + "36ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c832e843564",
          new BigInteger("131525c6fb6b6c4a3d0b74fcd86b41e364d2a892928b7628636d799fcb324fc9"
                  + "69a863176a57e94f8140a6a3f5a7bf73d8853bd0ab47aff0ae34e0714f896bcc"
                  + "549", 16),
          "0193975a00c6a7e5f40269b5f544b4e2af3925d03134bdcd673a0f36a0d66429"
              + "721a605abfef13baab4af086b77f43cc57364cc19b9c7fbf8d4754c4cefcfaee"
              + "3bda"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000401ffffffffff"
              + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe00d9254f"
              + "df800496acb33790b103c5ee9fac12832fe546c632225b0f7fce3da4574b1a87"
              + "9b623d722fa8fc34d5fc2a8731aad691a9a8bb8b554c95a051d6aa505acf",
          new BigInteger("0c8b8e496d087d9e2eb1e5c61b461f5794f6cfba75c64f7f72f5c1a29458898f"
                  + "3ffadb67aa0ed445e61bd459d8272939756d56bce45a5098ba16c43cbb5d83eb"
                  + "7fb", 16),
          "01c9b46ea9eebca3c84933cbdfacd48238034ea1e0d93a7d9b1b0178b25510ba"
              + "dd65fc231d69c7f42c8bce1ae0ce5668f4f3baf326fb92642069259fcdb9fa7b"
              + "182d"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b24030302080101070342000400000000"
              + "0000000000000000000000000000000000000000000000000000000109e0e9e8"
              + "d98fb89da2a32b2c7618b26bb99b920f02a5e831a142e6c8673110cd",
          new BigInteger("0a7c6b3e229cb647bea210ab995505e91c38531db462fe5b8f4e9af961b407400", 16),
          "1855af1f5db82998667d5667b0561555b11e641dca459a0758a8318ab1a0be31"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b24030302080101070342000400000000"
              + "0000000000000000000000000000000000000000000000000000000226ccfda8"
              + "234fa9b70316b5ec4da222972b34a970cfe6dd9983a05e2fa746b902",
          new BigInteger("0a2cab013ae7403a5a7fbeb2d59a99d4ab8befcef9c16fa3c2a0768dbf11a7847", 16),
          "4fe02c2e6b390a9097a3c336b735e91b324ceda19ad19b35380fec704359fcb4"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b24030302080101070342000400000000"
              + "ffffffff00000000ffffffff00000000ffffffff000000010000000131625916"
              + "fc4e157b1cf93f3c80352ba4dbf26effbd87d31a2a808d001081f06a",
          new BigInteger("71a27f1743dc3df6f983f377297a89385860635475d9460b52b55039db838246", 16),
          "58a91318d9234703fe1800d0dfd0b7cc58dd57a642ad30ff9b41107797c51294"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b2403030208010107034200040000ffff"
              + "0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff2c6fb330"
              + "2dd93dc25d2c6792c2ac6f86247c4d39637ee11d9267658017f0055a",
          new BigInteger("2bd41653f2e50f8d65f6b7e2eae1fc625450f4c71d0f55f288f8dcda60152d87", 16),
          "4e90e296f5b48ecc016d4eeafd176d4401cdf2dbef0d63035061cabdabf227d2"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b2403030208010107034200047f000000"
              + "01fffffffc00000007fffffff00000001fffffffc0000000800000020cf9ab58"
              + "99c59216d6d1bc786ddf6221e374cd37a8b745e826c6495bed0a56b0",
          new BigInteger("2068ce3d93fb02f16793e3ce9dce78e67be91ab0843a6e283d016133a8bdbe78", 16),
          "82ce8e44e8267a281bd8d968a259437db91c6d9090cff0a2a6915e08958db5e3"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b2403030208010107034200047fff0000"
              + "0003fffffff00000003fffffff00000003fffffff00000003fffffff01a1ad42"
              + "b3ff22ba6bf3c94b55cfa4d13c6e140d3c44963198f496ebbc50439a",
          new BigInteger("30f764d994487380c67383494ca74f730cb55cf44c2a81dab2da31c2184f4b27", 16),
          "23e25799b4b25e5d52f6b202a7fb5486dce7bc705e0c4e70d7f8dd4004f9b049"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b2403030208010107034200047fff0001"
              + "fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0008000369a4e24"
              + "f010260d7c2560f7dc19c41cde6b5c503b6563678580f0d22c74dda4",
          new BigInteger("7356eeb28dfd424976c1660732b23021da8ededa262a00509116d6af21f0f85e", 16),
          "0374d26b149dcdc5df5fbaf22bac0a56b28705fd4671089b4a5d774aa2bc7896"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b2403030208010107034200047fffffff"
              + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff178945df"
              + "488779235a2637c39a4a85ab707bd56e7c22b9ad41b652560123b6af",
          new BigInteger("3e8d9d702e5678e270f422d1d4c42543e85065575e74ed3dfcec0ffec1380fbd", 16),
          "58816ca002bdaac6485de985aa493e35677593544c03f268e0863a990992f78d"),
      new EcdhTestVector(
          "brainpoolP256r1",
          "305a301406072a8648ce3d020106092b240303020801010703420004a9fb57db"
              + "a1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e537613a0346d"
              + "b14d55d1bcc27079b68864ac32885b5bdfc3c9db6f85a35d3df4c39b",
          new BigInteger("1d5251bac7b11d73929029e9ee247d5c582970214bd21871259d5cdc9f6452f1", 16),
          "4d09ebc572a9598d3875eb00cd288a848a51f9a6f6f169b5bb79a68f1d829d60"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b24030302080101090352000400000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000000129110253d52cf3c5fc3382fca93d18adf7b97999028767b9722381db"
              + "68fe3a41793b7d9952c6177f",
          new BigInteger("088c2e254519c78a6be7b76aca06fb8e652aa6000826f4c41318cfdc7d7fa6ad"
                  + "b88d1059dfd72dc23", 16),
          "70669adbed0dc545f07d69e0dc6e94d36dfdfbaa916280a964787734f211f254"
              + "e13f3cdd4167f1b9"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b24030302080101090352000400000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "000000020d1a18c0b25d0d32d9c4249a523cfcc12a20c2ead596607d73260895"
              + "676315a70ad098e8b51d25a8",
          new BigInteger("4c8dd940c2a4e0a2c8c7795c1b0f9dcdcb561359aa4e07db8408667c5f5b0206"
                  + "a6c1a2573a2d2398", 16),
          "9c38b3f4eecbe4023d22be5d830853041de60f8802b8e1c9633fbda2d729afd0"
              + "a17516c88c0678b2"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b24030302080101090352000400000000"
              + "ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000001"
              + "000000063a91ee30c63eb15b1c0f2102c6cf3438dd75ca71636238f891e367c1"
              + "05f0b781d02de648399712a0",
          new BigInteger("7584f456eaa7eff0a63885c03295dc5ccbc77ae04924f42dafeefde9633805a3"
                  + "5f228d6d055f8c36", 16),
          "0e11df6236716ddaa14e304f56fdebb3deafe086acc1b3f6efb6c456ba116dca"
              + "8ab86e031fba6f6f"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b2403030208010109035200040000ffff"
              + "0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff"
              + "0000ffff308f36ab8f37e97723b0aadd7ee4dd585b9e68dc00db4242f6c3cf7b"
              + "0ec1497a26e629b24a613b3a",
          new BigInteger("6e2f97f1e8760800f8324484e1ae5307229a32d3b978e31f0fd820076fe9b3c7"
                  + "222867e004036252", 16),
          "1aeb05b333e3cf35fe629dc07e3fdd5d7fd4e917904b10b16765c1488b8e15f4"
              + "e33993f4ca7366f5"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b24030302080101090352000407fff000"
              + "1fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0007fff0001fff"
              + "c0007fff231f9aef9b1a7c143485f601980bfa4f7bc7b312b01400bd1d156691"
              + "97e07f2edf39cd08c905e280",
          new BigInteger("63c24c4f9d7c9db62b7c18ff03d63dbb83aaf59217a88ceef74be517ac37ca35"
                  + "e95507eff81c61a7", 16),
          "c37a0b7bbf58ca4a47eba12666ff5ddb6d32cacd2ebf9cdd24ae8de2844efd61"
              + "9e3a612179fe0ca4"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b2403030208010109035200047fc00000"
              + "007fffffff00000001fffffffc00000007fffffff00000001fffffffc0000000"
              + "800000011a2b8d3c67305de21501cd7c43ad4cd9a57459c42e6fdac1e2cb3795"
              + "2703ffdccd18fcb326a2e0c7",
          new BigInteger("0c1ecdf2fa0b63c2a9466dbf8db9a940afdd192556c3561d236d1d79b757993c"
                  + "e345555ca308858c5", 16),
          "2fec7c4258c0fd1650299ad5ea671843219522a886b1d6079ea6835412758c1d"
              + "32752faea4d1ef80"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b2403030208010109035200047ffff000"
              + "00003fffffff00000003fffffff00000003fffffff00000003fffffff0000000"
              + "40000001030432044ddf1b1586c51deec0306d02d88e54bc2a2dc6c7e6589589"
              + "1633f866addb9de1ad32a8bc",
          new BigInteger("09b5ec5170ed49cb61c7269e11962cd838a19e48a32f7e840a9a81fb65844bc6"
                  + "89ff731b0261667a9", 16),
          "81b9abb2bc3d793b3548fe47f1fdf0746569ef70cf629f781b8178e441064768"
              + "b3499b07ecd2e999"),
      new EcdhTestVector(
          "brainpoolP320r1",
          "306a301406072a8648ce3d020106092b2403030208010109035200047fffffff"
              + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "ffffffff04f2455cdb035b0cd4422a3ca06bb19bf018d1a5cb84eb12446d47f7"
              + "f7a16c035c70951b4b6bad7b",
          new BigInteger("1507aed61045ab6ad764a246d6da8101f8892ea31dac6a15b03710bc6bd173b3"
                  + "5f2524ec1d5c9b29", 16),
          "31022375cb74d3e74059ddf3e7e33cc67ac5d7c5a7a8aed49a38a82a65cad317"
              + "ec7f1a6c8fb5cee3"),
      new EcdhTestVector(
          "brainpoolP384r1",
          "307a301406072a8648ce3d020106092b240303020801010b0362000400000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "00000000000000000000000144e54365091651eebe3aa1e13a14ec2c0dd1b1ad"
              + "3778f69d586d078d7554c116a71e422add51cea477ce154ce873940e",
          new BigInteger("5b11e1f9b1cec1f6dffcf961dda23c42740c31a60df2f5fcb6c56fa0940c32c4"
                  + "93e00fc53018c428ca78516fa9d18ea2", 16),
          "35da13f0acd80a4c5420bed62513ff55215e5f53b41baff57d41bc775c2977c7"
              + "6823e721ef3d6268709c1df3cb899ffc"),
      new EcdhTestVector(
          "brainpoolP384r1",
          "307a301406072a8648ce3d020106092b240303020801010b0362000400000000"
              + "ffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000"
              + "ffffffff00000000ffffffff3e528e604dc03d7c658e1f5c4102e1d31ddeffaf"
              + "cc2f7d7a4816cec497a09a851f40ad616693013038c007697996de61",
          new BigInteger("42be7daa39423c51c73cfe3d3f74485da290423c44d70fcfdcea765ba9db5975"
                  + "82d6f4c003ac2e70fdcc54540c014871", 16),
          "6c07c6c0932629cd842deff18b99d2c3baa60af650110675c357933dbf970e4a"
              + "19b65fa96ea68cc62717a57127b220b5"),
      new EcdhTestVector(
          "brainpoolP384r1",
          "307a301406072a8648ce3d020106092b240303020801010b036200040000ffff"
              + "0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff"
              + "0000ffff0000ffff00010000200680b002d9adf1e053dbf04addddf8c58de920"
              + "543e0614c976446db34269d5e218c121704a0acf35d776d0a14e294d",
          new BigInteger("3206eaa6678c793bd05fdaf264c205dc9112c156b4a22c916e15d54caa799139"
                  + "5ae1fcad42a4ffc6148f5647e7d8ae1d", 16),
          "79e858897c3c49bb7ea3ff19497c891703bad13042e8197976e76c6a949664e8"
              + "0a344938ee92d66b17a932cb693b9cb5"),
      new EcdhTestVector(
          "brainpoolP384r1",
          "307a301406072a8648ce3d020106092b240303020801010b03620004007fff00"
              + "01fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0007fff0001ff"
              + "fc0007fff0001fffc000800204f1799aada7abdde3280f9638becb240be60123"
              + "c91ad14cf1f7d77e83330519a68a9dd61a8d639e12a41ab930bc278b",
          new BigInteger("5159187d8d7d30bca467d15eee9459356ce5454525b646100c91e670940cfe5d"
                  + "b9ec8adcfe9c7dc18d747d399aed7e61", 16),
          "7c6461f26148e8b1c3f9d0411bb3728c67ca0ec3170cdee8c116156fe9f922d7"
              + "da720bef76ca621d97c0694e6ed1ca91"),
      new EcdhTestVector(
          "brainpoolP384r1",
          "307a301406072a8648ce3d020106092b240303020801010b036200047ff00000"
              + "001fffffffc00000007fffffff00000001fffffffc00000007fffffff0000000"
              + "1fffffffc00000007fffffff2b8c710e160b3fdacffca46bc22b0b7b58349ab2"
              + "a4183931fdf9e0504685db3c40aa853607fbac52b3563e7c74516d61",
          new BigInteger("28e98b261c25e01cbc8ed503d24b19acb28274a37bbe87076bc04d53ad1cb547"
                  + "fac7ea7f48385784d4d4b160ae31744b", 16),
          "7af220991043c102a7b71b165b8fccd68b2d99b8f5109310eb7c75211e430129"
              + "c37750f70952e0a144c41aa54070b8c7"),
      new EcdhTestVector(
          "brainpoolP384r1",
          "307a301406072a8648ce3d020106092b240303020801010b036200047fffff00"
              + "000003fffffff00000003fffffff00000003fffffff00000003fffffff000000"
              + "03fffffff00000003fffffff4214f53b46996183016065c615037a34f8bd3468"
              + "48d13c870e6f74a26e3cee631d4d689244a615983f6f8b9a4880f508",
          new BigInteger("343c98de14ee603fdb01380e62843261fd390a07166ec4698d8c052aec883c8d"
                  + "98e4c6b5a7c7c470c452fc26af4a0289", 16),
          "6ace655ad8c564c0868456dfc828427876b2cd04361d9bd6a1c693c0350c73de"
              + "3f66631bcfde10d63ac75af1625695fe"),
      new EcdhTestVector(
          "brainpoolP384r1",
          "307a301406072a8648ce3d020106092b240303020801010b0362000480000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000000000000000000000012134018a6f7bb075ef67617abafd66a22ed8b514"
              + "6408aa52fc17cf52510b85f08b73acd0b4301e9967b3cc20b914f805",
          new BigInteger("27b09c5e90ac5390fbfe19d8ab169f39d262744bea13eb96d5b5fa09fb98fd5f"
                  + "9c88bb66df9c56ae6799ca3e145ff1f9", 16),
          "182ad635ac9df18b2dce39cc40464e0c3e8d3b613e951434d71162725ed98288"
              + "d2f644d0503f9f0592e703c07c3c11d8"),
      new EcdhTestVector(
          "brainpoolP512r1",
          "30819b301406072a8648ce3d020106092b240303020801010d03818200040000"
              + "0000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff0000"
              + "0000ffffffff00000000ffffffff00000000ffffffff000000010000000003c8"
              + "6f4fd8b138ac5509a4174bd4998e1b4d3d49de88d37e38dcaa74f9c42f3e37b7"
              + "f7be77cf5322514a879984e44b4a3caed566ab6874b1a781292e7ef791a6",
          new BigInteger("661d856de86bcadee194556ae6c2d0854592c26afa8cab8b38da2e25228a1b3b"
                  + "d92dc2a4a1570308d71012347f032f886506f51f72a2694ebec7f6deefe21b", 16),
          "aa49072afd65cc057c4eb59d1fef0f268382a8190d663d50ab75563a1adef125"
              + "f3ea80e6104827ada55cda2498ee5bf73661e294df3d6d1a5ad7ca203f715269"),
      new EcdhTestVector(
          "brainpoolP512r1",
          "30819b301406072a8648ce3d020106092b240303020801010d03818200040000"
              + "ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000"
              + "ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff3e35"
              + "ce50921fe7b45a53452690ea8398109e90b0985738e775ee45c5266b1385dc19"
              + "98956ae6e927a062f99d3729012c14f552dc17267fccdf634d0d3eb3acf1",
          new BigInteger("0a8c80e54e9d5d0049139ad8cee6c4e93ac9091e168f18892ef7b10c1ee058b1"
                  + "3842808642a121bc8f0ac82f1106bda5e5b03864f66d822e7e8b566c7a0de830"
                  + "7", 16),
          "4684370b1e63594c11958c6e8f12cac250be493e3548330c0d0e1d67aff233ff"
              + "86a7c0b59c007e5147160e35c93dedf50a7b532dc7d793a43e29cf87f1c949fd"),
      new EcdhTestVector(
          "brainpoolP512r1",
          "30819b301406072a8648ce3d020106092b240303020801010d03818200043fff"
              + "ffff00000003fffffff00000003fffffff00000003fffffff00000003fffffff"
              + "00000003fffffff00000003fffffff00000003fffffff00000003fffffff2854"
              + "149062fd692eecc2302747cc08be854c64c4f9abe86c467f161496b19a52bbb5"
              + "a4da84392573d7e9632a040e9dd737bc9089aedf5b0c15488e9f1b083a7a",
          new BigInteger("62b9a9cc1ea45ccc03baf7a36c0dedbe43ee68ebbf5574ebd3157697d9e0c440"
                  + "8756f7b5fd2e686398559d5313d913abc6a03a83e7e0a541cc9306c8c92ceb79", 16),
          "029c4a19633d0f1b0a559e4563bf149ea8e790e72f7b5020e0ee85bcda3e4d91"
              + "3c97cb47fa6d7374c0c718daf304c3413889c3eeb90f5b173484c61b4ca340b7"),
      new EcdhTestVector(
          "brainpoolP512r1",
          "30819b301406072a8648ce3d020106092b240303020801010d03818200044000"
              + "7fff0001fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0007fff"
              + "0001fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc000800009a3"
              + "7114d6a5c9ee64371c57bdd264e1764edda64f449cbd0ee1a72009890267fc1a"
              + "e7d2ee5ddfbb5b1693bda1a0b5494c862e0ed1df03b702f2f2c206e4c52c",
          new BigInteger("465db80e68274e8bfb43ee0a186400bf1657bfb2dd67c16e1ae57292583c6bfc"
                  + "bce065e5e872c67447f87da650756e54103973e074a7f1ec36e6a9ae24e95597", 16),
          "7e89fe4c583b377808f37912cb78ccfce8a03cb7b530d4e2c04dacdf07a46e9c"
              + "68387fde5914605b58a2731bc0f4dfed0313ae420cdf215a977d3cccbb1698b9"),
      new EcdhTestVector(
          "brainpoolP512r1",
          "30819b301406072a8648ce3d020106092b240303020801010d03818200047fff"
              + "00000001fffffffc00000007fffffff00000001fffffffc00000007fffffff00"
              + "000001fffffffc00000007fffffff00000001fffffffc00000007fffffff27cd"
              + "77712e0db1978186e9d6feb6eaa034318fbfbab7fa3342a9e43eeea04c28ddde"
              + "021916d5fcfe2d1b43743ca1ec2b5288cd553901825e4652cf4cf524bcb4",
          new BigInteger("0a714bab96f0fff7bf41aab010484d0b11b92770478510290d13b77131a9bfa6"
                  + "6a4c1b58dac0a0954a48be1b286857ac06f094a4d857ee553b879d8719f38a52"
                  + "6", 16),
          "3a6c0a915ff10844ea03676fba131655e81491fbabdc7c42c0b13caf38508053"
              + "1a2537659233442e056f7a0b4f471afd5a3081d1d6ff2ec5e5acc381549f4d24"),
      new EcdhTestVector(
          "brainpoolP512r1",
          "30819b301406072a8648ce3d020106092b240303020801010d03818200047fff"
              + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff026c"
              + "17238034c8372217a8cd9a234ecb7debdec5659b7e3f0c6e70ba226824f56acc"
              + "e025ae65da8b0aebc2efe2ef73dd826cea151b201b2f5b4f7623f2fbe332",
          new BigInteger("68f88078866eebb34fd8f49b04a363963f8142dfca0caba8ac20b5d7764fc3cf"
                  + "d06fbc5480f4963610f74bd870677f607309cb56d911ebaf096dfc99f922e223", 16),
          "93f2597bb5c7376f8ec55b052839a7c1f3d84e15e885b8f271e9ddbb7bf55595"
              + "c05161c0a8c178f7271f11feb8d051fb3311543c7fbfefe33afe7b9bcb724f31"),
      new EcdhTestVector(
          "brainpoolP512r1",
          "30819b301406072a8648ce3d020106092b240303020801010d0381820004aadd"
              + "9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d"
              + "9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f21278"
              + "0ae4d2fad1163e2a513d72ad6e3c2211f8079ccbddeb9b1e956b2ee36173abe8"
              + "4464b0c78dca8db21f6964e9a1398a5a0f6e1e717ddf4eac517032879266",
          new BigInteger("47d6e935323a48595a3c74ef737e9b159330199cfd3908be87aac5bf176d9c66"
                  + "ff40e0b7a01ab0936bc30d8af26481d83212dd834d40937cab0a1299605cd96b", 16),
          "9bb59b4c4b5e3d66dd2292996e5f2fee30ebf342bd2c4f491f6d8d31aed18bde"
              + "7afe52d858c3f5b077eaf98063f5d76a7ee6091a0dc489448e1c144a765c578f"),
      // CVE-2017-10176: Issue with elliptic curve addition
      // The effect of this bug is that the Sun provider throws an IllegalStateException.
      /*
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000400c6858e06b7"
              + "0404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77"
              + "efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd6601183929"
              + "6a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee"
              + "72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
          new BigInteger("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                  + "ffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386"
                  + "3f7", 16),
          "01bc33425e72a12779eacb2edcc5b63d1281f7e86dbc7bf99a7abd0cfe367de4"
              + "666d6edbb8525bffe5222f0702c3096dec0884ce572f5a15c423fdf44d01dd99"
              + "c61d"),
      */
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

  @Test
  public void testVectors() throws Exception {
    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    for (EcdhTestVector t : ECDH_TEST_VECTORS) {
      try {
        ka.init(t.getPrivateKey());
        ka.doPhase(t.getPublicKey(), true);
        byte[] shared = ka.generateSecret();
        assertEquals("Curve:" + t.curvename, TestUtil.bytesToHex(shared), t.shared);
      } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException ex) {
        // Skipped, because the provider does not support the curve.
      }
    }
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
   * Tests for CVE-2017-10176.
   *
   * <p>Some libraries do not compute P + (-P) correctly and return 2*P or throw exceptions. When
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
    // TODO(bleichen): currently disabled for presubmit tests.
    // testLargePrivateKey(EcUtil.getNistP521Params());
    testLargePrivateKey(EcUtil.getBrainpoolP256r1Params());
  }

  @NoPresubmitTest(
    providers = {ProviderType.OPENJDK},
    bugs = {"CVE-2017-10176"}
  )
  @Test
  public void testLargePrivateKeyNoPresubmit() throws Exception {
    testLargePrivateKey(EcUtil.getNistP521Params());
  }
}
