/**
 * @license
 * Copyright 2016 Google Inc. All rights reserved.
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
import junit.framework.TestCase;

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
 * <p># <b>Bugs:</b> CVE-2015-7940: BouncyCastle before 1.51 does not validate a point is on the
 * curve. BouncyCastle v.1.52 checks that the public key point is on the public key curve but does
 * not check whether public key and private key use the same curve. BouncyCastle v.1.53 is still
 * vulnerable to attacks with modified public keys. An attacker can change the order of the curve
 * used by the public key. ECDHC would then reduce the private key modulo this order, which can be
 * used to find the private key.
 *
 * <p>SunEC had similar problem. CVE ?
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
public class EcdhTest extends TestCase {

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
      // vectors with normal ECDH values
      new EcdhTestVector(
          "secp224r1",
          "304e301006072a8648ce3d020106052b81040021033a00049c08bb3788a5cb8d"
              + "22591f2520791cdaf61765a84f0419d28ff8fb2dcb5d51e5714d8740420d0945"
              + "187f97be42872bae9bf3f5b1857a475f",
          new BigInteger("8af784fe9cebd363df85f598dcc2ab82b2ca725360dadb77b3708032", 16),
          "c1921af3d06d813ccb009e363a647836d30b3f9c211c26e64a3bb0b6"),
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d030107034200044b3b0a5231"
              + "76309f259498c55e3a9be45c9fb65ad4e60d6064e04b89c1bd0a1835039219c1"
              + "22b89e2b539bb16d3afced502137f02944c374863137035fd3f1ae",
          new BigInteger("051a995be2a8499e2c9331b3b5f3c012048bb02a1a6f044ed93d9bd295fcec16", 16),
          "33befba428b295b9a0123d3a848d91d1e9a5266959e036d1a25e28d83d06421f"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b8104002203620004c1d31b771bb123f4"
              + "fb2b789a2880c57a68b3bbfa7da3d80b8325b73428bd2a4e79b55b57ac454f52"
              + "8ac02b62d54dfc315b9ba04363e94b825767951a9338f5d1db4c6d3f0e9a15bc"
              + "9b834fc11a01e4b310c22aba73766fd769ea684fbad5d9d2",
          new BigInteger("ff65a2bf5e1347e2286fb29273fb118a76996038bea2fcfd2032e8663f7588e5"
                  + "3130d195b161eba39085abbc3e24bcef", 16),
          "dbd85b2caaca6d69460c94bd9f99b3bd51404788a58334a18709a882050fe1bf"
              + "a4dd74de6e4368c1243443e5f64b60c7"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000401ca6ec5476b"
              + "ae3cf0f28f370ac3a9a0de2091418a590978bf87a6f1aeadebde98925e8fb42c"
              + "d03d57ff9aeb9890646067a3095874828a392b80a88880e5f456e4d000493581"
              + "376d20d711a487e0106a3fc047b91803ed154e274b26d858cf2f55e356b45765"
              + "2101b925b7d36b542d2a3e33e01404fb4f944c3b8ef276b6f5082e591135",
          new BigInteger("01f362c182f1eaae2920578a2f30c228e28b996e74d4bd799621300d5f2e6c69"
                  + "30204f00476732c95a79ae527503621edf633dbb87400740f54adc4430706221"
                  + "2f68", 16),
          "0107b9c99c80e2bc834e10c44afe2d611aafe8aad0eb80384aefbd9bb8196ea3"
              + "b5797bedac39de3362532c9b04aeb98a3e60034c3d2dcb4a43b8f8b44e9528d3"
              + "eeb8"),
      new EcdhTestVector(
          "brainpoolp256r1",
          "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
              + "01022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d"
              + "1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6c"
              + "e94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7"
              + "e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27"
              + "e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745"
              + "132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d71"
              + "8c397aa3b561a6f7901e0e82974856a7020101034200048178776ff8332108da"
              + "d4fa59bce3111133a30e33fa7f96d0211ec9fa4904dcca084de67f52fd720ccd"
              + "ada5c49305200a6028793a83cbe692c08237ecd0572fa2",
          new BigInteger("143be522a9d0420f6bd19b95ce3a5e19c61970c31f13448276546625e607e7c9", 16),
          "3658b819481f00f74cfd76b9dcf82867c3c3186f948cbc75bf296c6d332aedf0"),
      // vectors with extreme values for the shared secret
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d03010703420004983f80374a"
              + "4730f9decd7221fa3ebb527d44f459b6c6afcf7de7069481400a748fb8733ba0"
              + "8e01cd53d54af45975554d0dbd6d5f0acf0fd95692606347cace7e",
          new BigInteger("56556c546751dee664ae71baa0189a2e69b1e1f8939a49ed7cc35d7ea98fbcc7", 16),
          "0000000000000000000000000000000000000000000000000000000000000000"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b8104002203620004d64af08419f8a0aa"
              + "5d830a2b0f42e6a27a3c17e0e98f64a1e7e10c6a41a308832dcd9a493db0cd43"
              + "7e47063c1db6c967494c8460f03bf95ff619b7c7499e1bc08fd759fc44c4af3d"
              + "03de541a719baf996b4f91a9af5bf08fa671af0899f91359",
          new BigInteger("ee383acde7e5b3e6c246833e183c4272a1714a13097b4b57bc2eeecdccbd69b6"
                  + "cff435215a3c92b5d4e0b2c36444a7fa", 16),
          "0000000000000000000000000000000000000000000000000000000000000000"
              + "00000000000000000000000000000000"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b81040022036200041c1ed3f66b6ae370"
              + "411ac30fda63c784c5cbc3951a7cfe567d8bfa3ea535a2eb8c192d349e69ea2a"
              + "39eb5013a5cf383cf91c82e81eee1a9bc97386e340e65b2b2d8cf2633b919a82"
              + "10a638b8e2345cda054ce96efcaeee20dcce82d13d40eb6a",
          new BigInteger("98f230ef0c0ab02c78179ba9ea3e1c8d16c3ec276665c432b9040b803dfff657"
                  + "a6c77512b6a602d416785016c3cd3da7", 16),
          "0000000000000000000000000000000000000000000000000000000000000000"
              + "00000000000000000000000000000002"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b8104002203620004d10b0df120b1324d"
              + "8b76ee43065e4f4be63f68cf5b381ae79046920108a8f21cf8097bf313225b74"
              + "1125eb5a66105ee445961b28ad1843613775c063a85319f1353d8bf2a217210e"
              + "309f2c7c27b57d42fdc042abb00b37a0f3118cf74b4174f0",
          new BigInteger("5b8e9af3c17fa0d683f3bc94f8685f33c0b616281f91b466cac9da0a0e085ba6"
                  + "f48aafcdb4fc13d55f1a33ac436f82bb", 16),
          "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
              + "ffffffff0000000000000000fffffffe"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b810400230381860004008269c7d0ff"
              + "febadbf5bdfa2adf0f378d0844268e5acb57d0157fe688488cef91256e15939d"
              + "311aaf6479e29ef14de3981c3a5768c7b66693e956fa515d4a0c847c0054a32b"
              + "4a8f615ba5550f204ebf1f7f02f7252b5ae564361eec468adf4d59caa4c4b424"
              + "a30761d805d521c2e1f1dfde385e9146624cb2b84f94888730acbfbf1294",
          new BigInteger("019ad2de5943f5112021a3215cee84c4e8d40e188641419a5b7958636f1843d0"
                  + "cbda4747aad69fd806b333b82b095d0f10bda8dbeca7ee9f67d09caffb4869e4"
                  + "1172", 16),
          "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b810400230381860004003b0d698705"
              + "0fad0f76ac1ac7a1c7e91e24addf821c06ae0844a3f1b6338c111a32a94a5369"
              + "fdf8fd1cc137314c7d7a99dfabba1cc92f10026e45388714fe453ed50015e59a"
              + "c4bab161635e0df0f5553ee6112fc60f744ffc607965975c0843f7a893441c4f"
              + "e5e6e290426dd219ecbc159f39302b52b37b69a890e9fc4cf70eba39bbf6",
          new BigInteger("0147492d3019808024569dc81b0e6aef9f27bfd43e009e8b4b6b0512b220490e"
                  + "08f98324b16d3ed91a54d391f92973f5376c66b9f8a9cbf893b0900968fd8d6e"
                  + "5e7d", 16),
          "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "0001"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000401bb2936bfc5"
              + "8f1e9819d62ed2a38a0ce618f000546fe8af4983d8dbbda7b7ae914a656ac540"
              + "7c153f6edacb170fd2129d126d987d5032c7a31540bb6a4e93f8af15015c23ce"
              + "1263e691903cd2c859d883c980fada91b764aef7e5a20fb22bcf5949e62c8082"
              + "c8245bcf8686a6a39b7ef2eec49b1a047b73aeb06e3793c1d01fa24fd156",
          new BigInteger("5a5f98ceb2f856685c51ba714d5e1db06d1e6542a8d02b9c13efeeb1f3e6613d"
                  + "8ef83e49748cb63aad268ba68c9295c507dac125f51ba75c82f6029dcc14d4ab"
                  + "16", 16),
          "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "0002"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000401ce7a5356fd"
              + "002ff3d9a193dd910795b56f8bd2f975367d982d27e04b4e0935425fdef6b3e1"
              + "6fac26a898a757ddbfb01a45236a8a06ead9db3dff644ed87a7f09310000c862"
              + "7374a123b1c0fdf7efaaee362fa7fdeb1c56bd787e81484d21a818ff49552704"
              + "af2d2fe714a1576299ff6d3745349cdb463e8c003641c13c870391cfd360",
          new BigInteger("c5dd96d1f0aa141f184d0a749809dc0749a0629b9b7d99d1cbe40c14204d70c7"
                  + "f63413756040a4c2a67551df6723c4b784ace44d7e35f46233c78b2c7548594b"
                  + "3d", 16),
          "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "fffd"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000400d4574ad46e"
              + "42824b7738f0ed19f0dbec65e743ed6a1798e8168546713a929c97cb8b2f3c20"
              + "928bed9fad88319ef216e42c7a82707befead2b21000e06e6ca37709004848c1"
              + "34a7fa6d0f8cd9aa237b84ffa02cb3bc8d84b8022153a3e01248dfc87403e8f3"
              + "f1b70b52b7eabffd01fe1b4101fa901494a2067e2321a47e87cce45eecfd",
          new BigInteger("01ac34343b1814a092e48f1c60de0bacced8c328246f103428ab0ce6611807e6"
                  + "90022dbc6bc558265b917dc513152cd1661b30e3b62a2cc2bf9f909e3fd51918"
                  + "de5b", 16),
          "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "fffe"),
      new EcdhTestVector(
          "brainpoolp256r1",
          "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
              + "01022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d"
              + "1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6c"
              + "e94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7"
              + "e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27"
              + "e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745"
              + "132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d71"
              + "8c397aa3b561a6f7901e0e82974856a70201010342000498703a894131de3f81"
              + "5836bdb1d5a03e59fbf50ffde6575ee690e9ebf6a32e785ad50d1eb00062a9b8"
              + "176ba32f06f3908f82a3ddd9da10eafcac61f57a180bcb",
          new BigInteger("17617237e4ec2629d798a81ca086c1a73494e70619dd7b77cb7360174de82107", 16),
          "0000000000000000000000000000000000000000000000000000000000000001"),
      new EcdhTestVector(
          "brainpoolp256r1",
          "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
              + "01022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d"
              + "1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6c"
              + "e94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7"
              + "e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27"
              + "e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745"
              + "132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d71"
              + "8c397aa3b561a6f7901e0e82974856a702010103420004055f1b89b08c1c4a0f"
              + "96ff15dd284bdad79b90636ce73c461cb6da001e19638c07490bed6a644e944a"
              + "c3e8684c4d5cf469a3f5b039690cba52dc0dccb095e61e",
          new BigInteger("7988ceedd4ce4f516f083261dc0dbb4d59c71b058bf00876135fb1d5e72a1cea", 16),
          "0000000000000000000000000000000000000000000000000000000000000002"),
      new EcdhTestVector(
          "brainpoolp256r1",
          "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
              + "01022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d"
              + "1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6c"
              + "e94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7"
              + "e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27"
              + "e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745"
              + "132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d71"
              + "8c397aa3b561a6f7901e0e82974856a70201010342000424f99dbc3d8f4989f2"
              + "43662e67de0f8d03d0f84031caa553f4a3ccc1c999de1e43530fcd456a5d83d5"
              + "11aedc8bda7c2b18cc509cabe47e76d46501fd82ebbfae",
          new BigInteger("844649c38c375c5f4959b129c6510e54f71a60b91d1b09a7b1a8dd0e954da186", 16),
          "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5376"),
      // vectors with extreme values for the public key
      new EcdhTestVector(
          "secp256r1",
          "3059301306072a8648ce3d020106082a8648ce3d030107034200040000000000"
              + "00000000000000000000000000000000000000000000000000000066485c780e"
              + "2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4",
          new BigInteger("2e0a2c5159af006f28f5b51e55ce9270f17a431ebefee2d95bf2f954c3c460c5", 16),
          "bb4b8e7b1b5d766d7e6d3de41e0ab0703cadcca4e039f310e3ed0004e2c1ba67"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b81040022036200040000000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "00000000000000003cf99ef04f51a5ea630ba3f9f960dd593a14c9be39fd2bd2"
              + "15d3b4b08aaaf86bbf927f2c46e52ab06fb742b8850e521e",
          new BigInteger("b0a8c4804a2b9769216a51b51ece43391cf3f66c383a748d54f1c15f27bbf041"
                  + "a3b9470a6d49f8abe9e6b4db6bd7c59f", 16),
          "6598237fdfd3f38e00c3c58a3045b9d54c510f0f5523293af1966635f2ddf963"
              + "87b12065ad8e1a5b72618e6441c72841"),
      new EcdhTestVector(
          "secp384r1",
          "3076301006072a8648ce3d020106052b8104002203620004ffffffffffffffff"
              + "fffffffffffffffffffffffffffffffffffffffffffffffeffffffff00000000"
              + "00000000fffffffe732152442fb6ee5c3e6ce1d920c059bc623563814d79042b"
              + "903ce60f1d4487fccd450a86da03f3e6ed525d02017bfdb3",
          new BigInteger("135b5751b27de8fe0e34d452ad81c4ca90def546275c349f467aabd24e039b75"
                  + "28c473bc5732cb96921d01e6ca11739a", 16),
          "ef5ceb524843eb0277f574b278b09f82670dbcdacbe51a646441a45ebdfa4976"
              + "1fb3b534bfccd957edb99e9a4e329467"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b810400230381860004000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "0000000000000000000000000000000000000000000000000000000000d20ec9"
              + "fea6b577c10d26ca1bb446f40b299e648b1ad508aad068896fee3f8e614bc630"
              + "54d5772bf01a65d412e0bcaa8e965d2f5d332d7f39f846d440ae001f4f87",
          new BigInteger("7ca82bb7bdd0ab3805e1d25ce49f71780e93a0314f579a474d0b0f81812c8365"
                  + "bc3917eb00208a1cfdb44cdc53f112930560e86bcad563d0bd4ff951f2c41454"
                  + "f6", 16),
          "00d6283f6a7b59628920dd3afe97a5021c79e26c71adf5c0774cedaaf5b25b92"
              + "ed2776cfefbe95e467a15032c221064ff19b1207183f0ca0c594b6a83ca0e3f3"
              + "2250"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b810400230381860004000000000000"
              + "0000000000000000000000000000000000000000000000000000000000000000"
              + "000000000000000000000000000000000000000000000000000000010010e59b"
              + "e93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03df47849bf550ec6"
              + "36ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c832e843564",
          new BigInteger("011cf3abed354498f6922af2ddc9d74b2bb829bee79cc272c7b154f16a720c29"
                  + "429bb354bb034549e33be5b84ffb6da99a0c28bb37fa44f78cce5feb871370e1"
                  + "2c93", 16),
          "00e51b94872c9cb3831bac48e9e4cbc6b4eafdc09ce51f43d0ff118b5d429f20"
              + "b88261dbfc9636ecf081cdcf1b1336425a39841cf1ff742bc3d5553a709cd0a7"
              + "3a13"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000401ffffffffff"
              + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "fffffffffffffffffffffffffffffffffffffffffffffffffffffffd0010e59b"
              + "e93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03df47849bf550ec6"
              + "36ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c832e843564",
          new BigInteger("011c2b1a82cd320924e757b4259e5f7c0455efe3f05d316c9705b5071fdbd59e"
                  + "db59ee938b95a67727ca01ffe5155baf5eff83ae5ec4a56770a50475b017a762"
                  + "30cf", 16),
          "000adf30396bda59d36fc307a4f43f594806f3a46373f3e4af6516e67f99d981"
              + "1c0496f49527895fa7738423f6429318f54afa6841cb4692e15016fe49fc7c82"
              + "509d"),
      new EcdhTestVector(
          "secp521r1",
          "30819b301006072a8648ce3d020106052b81040023038186000401ffffffffff"
              + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              + "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe00d9254f"
              + "df800496acb33790b103c5ee9fac12832fe546c632225b0f7fce3da4574b1a87"
              + "9b623d722fa8fc34d5fc2a8731aad691a9a8bb8b554c95a051d6aa505acf",
          new BigInteger("01e1603fe7e275673aeb8b3f105f4058e073b4c37d2f0ae2bd66b189454e1b41"
                  + "c442c3f35f085eae3aa37eefffe76736440f9b3fd2e3931d468b6d90e560bc0f"
                  + "35f5", 16),
          "0158694585e55f1289e410fdeeed82940b3029dd8207dcb4de407278a6328d5e"
              + "b904262419f1ef2ecacb415872f0c9d64df82b1241cd780bd0abc9e26ceebadf"
              + "44e7"),
      new EcdhTestVector(
          "brainpoolp256r1",
          "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
              + "01022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d"
              + "1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6c"
              + "e94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7"
              + "e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27"
              + "e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745"
              + "132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d71"
              + "8c397aa3b561a6f7901e0e82974856a702010103420004000000000000000000"
              + "000000000000000000000000000000000000000000000109e0e9e8d98fb89da2"
              + "a32b2c7618b26bb99b920f02a5e831a142e6c8673110cd",
          new BigInteger("61c2be000b5888035bfde07d532b36d91cc347f556d87c7a01397f4cde29c6e4", 16),
          "3db56c93e51a0b5b17a8009be010be6eecca6b7e0b587753cb8bc850869a710d"),
      new EcdhTestVector(
          "brainpoolp256r1",
          "308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d01"
              + "01022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d"
              + "1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6c"
              + "e94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7"
              + "e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27"
              + "e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745"
              + "132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d71"
              + "8c397aa3b561a6f7901e0e82974856a702010103420004a9fb57dba1eea9bc3e"
              + "660a909d838d726e3bf623d52620282013481d1f6e537613a0346db14d55d1bc"
              + "c27079b68864ac32885b5bdfc3c9db6f85a35d3df4c39b",
          new BigInteger("8527b0540fc10b025a6e0892439c59a889a52e57a0f81b4df41442869c524873", 16),
          "a01ed9d4f5a0884db2a232dd5369d6014bfe1f2f6a6d05a757e7a078b71a1f54"),
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

  public void testVectors() throws Exception {
    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    for (EcdhTestVector t : ECDH_TEST_VECTORS) {
      try {
        ka.init(t.getPrivateKey());
        ka.doPhase(t.getPublicKey(), true);
        byte[] shared = ka.generateSecret();
        assertEquals("Curve:" + t.curvename, TestUtil.bytesToHex(shared), t.shared);
      } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
        // Skipped, because the provider does not support the curve.
      }
    }
  }

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

  public void testModifiedPublic() throws Exception {
    testModifiedPublic("ECDH");
    testModifiedPublic("ECDHC");
  }

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

  public void testWrongOrderEcdh() throws Exception {
    testWrongOrder("ECDH", EcUtil.getNistP256Params());
    testWrongOrder("ECDH", EcUtil.getBrainpoolP256r1Params());
  }

  public void testWrongOrderEcdhc() throws Exception {
    testWrongOrder("ECDHC", EcUtil.getNistP256Params());
    testWrongOrder("ECDHC", EcUtil.getBrainpoolP256r1Params());
  }
}
